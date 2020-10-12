#!usr/bin/env python3

"""
This class contains code for creating certifier's wallet and creating and submitting transactions by interfacing with
sawtooth through the REST API.
It accepts input from a _client CLI interface.

"""
import base64

import logging
import os
import random
import sys
import traceback
from datetime import datetime
from sys import path

import cbor
import yaml
from bsddb3 import db
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_signing import CryptoFactory
from sawtooth_signing import ParseError
from sawtooth_signing import create_context
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey

path.append(os.getcwd())
from constants import digital_id_constants
from protobuf import digital_id_pb2, id_attribute_pb2, digital_id_transaction_pb2
from protobuf.digital_id_transaction_pb2 import DigitalIdTransaction
from util import hashing, chain_access_util
# from certifier.certifier_events_cli import CertifierEventsClient
from util.transaction_generator import TransactionGenerator

# The transaction family name

FAMILY_NAME_CERTIFIER = 'certifier'
DEFAULT_KEY_FILE_NAME = 'certifier1'
EVENTS_DB = 'certifier_events_db'
FAMILY_NAME_LEARNER = 'learner'
FAMILY_CERTIFIER_CLIENT = 'certifier_client_info'
REGISTRY_DB_FILE = 'user_registry_db'

LOGGER = logging.getLogger('certifier_wallet.client')
# LOGGER.setLevel(logging.INFO)
SKILL_POINTS = 50   # any value

STATUS_ENUM = {0: 'DEFAULT',
               1: 'REGISTERED',
               2: 'PII_REGISTERED',
               3: 'SKILL_REGISTERED',
               4: 'SKILL_ATTESTED',
               5: 'EXPIRED',
               6: 'ACK_CONFIRMED',
               7: 'INVALID',
               8: 'INVALID_ACK',
               9: 'RECOVERY_REQ'}


def _get_private_key_file(key_file_name):
    """Get the private key from key_file_name."""
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")
    return '{}/{}.priv'.format(key_dir, key_file_name)


class CertifierWalletClient(object):
    """ Certifier Wallet class """

    wait_time = 100

    def __init__(self, base_url, key_file_name=DEFAULT_KEY_FILE_NAME):

        """Initialize the _client class, get the key pair and compute the address. """
        self.base_url = base_url
        self._key_file = _get_private_key_file(key_file_name)
        LOGGER.debug("key_file %s", key_file_name)
        try:
            with open(self._key_file) as fd:
                priv_key_str = fd.read().strip()
        except OSError as err:
            raise Exception('Failed to read private key {}: {}'.format(self._key_file, str(err)))

        try:

            self._private_key = Secp256k1PrivateKey.from_hex(priv_key_str)
        except ParseError as err:
            raise Exception('Failed to load private key:{}'.format(str(err)))

        self._signer = CryptoFactory(create_context('secp256k1')).new_signer(self._private_key)
        self.public_key = self._signer.get_public_key().as_hex()
        self._public_address = hashing.get_pub_key_hash(self.public_key)
        print("\nPublic Key of key profile {} : {}".format(key_file_name, self.public_key))
        print("\nBlockchain address of key profile {} : {}".format(key_file_name, self._public_address))
        self._self_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_CERTIFIER,
                                                                 key='self',
                                                                 pub_key_hash=self._public_address)

        self.txn_generator = TransactionGenerator(base_url=self.base_url,
                                                  public_key=self.public_key,
                                                  signer=self._signer)
        user_dir = os.path.join(os.getcwd(), key_file_name)
        if os.path.isdir(user_dir) is False:
            os.mkdir(key_file_name)
        self.events_db_file = os.path.join(user_dir, EVENTS_DB)

    def __del__(self):
        LOGGER.debug("Inside destructor method")



    def _issue_certificate(self, id_attribute, attribute_data):
        LOGGER.debug("inside _issue_certificate")

        attribute_data.attestor_pub_key = self.public_key
        current_time = datetime.now()
        attribute_data.sign_timestamp = str(current_time.isoformat())
        attribute_data.enc_code = random.random().hex().encode()
        attribute_data_bytes = attribute_data.SerializeToString()
        id_attribute.status = id_attribute_pb2.SKILL_ATTESTED
        id_attribute.skill_point = SKILL_POINTS
        id_attribute.course_details = attribute_data_bytes
        id_attribute.certificate = self._signer.sign(hashing.get_hash_from_bytes(attribute_data_bytes))


    def attest_skill(self, request_txn_id=None):

        LOGGER.debug("Inside attest_skill")
        LOGGER.debug("Certifier public key : {}".format(self.public_key))

        if request_txn_id is not None:
            try:
                if self._verify_learning_credential(request_txn_id=request_txn_id) is True:
                    # print("Request successfully processed")
                    events_db = db.DB()
                    try:
                        events_db.open(self.events_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
                        key = "learner/skill_register"
                        data = events_db.get(key.encode())
                        if data is not None:
                            request_list = cbor.loads(data)
                            if request_list is not None and request_list != []:
                                for req_txn in request_list:
                                    request_list.remove(req_txn)
                                    events_db.put(key.encode(), cbor.dumps(request_list))
                    except BaseException:
                        LOGGER.debug("Exception while updating database")
                        traceback.print_exc(file=sys.stderr)
                    finally:
                        events_db.close()
                else:
                    print("Failed to process.")
            except InvalidTransaction:
                print("Failed to process - Invalid Transaction")

    def _verify_learning_credential(self, request_txn_id):

        LOGGER.debug("inside _verify_learning_credential")
        txn_response = chain_access_util.get_transaction(base_url=self.base_url, requesting_txn_id=request_txn_id)
        try:
            txn_header = txn_response['header']
            owner_pub_key_hex = txn_header['signer_public_key']
            owner_address = hashing.get_pub_key_hash(owner_pub_key_hex)
            output_state_address = txn_header['outputs'][0]
            txn_payload = txn_response['payload']
            id_transaction = digital_id_transaction_pb2.DigitalIdTransaction()
            id_transaction.ParseFromString(base64.b64decode(txn_payload))
        except BaseException as err:
            LOGGER.error("Error while reading transaction data {}".format(err))
            raise Exception("Error while reading transaction data")
        if id_transaction.status != id_attribute_pb2.SKILL_REGISTERED:
            LOGGER.debug("Invalid transaction status for skill attest operation {}".format(id_transaction.status))
            print("Invalid transaction status for skill attest operation {}".format(id_transaction.status))
            return False

        if id_transaction.receiver_address != self._public_address:
            LOGGER.debug("Invalid Request: Request Transaction not addressed to {}".format(self._public_address))
            print("Invalid Request: Request Transaction not addressed to {}".format(self._public_address))
            return False

        to_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_LEARNER,
                                                   key=self._public_address,
                                                   pub_key_hash=owner_address
                                                   )

        if to_address != output_state_address:
            LOGGER.debug("Invalid output_state_address found in the transaction")
            print("Invalid output_state_address found in the transaction")
            return False

        digital_id_bytes = id_transaction.digital_id
        learning_credential = digital_id_pb2.learning_credential()
        learning_credential.ParseFromString(digital_id_bytes)
        self._get_attested_credential(learning_credential)
        action = "attest_skill"

        result = self._create_n_send_txn(action=action, to_address_list=[output_state_address],
                                         digital_id_msg=learning_credential,
                                         dependency_txn_list=[request_txn_id]
                                         )
        LOGGER.debug(result)
        print(result)
        if result != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
            status = yaml.safe_load(result)['data'][0]['status']
            if status == 'COMMITTED':
                print("Successfully processed request")
                return True
            elif status == 'UNKNOWN':
                print("Transaction status unknown")
                return True
            else:
                print("Failed to process request")
                return False
        else:
            return False

    def _get_attested_credential(self, learning_credential):

        course_map = learning_credential.course_attribute_set

        for course_key in course_map:
            attribute_bytes = course_map[course_key]
            course_attribute = id_attribute_pb2.CourseAttributeDataType()
            course_attribute.ParseFromString(attribute_bytes)
            value_attr_data = course_attribute.course_details
            course_details = id_attribute_pb2.CourseDetails()
            course_details.ParseFromString(value_attr_data)
            course_field_list = course_details.ListFields()
            for course_field in course_field_list:
                print("{}: {}".format(course_field[0].name, course_field[1]))

            resp = input("Press 'Y' if the course details are valid. Else press any other key.")
            if resp.capitalize().strip() == 'Y':
                self._issue_certificate(id_attribute=course_attribute, attribute_data=course_details)
            else:
                print("Course details for {} could not be validated".format(course_key))
                continue

    def _create_n_send_txn(self, action, to_address_list, digital_id_msg, dependency_txn_list,
                           from_address_list=None):

        LOGGER.debug("Inside certifier_client._create_n_send_txn()")
        # constructing the self_address where we'll store our state
        input_address_list = []
        output_address_list = []
        if to_address_list is not None and len(to_address_list) != 0:
            output_address_list.extend(to_address_list)

        if from_address_list is not None and len(from_address_list) != 0:
            input_address_list.extend(from_address_list)
        else:
            input_address_list.extend(to_address_list)

        digital_id_msg.enc_code_id = random.random().hex().encode()
        digital_id_bytes = digital_id_msg.SerializeToString()

        digital_id_transaction = DigitalIdTransaction()
        digital_id_transaction.digital_id = digital_id_bytes

        # Sign on the hash of the digital id.
        # Verifiable using the transaction signing public key in the digitalid_tp
        digital_id_transaction.certifier_signature = self._signer.sign(hashing.get_hash_from_bytes(digital_id_bytes))

        if "issue_certificate" == action:
            LOGGER.debug("Sending Transaction for issue_certificate")
            digital_id_transaction.status = id_attribute_pb2.Status.ON_VERIFICATION

        payload = digital_id_transaction.SerializeToString()

        transaction = self.txn_generator.make_transaction(family=FAMILY_NAME_LEARNER, payload=payload,
                                                              input_address_list=input_address_list,
                                                              output_address_list=output_address_list,
                                                              dependency_list=dependency_txn_list)
        transaction_list = [transaction]
        batch_list = self.txn_generator.make_batch(transaction_list)
        batch_id = batch_list.batches[0].header_signature

        # Send batch_list to the REST API
        result = self.txn_generator.send_to_rest_api("batches", batch_list.SerializeToString(),
                                                     'application/octet-stream')
        LOGGER.debug("Result from Rest-API {}".format(result))

        result = self.txn_generator.wait_for_status(batch_id, CertifierWalletClient.wait_time, result)

        return result
