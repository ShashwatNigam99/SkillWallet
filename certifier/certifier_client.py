#!usr/bin/env python3

"""
This class contains code for creating certifier's wallet and creating and submitting transactions by interfacing with
sawtooth through the REST API.
It accepts input from a _client CLI interface.

"""
import base64
import json

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

from certifier.id_share_module import DigitalIdSharingClass

path.append(os.getcwd())
from certifier import peer_verification_module
from constants import digital_id_constants
from protobuf import digital_id_pb2, id_attribute_pb2, client_pb2, digital_id_transaction_pb2, shared_id_pb2
from protobuf.digital_id_transaction_pb2 import DigitalIdTransaction
from util import hashing, chain_access_util
# from certifier.certifier_events_cli import CertifierEventsClient
from util.transaction_generator import TransactionGenerator

# The transaction family name

FAMILY_NAME_CERTIFIER = 'digitalid_certifier'
DEFAULT_KEY_FILE_NAME = 'certifier1'
EVENTS_DB = 'certifier_events_db'
FAMILY_NAME_DIGITALID = 'digitalid'
FAMILY_NAME_PEER_VERIFY = 'peer_verification'
FAMILY_CERTIFIER_CLIENT = 'certifier_client_info'
FAMILY_NAME_SHAREDID = 'shared_id'
REGISTRY_DB_FILE = 'user_registry_db'

LOGGER = logging.getLogger('certifier_wallet.client')
# LOGGER.setLevel(logging.INFO)

# TF Prefix is first 6 characters of SHA-512("digitalid_certifier"),

STATUS_ENUM = {0: 'DEFAULT',
               1: 'REQUESTED',
               2: 'ON_VERIFICATION',
               3: 'ON_UPDATE',
               4: 'CONFIRMED',
               5: 'EXPIRED',
               6: 'ACK_CONFIRMED',
               7: 'INVALID'}
FAMILY_ENUM = {
    'digitalid': 'digitalid learner',
    'digitalid_certifier': 'digitalid certifier'
}

def _get_private_key_file(key_file_name):
    """Get the private key from key_file_name."""
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")
    return '{}/{}.priv'.format(key_dir, key_file_name)


def _get_id_from_state(state_data):
    digital_id_msg = None
    if state_data is not None:
        id_data = state_data['digital_id']
        # TODO decrypt and de-compress _state_data
        digital_id_msg = digital_id_pb2.DigitalId()
        digital_id_msg.ParseFromString(id_data)
    return digital_id_msg


def _build_contract():
    LOGGER.debug("Inside certifier_client._build_contract()")
    contract_msg = shared_id_pb2.contract()
    attr_names = input("Enter the list of attributes to include in contract: ")
    LOGGER.debug("Selected attributes: {}".format(attr_names))
    attr_names = attr_names.split(",")
    attr_names = [x.strip().lower() for x in attr_names]
    LOGGER.debug("Selected attributes for contract setting {} ".format(attr_names))
    id_attr_set = digital_id_pb2.IdAttributeSet()
    if 'name' in attr_names:
        LOGGER.debug("Setting attribute 'name'")
        id_attr_set.name.status = id_attribute_pb2.REQUESTED
        attr_names.remove('name')
    if 'date_of_birth' in attr_names:
        LOGGER.debug("Setting attribute 'date_of_birth'")
        id_attr_set.date_of_birth.status = id_attribute_pb2.REQUESTED
        attr_names.remove('date_of_birth')
    if 'address_permanent' in attr_names:
        LOGGER.debug("Setting attribute 'address_permanent'")
        id_attr_set.address_permanent.status = id_attribute_pb2.REQUESTED
        attr_names.remove('address_permanent')
    if 'nationality' in attr_names:
        LOGGER.debug("Setting attribute 'nationality'")
        id_attr_set.nationality.status = id_attribute_pb2.REQUESTED
        attr_names.remove('nationality')
    if 'gender' in attr_names:
        LOGGER.debug("Setting attribute 'gender'")
        id_attr_set.gender.status = id_attribute_pb2.REQUESTED
        attr_names.remove('gender')
    LOGGER.debug("Remaining attr_names: {}".format(attr_names))
    if len(attr_names) != 0:
        others_map = id_attr_set.others
        for attr in attr_names:
            LOGGER.debug("Setting attribute {}".format(attr))
            others_map.get_or_create(attr)
            attr_val = others_map[attr]
            attr_val.status = id_attribute_pb2.REQUESTED
    contract_msg.attribute_set.CopyFrom(id_attr_set)
    validity_in_years = input("Enter contract validity (in years): ")
    contract_msg.validity_in_years = int(validity_in_years)
    current_time = datetime.now()
    contract_msg.create_timestamp = str(current_time.isoformat())
    LOGGER.debug("Timestamp {}".format(contract_msg.create_timestamp))
    return contract_msg


def _display_id(digital_id_msg):
    status = digital_id_msg.status
    valid_years = digital_id_msg.validity_in_years
    print("ID processing status: {}".format(STATUS_ENUM[status]))
    print("ID valid for : {} years from issuance".format(valid_years))
    # Retrieve the fields of attribute_set_msg using listField
    attribute_set_msg = digital_id_msg.attribute_set
    attribute_fields = attribute_set_msg.ListFields()

    for attribute_field in attribute_fields:
        if attribute_field[0].name != 'others':
            field_name = attribute_field[0].name
            field_value = attribute_field[1]
            value_attr_data = field_value.attribute_data_enc
            attribute_struct = id_attribute_pb2.AttributeData()
            attribute_struct.ParseFromString(value_attr_data)
            print("\nDetails of field {}: \n".format(field_name.capitalize()))
            print("Status: {}".format(STATUS_ENUM[field_value.status]))
            print("Value: {}".format(attribute_struct.value))
            print("Issuer's public key: {}".format(str(attribute_struct.signer_pub_key)))
            print("Issue Timestamp: {}".format(str(attribute_struct.sign_timestamp)))
            # print("Validity: {}".format(str(attribute_struct.valid_till)))
            # print("Verification quorum: {}".format(str(field_value.verification_quorum)))
            print("Credibility score: {}".format(str(field_value.credibility_strength)))
            client_info = client_pb2.ClientAttributes()
            verifier_list = []
            for verifier in field_value.verifier_list:
                client_info.ParseFromString(verifier)
                verifier_info = client_info.user_address + " (" + \
                                FAMILY_ENUM[client_info.family_name] + ")"
                verifier_list.append(verifier_info)
            print("Verifier list: {}".format(verifier_list))
        else:
            attr_map = attribute_field[1]
            for field_name in attr_map:
                # field_name is the key
                field_value = attr_map[field_name]
                value_attr_data = field_value.attribute_data_enc
                attribute_struct = id_attribute_pb2.AttributeData()
                attribute_struct.ParseFromString(value_attr_data)
                print("\nDetails of field {}: \n".format(field_name.capitalize()))
                print("Status: {}".format(STATUS_ENUM[field_value.status]))
                print("Value: {}".format(attribute_struct.value))
                print("Issuer's public key: {}".format(str(attribute_struct.signer_pub_key)))
                print("Issue Timestamp: {}".format(str(attribute_struct.sign_timestamp)))
                # print("Validity: {}".format(str(attribute_struct.valid_till)))
                # print("Verification quorum: {}".format(str(field_value.verification_quorum)))
                print("Credibility score: {}".format(str(field_value.credibility_strength)))
                client_info = client_pb2.ClientAttributes()
                verifier_list = []
                for verifier in field_value.verifier_list:
                    client_info.ParseFromString(verifier)
                    verifier_info = client_info.user_address + " (" + \
                                    FAMILY_ENUM[client_info.family_name] + ")"
                    verifier_list.append(verifier_info)
                print("Verifier list: {}".format(verifier_list))


def review_disable_req(disabled_digital_id, owner_address, txn_id):
    LOGGER.debug("Inside certifier_client.review_disable_req()")

    print("Disable ID request received from address {}".format(owner_address))
    print("Transaction ID {}".format(txn_id))

    _display_id(disabled_digital_id)
    send_ack_resp = input("Send acknowledgement? Y/N :")
    return send_ack_resp.capitalize().strip()


def _fill_details(field_name, attribute_data, symm_key, dec_key, status=None):
    LOGGER.debug("inside _fill_details")

    # dec_key = input("Enter decode key for field {}: ".format(field_name))
    # find code for encoding data using enc_key and Id owner's public key
    # r = hashing.get_code_from_key(symm_key=symm_key, dec_key=dec_key)  # TODO find code using dec_key
    r = dec_key.to_bytes(32, 'big')
    LOGGER.debug("r = {} has type {}".format(r, type(r)))
    is_verified = False
    if attribute_data.value is not None and attribute_data.value != b'':
        # print('Existing value:')
        # print('Existing value of {} : {}'.format(field_name, attribute_data.value.decode()))
        print('\nExisting value of {} : {}'.format(field_name, attribute_data.value))
        while True:
            is_verified = hashing.verify_data_value(attribute_data.value, r)
            if not is_verified:
                print("Verification failed. Entered data does not match.\n")
                resp = input("Press 'Y' Retry. To ignore press any other key\n")
                if resp.strip().capitalize() != 'Y':
                    return
            else:
                break

    if not (is_verified and status == id_attribute_pb2.REQUESTED):
        print("\nEnter plain_text value to update\n")
        val = input("{}: ".format(field_name.capitalize()))
        attribute_data.value = hashing.get_encoding(val.lower(), r)

    LOGGER.debug("returning from _fill_details")
    # if field_name == 'name':
    #     name_val = input("Name: ")
    #     # serialize to byte
    #     # attribute_data.value = 'Suchira'.encode('utf-8')
    #     attribute_data.value = name_val.encode('utf-8')
    #     LOGGER.debug("name set to: {}".format(attribute_data.value))
    # elif field_name == 'date_of_birth':
    #     dob_val = input("Date of Birth: ")
    #     # serialize to byte
    #     # attribute_data.value = 'Jan 10, 1992'.encode('utf-8')
    #     attribute_data.value = dob_val.encode('utf-8')
    # elif field_name == 'address_permanent':
    #     paddrs_val = input("Permanent address: ")
    #     # attribute_data.value = 'Kolkata'.encode('utf-8')
    #     attribute_data.value = paddrs_val.encode('utf-8')
    # elif field_name == 'nationality':
    #     nation_val = input("Nationality: ")
    #     # attribute_data.value = 'Indian'.encode('utf-8')
    #     attribute_data.value = nation_val.encode('utf-8')
    # elif field_name == 'gender':
    #     gender_val = input("Gender: ")
    #     # attribute_data.value = 'Female'.encode('utf-8')
    #     attribute_data.value = gender_val.encode('utf-8')
    # else:
    #     field_val = input("{}: ".format(field_name))
    #     # attribute_data.value = 'Female'.encode('utf-8')
    #     attribute_data.value = field_val.encode('utf-8')
    # else create a map or add an entry to an existing map


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
        user_dir = os.path.join(os.getcwd(), key_file_name)
        if os.path.isdir(user_dir) is False:
            os.mkdir(key_file_name)
        self.events_db_file = os.path.join(user_dir, EVENTS_DB)
        self.registry_db_file = os.path.join(os.getcwd(), 'shared', REGISTRY_DB_FILE)
        registry_db = db.DB()
        registry_db.open(self.registry_db_file, None, db.DB_HASH, db.DB_CREATE)
        self._refresh_state()
        self.txn_generator = TransactionGenerator(base_url=self.base_url,
                                                  public_key=self.public_key,
                                                  signer=self._signer)

        # Added check for self._trust_score != digital_id_constants.MAX_CLIENT_TRUST_SCORE
        # to update the score as per the new value set in the algorithm
        if self._trust_score == 0 or self._trust_score != digital_id_constants.MAX_CLIENT_TRUST_SCORE:
            result = self.save_client_info()
            LOGGER.debug("From save_client_info: {}".format(result))
            self._refresh_state()

        # old code:
        # hash512(FAMILY_NAME_CERTIFY.encode('utf-8'))[0:6] + hash512(self._publicKey.encode('utf-8'))[0:64]
        # self.proc_event_listener = multiprocessing.Process(target=_start_events_listener, args=(self.public_address,))
        # self.proc_event_listener.start()

    def __del__(self):
        LOGGER.debug("Inside destructor method")

    def _refresh_state(self):
        # self.state_info_dict = {}
        print("\n--refreshing state--\n")
        LOGGER.debug("Inside certifier_client._refresh_state()")
        state_response = chain_access_util.get_state(base_url=self.base_url, address=self._self_state_address)
        LOGGER.debug("state_response: {}".format(state_response))
        if state_response == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            self._id_creation_state = digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE
            # self.state_info_dict['trust_score'] = 0
            self._trust_score = 0

        else:  # data
            self._id_creation_state = state_response
            self._trust_score = self._id_creation_state['trust_score']
            registry_db = db.DB()
            registry_db.open(self.registry_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
            reg_trust_score = registry_db.get(self._public_address.encode())
            if reg_trust_score is None:
                LOGGER.debug("Trust score is not registered yet.")
            if reg_trust_score is None or reg_trust_score != self._trust_score:
                registry_db.put(self._public_address.encode(), self._trust_score.to_bytes(length=2, byteorder='big'))
                LOGGER.debug("Trust score in user_registry_db updated to: {}".format(
                    int.from_bytes(registry_db.get(self._public_address.encode()), 'big')))
            registry_db.close()

    # process_request() is used by process_pending_requests()
    # TODO add code to handle update requests
    # def process_request(self, txn_status, address=None, owner_signature=None, signer_pub_key=None,
    def process_request(self, txn_status, address=None, signer_pub_key_hex=None,
                        transaction_id=None):
        LOGGER.debug("Inside certifier_client.process_request()")
        # TODO can receive owner signature and other information from the transaction payload itself?
        # if (owner_signature is None) or (signer_pub_key is None) or (transaction_id is None):
        if (signer_pub_key_hex is None) or (transaction_id is None):
            raise Exception('Digital ID signature cannot be verified')

        if address is None:
            raise Exception('User address cannot be empty')
        # address = self._address

        _state_data = chain_access_util.get_state(base_url=self.base_url, address=address)

        # TODO requested txn_status = REQUESTED

        # get digital id and transaction from _state_data
        try:
            id_data = _state_data['digital_id']
            state_transaction_id = _state_data['acting_transaction_id']
            LOGGER.debug("Transaction id from state: {}".format(state_transaction_id))
        except BaseException as err:
            LOGGER.error("Error while reading state data : {}".format(err))
            raise Exception("Error while reading state data")
        if id_data is None or id_data is b'':
            LOGGER.error("Invalid digital ID information in state")
            raise InvalidTransaction("Invalid digital ID information in state")

        if state_transaction_id != transaction_id:
            # TODO invalidate request or clear state data
            LOGGER.error("state_transaction_id {} does not match with requesting transaction id {}".
                         format(state_transaction_id, transaction_id))
            raise InvalidTransaction("Invalid transaction id information in state")
        txn_response = chain_access_util.get_transaction(base_url=self.base_url, requesting_txn_id=transaction_id)
        try:
            txn_payload = txn_response['payload']
            digital_id_transaction = DigitalIdTransaction()
            digital_id_transaction.ParseFromString(base64.b64decode(txn_payload))
            # digital_id = digital_id_pb2.DigitalId
            # digital_id.ParseFromString(digital_id_transaction.digital_id)
            # TODO set owner_info
            owner_signature = digital_id_transaction.owner_signature
            owner_info = digital_id_transaction.owner_info
        except BaseException as err:
            LOGGER.error("Error while reading transaction data {}".format(err))
            raise Exception("Error while reading transaction data")

        digital_id_msg = self._get_digital_id(id_data, txn_status)
        # if pii_credential_msg is :
        LOGGER.debug('pii_credential_msg.name.attribute_data_enc : {}'
                     .format(digital_id_msg.attribute_set.name.attribute_data_enc))
        # send transaction to update state data
        action = ""
        if txn_status == id_attribute_pb2.Status.REQUESTED \
                or txn_status == id_attribute_pb2.Status.ON_UPDATE:

            if owner_info.trust_score == digital_id_constants.UNINITIATED_ID_TRUST_SCORE:
                owner_info.trust_score = digital_id_constants.PRIMARY_CERTIFIED_TRUST_SCORE
            # TODO else : add renewal logic
            action = "issue_certificate"
        elif txn_status == id_attribute_pb2.Status.CONFIRMED:
            action = "ack_confirmation"

        result = self._create_n_send_txn(action=action, to_address_list=[address], digital_id_msg=digital_id_msg,
                                         dependency_txn_list=[transaction_id], owner_signature=owner_signature,
                                         owner_info=owner_info)
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

    # TODO handle update requests
    def process_pending_requests(self):
        events_db = db.DB()
        try:
            events_db.open(self.events_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
            key = "digitalid/request".encode()
            LOGGER.debug(key)
            request_list = events_db.get(key)
            # processed = []
            LOGGER.debug(request_list)
            if request_list is not None:
                request_events = cbor.loads(request_list)
                pending_list = request_events
                LOGGER.debug(request_events)
                for request_event in request_events:
                    address = request_event['address']
                    transaction_id = request_event['transaction_id']
                    signer_public_key = request_event['signer_public_key']
                    # Removing owner_signature
                    # signature = request_event['owner_signature']
                    requester = hashing.get_pub_key_hash(signer_public_key)
                    resp = input("Process ID request for address {} ? Y/N: ".format(requester))
                    if resp.capitalize().strip() == 'Y':

                        try:
                            # TODO
                            # isSuccess = self.process_request(id_attribute_pb2.Status.REQUESTED, address,
                            isSuccess = self.process_request(id_attribute_pb2.Status.REQUESTED, address,
                                                             signer_public_key, transaction_id)
                            if isSuccess is True:
                                # processed.append(request_event)
                                pending_list.remove(request_event)
                                print("Successfully Processed")
                        except InvalidTransaction:
                            pending_list.remove(request_event)
                            # events_db.put(key, cbor.dumps(pending_list))
                            # events_db.close()
                            print("Invalid Transaction - Removed Request from list")
                            continue
                    else:
                        LOGGER.debug("Request from {} skipped".format(requester))
                        continue

                # request_list = [event for event in request_events if event not in processed]
                LOGGER.debug(pending_list)
                events_db.put(key, cbor.dumps(pending_list))
                events_db.close()
            else:
                print("No peer verification request pending")

        except BaseException as err:
            LOGGER.error("Error while reading event db {}".format(err))
            raise Exception(err)
        finally:
            LOGGER.debug("Inside finally")
            events_db.close()

    def process_recovery_request(self, req_txn_id):
        """This method processes ID recovery request from users.
        Parameter req_txn_id holds the txn_id using which the ID was invalidated"""

        LOGGER.debug("Inside certifier_client.process_recovery_request")
        # retrieve req_txn_id to get owner_pub_address
        # retrieve transaction requesting ID invalidation
        txn_response = chain_access_util.get_transaction(base_url=self.base_url, requesting_txn_id=req_txn_id)
        try:
            txn_header = txn_response['header']
            signer_pub_key_hex = txn_header['signer_public_key']
            # get digital id from transaction payload and check its state
            txn_payload = txn_response['payload']
            req_transaction = digital_id_transaction_pb2.DigitalIdTransaction()
            req_transaction.ParseFromString(base64.b64decode(txn_payload))
            owner_signature = req_transaction.owner_signature
            owner_info = req_transaction.owner_info
            digital_id_bytes = req_transaction.digital_id
            digital_id_in_txn = digital_id_pb2.DigitalId()
            digital_id_in_txn.ParseFromString(digital_id_bytes)
            old_pub_key = digital_id_in_txn.id_owner_public_key
        except BaseException as err:
            LOGGER.error("Error while reading transaction data {}".format(err))
            print("Error while reading transaction data {}".format(err))
            return False

        if req_transaction.status != id_attribute_pb2.Status.RECOVERY_REQ:
            print("The input transaction is not a valid reference for recovery request")
            return False

        owner_address = hashing.get_pub_key_hash(signer_pub_key_hex)

        # April 3, 2020: check the owner_address state space for Recovery_req operation
        req_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                          pub_key_hash=owner_address,
                                                          key=FAMILY_NAME_CERTIFIER)
        _req_state_data = chain_access_util.get_state(base_url=self.base_url, address=req_state_address)

        if _req_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            print("Invalid state data for {} ".format(owner_address))
            return False

        try:
            req_digital_id_data = _req_state_data['digital_id']
        except BaseException as err:
            LOGGER.error("Error while reading state data : {}".format(err))
            print("Digital Id cannot be retrieved")
            print("Error while reading state data {}".format(err))
            return False

        if req_digital_id_data is None or req_digital_id_data is b'':
            LOGGER.error("Invalid Digital-ID state found for {}".format(owner_address))
            print("Recovery Request Digital-ID cannot be found")
            return False
        else:
            # check status of the retrieved digital_id_data
            req_digital_id = digital_id_pb2.DigitalId()
            req_digital_id.ParseFromString(req_digital_id_data)
            if req_digital_id.status != id_attribute_pb2.Status.RECOVERY_REQ:
                LOGGER.error("Retrieved digital ID from state of {} has non-permitted status of {}",
                             owner_address, req_digital_id.status)
                print("Requesting Digital ID has an invalid status. Retrieved status {}".format(
                    req_digital_id.status))
                return False

        # get the digital-id from the recovery_address state space
        recovery_address = hashing.get_pub_key_hash(old_pub_key)
        state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                      pub_key_hash=recovery_address,
                                                      key=FAMILY_NAME_CERTIFIER)
        _state_data = chain_access_util.get_state(base_url=self.base_url, address=state_address)

        if _state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            print("Recovery of ID not possible - ID state of learner {} not found".format(recovery_address))
            return False

        try:
            digital_id_data = _state_data['digital_id']
        except BaseException as err:
            LOGGER.error("Error while reading state data : {}".format(err))
            print("Digital Id cannot be retrieved")
            print("Error while reading state data {}".format(err))
            return False

        if digital_id_data is None or digital_id_data is b'':
            LOGGER.error("Invalid Digital-ID state")
            print("Digital-ID cannot be found")
            return False
        else:
            # check status of the retrieved digital_id_data
            recovered_digital_id = digital_id_pb2.DigitalId()
            recovered_digital_id.ParseFromString(digital_id_data)
            # if recovered_digital_id.status != id_attribute_pb2.Status.RECOVERY_REQ:
            if recovered_digital_id.status != id_attribute_pb2.Status.INVALID:
                LOGGER.error("Retrieved digital ID from state of {} has non-permitted status of {}",
                             recovery_address, recovered_digital_id.status)
                print("Requested Digital ID is not invalidated yet. Retrieved status {}".format(
                    recovered_digital_id.status))
                return False
            else:
                # change state and issue new certificate on the digital id
                is_any_valid = self._verify_and_certify(digital_id=recovered_digital_id)

                # send transaction
                if is_any_valid:
                    # set trust_score to 1?
                    recovered_digital_id.status = id_attribute_pb2.Status.ON_VERIFICATION
                    recovered_digital_id.id_owner_public_key = signer_pub_key_hex

                    if owner_info.trust_score == digital_id_constants.UNINITIATED_ID_TRUST_SCORE:
                        owner_info.trust_score = digital_id_constants.PRIMARY_CERTIFIED_TRUST_SCORE

                    result = self._create_n_send_txn(action="issue_certificate",
                                                     to_address_list=[req_state_address, state_address],
                                                     digital_id_msg=recovered_digital_id,
                                                     dependency_txn_list=[req_txn_id], owner_signature=owner_signature,
                                                     owner_info=owner_info,
                                                     from_address_list=[req_state_address, state_address])

                    LOGGER.debug(result)
                    print(result)
                    if result != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
                        status = yaml.safe_load(result)['data'][0]['status']
                        if status == 'COMMITTED':
                            print("Recovered DigitalID successfully committed")
                            return True
                        elif status == 'UNKNOWN':
                            print("Transaction status unknown")
                            return True
                        else:
                            print("Failed to recover digital ID")
                            return False
                    else:
                        return False

    def _verify_and_certify(self, digital_id):
        LOGGER.debug("Inside certifier_client._verify_and_certify()")
        attribute_set_msg = digital_id.attribute_set
        attribute_fields = attribute_set_msg.ListFields()
        removal_list = []
        other_attr_map = None
        is_any_valid = False
        # print("\nDecoder key file for learner {} to be uploaded".format(hashing.get_pub_key_hash(id_owner_public_key)))
        code_file_path = input("Please enter the decoder key file path: \n")
        file_handle = open(code_file_path, "r+")
        code_str = file_handle.readline()
        is_valid = False
        for attribute_field in attribute_fields:
            code_dict = json.loads(code_str)

            if attribute_field[0].name != 'others':
                dec_key = code_dict.get(attribute_field[0].name)
                LOGGER.debug('dec_key {}'.format(dec_key))
                r = dec_key.to_bytes(32, 'big')
                field_name = attribute_field[0].name
                attribute = attribute_field[1]
                data = attribute.attribute_data_enc
                attribute_data = id_attribute_pb2.AttributeData()
                attribute_data.ParseFromString(data)
                print('\n{}: {}\n'.format(field_name.capitalize(),
                                          attribute_data.value))
                # is_valid = input('Is data valid? Y/N: ')
                # if is_valid.capitalize().strip() == 'Y':

                for i in range(3):
                    is_valid = hashing.verify_data_value(attribute_data.value, r)
                    if not is_valid:
                        print("Verification failed. Entered data does not match.\n")
                        if i < 3:
                            resp = input("Press 'Y' Retry. To ignore press any other key\n")
                            if resp.strip().capitalize() != 'Y':
                                break
                    else:
                        break

                if is_valid is True:
                    self._issue_certificate(id_attribute=attribute, attribute_data=attribute_data)
                    is_any_valid = True
                # elif is_valid.capitalize().strip() == 'N':
                else:
                    # remove invalid data from the ID
                    removal_list.append(attribute_field[0].name)
            elif attribute_field[0].name == 'others':
                other_attr_map = attribute_field[1]
                for field_name in other_attr_map:
                    dec_key = code_dict.get(field_name)
                    LOGGER.debug('dec_key {}'.format(dec_key))
                    r = dec_key.to_bytes(32, 'big')
                    attribute = other_attr_map[field_name]
                    value_attr_data = attribute.attribute_data_enc
                    # TODO decrypt data here
                    attribute_data = id_attribute_pb2.AttributeData()
                    attribute_data.ParseFromString(value_attr_data)
                    print('\n{}: {}\n'.format(field_name.capitalize(),
                                              attribute_data.value))
                    # is_valid = input('Is data valid? Y/N: ')
                    # if is_valid.capitalize().strip() == 'Y':

                    for i in range(3):
                        is_valid = hashing.verify_data_value(attribute_data.value, r)
                        if not is_valid:
                            print("Verification failed. Entered data does not match.\n")
                            if i < 3:
                                resp = input("Press 'Y' Retry. To ignore press any other key\n")
                                if resp.strip().capitalize() != 'Y':
                                    break
                        else:
                            break

                    if is_valid is True:
                        self._issue_certificate(attribute, attribute_data)
                        is_any_valid = True
                    # elif is_valid.capitalize().strip() == 'N':
                    else:
                        # invalidate data
                        removal_list.append(attribute_field[0].name)

        if is_any_valid:
            for attr_name in removal_list:
                LOGGER.debug('Removing field {} from ID attribute set'.format(attr_name))
                try:
                    if attribute_set_msg.HasField(attr_name):
                        attribute_set_msg.ClearField(attr_name)
                    elif other_attr_map is not None:
                        other_attr_map.pop(attr_name)
                except Exception as err:
                    print("Error while removing invalid attribute data {}".format(attr_name))
                    LOGGER.error(err)

            # for debug
            if len(removal_list) != 0:
                LOGGER.debug("Following attributes are present after verification: ")
                attribute_fields = attribute_set_msg.ListFields()
                for attribute_field in attribute_fields:
                    LOGGER.debug("attribute {}".format(attribute_field[0].name))

        return is_any_valid

    def process_id_request(self, owner_pub_address):
        LOGGER.debug("Inside certifier_client.process_id_request")

        id_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                         pub_key_hash=owner_pub_address, key=FAMILY_NAME_CERTIFIER)
        _state_data = chain_access_util.get_state(base_url=self.base_url, address=id_state_address)
        # get digital id and transaction from _state_data
        try:
            id_data = _state_data['digital_id']
            state_transaction_id = _state_data['acting_transaction_id']
            digital_id = digital_id_pb2.DigitalId()
            digital_id.ParseFromString(id_data)
            txn_status = digital_id.status
            LOGGER.debug("Digital ID status: {}".format(txn_status))
            if txn_status != id_attribute_pb2.Status.REQUESTED and \
                    txn_status != id_attribute_pb2.Status.ON_UPDATE:
                print("Operation not allowed for {}".format(owner_pub_address))
                return
            signer_pub_key_hex = digital_id.id_owner_public_key
            signer_address = hashing.get_pub_key_hash(signer_pub_key_hex)
            LOGGER.debug("Transaction id from state: {}".format(state_transaction_id))
            LOGGER.debug("ID owner public key: {}".format(signer_pub_key_hex))
            # TODO test this
            if signer_address != owner_pub_address:
                print("Owner address {} is not valid".format(owner_pub_address))
                return
        except BaseException as err:
            LOGGER.error("Error while reading state data : {}".format(err))
            raise Exception("Error while reading state data")

        if id_data is None or id_data is b'':
            LOGGER.error("Empty digital ID information in state")
            raise Exception("Invalid digital ID information in state")

        LOGGER.debug("state_transaction_id is {}".format(state_transaction_id))
        if state_transaction_id is None:
            # blacklist the owner_address
            registry_db = db.DB()
            registry_db.open(self.registry_db_file, None, db.DB_HASH, db.DB_CREATE)
            self.black_list.append(owner_pub_address)
            registry_db.put('black_list'.encode(), cbor.dumps(self.black_list))
            registry_db.close()
            print("Address {} is blacklisted".format(owner_pub_address))
            print("Updated black_list {}".format(self.black_list))
            LOGGER.error("state_transaction_id is {}".format(state_transaction_id))
            raise Exception("Invalid transaction id information in state")

        # transaction data is being fetched to see if the retrieved state is consistent
        # ----- start of consistency check ----------
        txn_response = chain_access_util.get_transaction(base_url=self.base_url, requesting_txn_id=state_transaction_id)
        try:
            txn_payload = txn_response['payload']
            digital_id_transaction = DigitalIdTransaction()
            digital_id_transaction.ParseFromString(base64.b64decode(txn_payload))
            owner_signature = digital_id_transaction.owner_signature

            if id_data != digital_id_transaction.digital_id:
                # blacklisting the address derived from the public key
                LOGGER.error("id data not same in state and transaction")
                print("Invalid digital ID or transaction for ID request")
                registry_db = db.DB()
                registry_db.open(self.registry_db_file, None, db.DB_HASH, db.DB_CREATE)
                self.black_list.append(owner_pub_address)
                registry_db.put('black_list'.encode(), cbor.dumps(self.black_list))
                registry_db.close()
                print("Address {} blacklisted".format(owner_pub_address))
                LOGGER.error("Address {} blacklisted".format(owner_pub_address))
                LOGGER.error("Updated blacklist {}".format(self.black_list))
                return False
            # Apr 13, 2020: Following check is removed.
            # This check is redundant as such conditions are taken care of by the transaction processors
            # txn_header = txn_response['header']
            # txn_signing_key = txn_header['signer_public_key']
            # if txn_signing_key != signer_pub_key:
            #     LOGGER.error("Invalid Request: "
            #                  "Transaction is not signed by the id owner")
            #     print("Invalid Request: "
            #           "Transaction is not signed by the id owner")
            #
            #     return False
            # setting owner_info
            owner_info = digital_id_transaction.owner_info
        except BaseException as err:
            LOGGER.error("Error while reading transaction data {}".format(err))
            print("Error while reading transaction data: {}".format(err))
            return False
        # ---End of consistency check --

        digital_id_msg = self._get_digital_id(id_data, txn_status)
        LOGGER.debug('pii_credential_msg.name.attribute_data_enc : {}'
                     .format(digital_id_msg.attribute_set.name.attribute_data_enc))
        # send transaction to update state data
        action = ""
        if txn_status == id_attribute_pb2.Status.REQUESTED \
                or txn_status == id_attribute_pb2.Status.ON_UPDATE:
            if owner_info.trust_score == digital_id_constants.UNINITIATED_ID_TRUST_SCORE:
                owner_info.trust_score = digital_id_constants.PRIMARY_CERTIFIED_TRUST_SCORE
            # TODO else : add renewal logic, keep the trust score same
            action = "issue_certificate"

        try:
            result = self._create_n_send_txn(action=action, to_address_list=[id_state_address],
                                             digital_id_msg=digital_id_msg, dependency_txn_list=[state_transaction_id],
                                             owner_signature=owner_signature, owner_info=owner_info)

        except InvalidTransaction as err:
            print("Received InvalidTransaction {}".format(err))
            return False
        LOGGER.debug(result)
        print(result)
        if result != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
            status = yaml.safe_load(result)['data'][0]['status']
            if status == 'COMMITTED':
                print("Request successfully processed")
                try:
                    events_db = db.DB()
                    events_db.open(self.events_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
                    key = "digitalid/request"
                    data = events_db.get(key.encode())
                    if data is not None:
                        request_list = cbor.loads(data)
                        if request_list is not None and request_list != []:
                            for req in request_list:
                                if req['signer_public_key'] == signer_pub_key_hex:
                                    request_list.remove(req)
                                    events_db.put(key.encode(), cbor.dumps(request_list))
                    events_db.close()
                except BaseException:
                    LOGGER.debug("Exception while updating database")
                    traceback.print_exc(file=sys.stderr)
                return True
            elif status == 'UNKNOWN':
                print("Transaction status unknown")
                return True
            else:
                print("Failed to process request")
                return False
        else:
            return False

    def send_ack(self, address):
        LOGGER.debug("Inside certifier_client.send_ack()")
        state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                      pub_key_hash=address,
                                                      key=FAMILY_NAME_CERTIFIER)
        _state_data = chain_access_util.get_state(base_url=self.base_url, address=state_address)
        try:
            id_data = _state_data['digital_id']
            transaction_id = _state_data['acting_transaction_id']
            LOGGER.debug("Transaction id from state: {}".format(transaction_id))
        except BaseException as err:
            LOGGER.error("Error while reading state data : {}".format(err))
            print("Error while reading state data : {}".format(err))
            return False
            # raise Exception("Error while reading state data")

        if id_data is None or id_data is b'':
            LOGGER.error("Invalid digital ID information in state")
            print("Digital-ID information not found in the state")
            return False
            # raise Exception("Invalid digital ID information in state")

        # added code to check if the status is CONFIRMED
        digital_id_msg = digital_id_pb2.DigitalId()
        digital_id_msg.ParseFromString(id_data)
        id_status = digital_id_msg.status
        if id_status != id_attribute_pb2.Status.CONFIRMED:
            LOGGER.error("Digital-id status found {}. Expected value {}".
                         format(id_status, id_attribute_pb2.Status.CONFIRMED))
            print("The Digital-ID under processing does not have a confirmed status")
            return False

        # retrieve acting_transaction_id
        txn_response = chain_access_util.get_transaction(base_url=self.base_url, requesting_txn_id=transaction_id)
        try:
            # txn_header = txn_response['header']
            # id_owner_pub_key = txn_header['signer_public_key']
            txn_payload = txn_response['payload']
            digital_id_transaction = DigitalIdTransaction()
            digital_id_transaction.ParseFromString(base64.b64decode(txn_payload))
            owner_signature = digital_id_transaction.owner_signature
            # txn_status = digital_id_transaction.status
            owner_info = digital_id_transaction.owner_info
            # TODO debug
            if digital_id_transaction.digital_id == id_data:
                LOGGER.debug("Id data in digital_id_transaction and state matched")
            else:
                LOGGER.debug("Id data in digital_id_transaction and state did not match")

            if owner_info.trust_score != digital_id_constants.CONFIRMED_ID_TRUST_SCORE:
                LOGGER.error("Wrong value of owner_info.trust_score {}".format(owner_info.trust_score))
                raise Exception("ID owner's trust_score not appropriate")

        except BaseException as err:
            LOGGER.error("Error while reading transaction data {}".format(err))
            raise Exception("Error while reading transaction data")

        # removed the code for getting new digital-id.
        # Signing over the ID that is present in the requesting transaction.

        # pii_credential_msg = self._get_digital_id(id_data, txn_status)

        # send transaction to update state data
        action = "ack_confirmation"
        result = self._create_n_send_txn(action=action, to_address_list=[state_address], digital_id_msg=id_data,
                                         dependency_txn_list=[transaction_id], owner_signature=owner_signature,
                                         owner_info=owner_info)

        LOGGER.debug(result)
        print(result)
        if result != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
            status = yaml.safe_load(result)['data'][0]['status']
            if status == 'COMMITTED':
                print("Acknowledgement successfully committed")
                return True
            elif status == 'UNKNOWN':
                print("Transaction status unknown")
                return True
            else:
                print("Failed to commit acknowledgement")
                return False
        else:
            return False

    # def _isfilled(self, id_attribute):
    #     LOGGER.debug(id_attribute.status)
    #     if id_attribute.status != id_attribute_pb2.Status.DEFAULT:
    #         return True
    #     else:
    #         return False

    def _issue_certificate(self, id_attribute, attribute_data):
        LOGGER.debug("inside _issue_certificate")
        attribute_data.signer_pub_key = self.public_key
        current_time = datetime.now()
        attribute_data.sign_timestamp = str(current_time.isoformat())
        # introduced _validity_in_years to remove hardcode
        years = self._validity_in_years
        attribute_data.valid_till = str(current_time.replace(year=(current_time.year + years)).isoformat())
        attribute_data.enc_code = random.random().hex().encode()
        attribute_data_bytes = attribute_data.SerializeToString()
        id_attribute.status = id_attribute_pb2.Status.ON_VERIFICATION
        id_attribute.attribute_data_enc = attribute_data_bytes
        # changed code to signing on hash
        id_attribute.certificate = self._signer.sign(hashing.get_hash_from_bytes(attribute_data_bytes))
        # id_attribute.certificate = self._signer.sign(attribute_data_bytes)
        # id_attribute.verification_quorum = self._trust_score
        id_attribute.credibility_strength = 0
        LOGGER.debug('id_attribute.attribute_data_enc : {}'.format(id_attribute.attribute_data_enc))

    def _fill_and_sign_attributes(self, id_owner_public_key, attribute_set_msg):

        LOGGER.debug("Inside certifier_client._fill_and_sign_attributes")
        # TODO Currently not matching attribute status with ID status
        # if attribute_set_msg.IsInitialized():
        #     LOGGER.debug("attribute_set_msg is initialized")
        #     # always initialized
        # else:
        #     LOGGER.debug("attribute_set_msg is not initialized")

        self._process_user_id(id_owner_public_key, attribute_set_msg)

        # populate name
        # if attribute_set_msg.HasField('name'):  # if block will be taken in UPDATE flow
        #     name_attribute = attribute_set_msg.name
        #     LOGGER.debug("name_attribute is initialized")
        # else:  # else block is taken in REQUEST/UPDATE ID flow
        #     name_attribute = id_attribute_pb2.AttributeDataType()
        #     LOGGER.debug("name_attribute is not initialized")
        #
        # # Adding change for update
        # if name_attribute.status == id_attribute_pb2.Status.ON_UPDATE or \
        #         name_attribute.status == id_attribute_pb2.REQUESTED or \
        #         name_attribute.status == id_attribute_pb2.Status.DEFAULT:
        #     LOGGER.debug("Populating name")
        #     self._populate_attribute('name', name_attribute)
        #     attribute_set_msg.name.CopyFrom(name_attribute)
        #     LOGGER.debug('attribute_set_msg.name.attribute_data_enc : {}'
        #                  .format(attribute_set_msg.name.attribute_data_enc))

        # populate date of birth
        # if attribute_set_msg.HasField('date_of_birth'):
        #     dob_attribute = attribute_set_msg.date_of_birth
        #     LOGGER.debug("attribute_set_msg.date_of_birth is initialized")
        # else:
        #     dob_attribute = id_attribute_pb2.AttributeDataType()
        #     LOGGER.debug("attribute_set_msg.date_of_birth is not initialized")
        #
        # if dob_attribute.status == id_attribute_pb2.Status.ON_UPDATE or \
        #         dob_attribute.status == id_attribute_pb2.REQUESTED or \
        #         dob_attribute.status == id_attribute_pb2.Status.DEFAULT:
        #     LOGGER.debug("populating date of birth")
        #     self._populate_attribute('date_of_birth', dob_attribute)
        #     attribute_set_msg.date_of_birth.CopyFrom(dob_attribute)
        #     LOGGER.debug('attribute_set_msg.date_of_birth.attribute_data_enc : {}'
        #                  .format(attribute_set_msg.date_of_birth.attribute_data_enc))
        #
        # # populate permanent address
        # if attribute_set_msg.HasField('address_permanent'):
        #     address_perm_attribute = attribute_set_msg.address_permanent
        #     LOGGER.debug("attribute_set_msg.address_permanent is initialized")
        # else:
        #     address_perm_attribute = id_attribute_pb2.AttributeDataType()
        #     LOGGER.debug("attribute_set_msg.address_permanent is not initialized")
        # if address_perm_attribute.status == id_attribute_pb2.Status.ON_UPDATE or \
        #         address_perm_attribute.status == id_attribute_pb2.REQUESTED or \
        #         address_perm_attribute.status == id_attribute_pb2.Status.DEFAULT:
        #     LOGGER.debug("populating permanent address")
        #     self._populate_attribute('address_permanent', address_perm_attribute)
        #     attribute_set_msg.address_permanent.CopyFrom(address_perm_attribute)
        #     LOGGER.debug('attribute_set_msg.address_permanent.attribute_data_enc : {}'
        #                  .format(attribute_set_msg.address_permanent.attribute_data_enc))
        #
        # # populate nationality
        # if attribute_set_msg.HasField('nationality'):
        #     nationality_attribute = attribute_set_msg.nationality
        #     LOGGER.debug("attribute_set_msg.nationality is initialized")
        # else:
        #     nationality_attribute = id_attribute_pb2.AttributeDataType()
        #     LOGGER.debug("attribute_set_msg.nationality is not initialized")
        #
        # if nationality_attribute.status == id_attribute_pb2.Status.ON_UPDATE or \
        #         nationality_attribute.status == id_attribute_pb2.REQUESTED or \
        #         nationality_attribute.status == id_attribute_pb2.Status.DEFAULT:
        #     LOGGER.debug("populating nationality")
        #     self._populate_attribute('nationality', nationality_attribute)
        #     attribute_set_msg.nationality.CopyFrom(nationality_attribute)
        #     LOGGER.debug('attribute_set_msg.nationality.attribute_data_enc : {}'
        #                  .format(attribute_set_msg.nationality.attribute_data_enc))
        #
        # # populate gender
        # if attribute_set_msg.HasField('gender'):
        #     gender_attribute = attribute_set_msg.gender
        #     LOGGER.debug("attribute_set_msg.gender is initialized")
        # else:
        #     gender_attribute = id_attribute_pb2.AttributeDataType()
        #     LOGGER.debug("attribute_set_msg.gender is not initialized")

        # if gender_attribute.status == id_attribute_pb2.Status.ON_UPDATE or \
        #         gender_attribute.status == id_attribute_pb2.REQUESTED or \
        #         gender_attribute.status == id_attribute_pb2.Status.DEFAULT:
        #     LOGGER.debug("populating gender")
        #     self._populate_attribute('gender', gender_attribute)
        #     attribute_set_msg.gender.CopyFrom(gender_attribute)
        #     LOGGER.debug('attribute_set_msg.nationality.attribute_data_enc : {}'
        #                  .format(attribute_set_msg.gender.attribute_data_enc))
        #
        # # populate others by iterating through the map and certify
        # # no else block : no need to populate if not set by the requester
        # try:
        #     other_attributes_map = attribute_set_msg.others
        #     for field_name in other_attributes_map:
        #         field_value = other_attributes_map[field_name]
        #         if field_value.status == id_attribute_pb2.Status.ON_UPDATE or \
        #                 field_value.status == id_attribute_pb2.REQUESTED or \
        #                 field_value.status == id_attribute_pb2.Status.DEFAULT:
        #             self._populate_attribute(field_name, field_value)
        #             # other_attributes_map[field_name] = field_value
        #             LOGGER.debug('others.{}.attribute_data_enc : {}'
        #                          .format(field_name, other_attributes_map.get(field_name).attribute_data_enc))
        # except AttributeError as err:
        #     LOGGER.debug(err)
        #     print("No additional attribute is requested")

        return attribute_set_msg

    def _get_digital_id(self, state_data, txn_status):

        LOGGER.debug("Inside certifier_client._get_digital_id()")
        # TODO code to decrypt state_data goes here
        digital_id_msg = digital_id_pb2.DigitalId()
        digital_id_msg.ParseFromString(state_data)
        status = digital_id_msg.status
        # owner_pub_key = pii_credential_msg.id_owner_public_key
        LOGGER.debug("Status = %s.", status)
        # verify the txn_status and signer public keys
        if txn_status != status:
            LOGGER.error("Invalid Request: "
                         "Transaction status does not match with Digital ID status ")

            raise Exception("Invalid Request: "
                            "Transaction status does not match with Digital ID status ")
        # TODO inappropriate logic. owner_pub_key == pii_credential_msg.id_owner_public_key
        # if txn_signing_key != owner_pub_key:
        #     LOGGER.error("Invalid Request: "
        #                  "Transaction is not signed by the id owner")
        #     raise Exception("Invalid Request: "
        #                     "Transaction is not signed by the id owner")

        if status == id_attribute_pb2.Status.REQUESTED:
            LOGGER.debug("Processing ID request")
            digital_id_msg.validity_in_years = self._validity_in_years
            if digital_id_msg.HasField('attribute_set'):
                attribute_set_msg = digital_id_msg.attribute_set
                LOGGER.debug("attribute_set has field true")
            else:
                attribute_set_msg = digital_id_pb2.IdAttributeSet()
                LOGGER.debug("attribute_set has field false")
            self._fill_and_sign_attributes(digital_id_msg.id_owner_public_key, attribute_set_msg)
            digital_id_msg.attribute_set.CopyFrom(attribute_set_msg)
            digital_id_msg.status = id_attribute_pb2.Status.ON_VERIFICATION
            return digital_id_msg

        if status == id_attribute_pb2.Status.CONFIRMED:
            return digital_id_msg

        if status == id_attribute_pb2.Status.ON_UPDATE:
            LOGGER.debug("Processing ID update request")
            attribute_set_msg = digital_id_msg.attribute_set
            self._fill_and_sign_attributes(digital_id_msg.id_owner_public_key, attribute_set_msg)
            digital_id_msg.attribute_set.CopyFrom(attribute_set_msg)
            digital_id_msg.status = id_attribute_pb2.Status.ON_VERIFICATION
            return digital_id_msg

    def _process_user_id(self, id_owner_public_key, attribute_set_msg):
        LOGGER.debug("_process_user_id")
        print("\nDecoder key file for learner {} to be uploaded".format(hashing.get_pub_key_hash(id_owner_public_key)))
        code_file_path = input("Please enter the decoder key file path: \n")
        file_handle = open(code_file_path, "r+")
        code_str = file_handle.readline()
        code_dict = json.loads(code_str)
        # Find symmetric key
        priv_bytes = self._private_key.as_bytes()
        symm_key = hashing.get_symmetric_key(private_key_bytes=priv_bytes, public_key_bytes=id_owner_public_key)
        # read file of name id_owner_public_key
        if attribute_set_msg.name.status == id_attribute_pb2.Status.DEFAULT:
            attribute_set_msg.name.status = id_attribute_pb2.REQUESTED
        if attribute_set_msg.date_of_birth.status == id_attribute_pb2.Status.DEFAULT:
            attribute_set_msg.date_of_birth.status = id_attribute_pb2.REQUESTED
        if attribute_set_msg.address_permanent.status == id_attribute_pb2.Status.DEFAULT:
            attribute_set_msg.address_permanent.status = id_attribute_pb2.REQUESTED
        if attribute_set_msg.nationality.status == id_attribute_pb2.Status.DEFAULT:
            attribute_set_msg.nationality.status = id_attribute_pb2.REQUESTED
        if attribute_set_msg.gender.status == id_attribute_pb2.Status.DEFAULT:
            attribute_set_msg.gender.status = id_attribute_pb2.REQUESTED

        attribute_fields = attribute_set_msg.ListFields()
        for attribute_field in attribute_fields:
            field_name = attribute_field[0].name
            if field_name != 'others':
                field_value = attribute_field[1]
                if field_value.status == id_attribute_pb2.Status.ON_UPDATE or \
                        field_value.status == id_attribute_pb2.REQUESTED or \
                        field_value.status == id_attribute_pb2.DEFAULT:
                    LOGGER.debug("populating {}".format(field_name))
                    dec_key = code_dict.get(field_name)
                    self._populate_attribute(field_name=field_name, field_attribute=field_value,
                                             symm_key=symm_key, dec_key=dec_key)
                    LOGGER.debug('field_value.attribute_data_enc : {}'
                                 .format(field_value.attribute_data_enc))
            elif field_name == 'others':
                others_map = attribute_field[1]
                for field_name in others_map:
                    field_value = others_map[field_name]
                    if field_value.status == id_attribute_pb2.Status.ON_UPDATE or \
                            field_value.status == id_attribute_pb2.REQUESTED or \
                            field_value.status == id_attribute_pb2.DEFAULT:
                        LOGGER.debug("populating {}".format(field_name))
                        dec_key = code_dict.get(field_name)
                        self._populate_attribute(field_name=field_name, field_attribute=field_value,
                                                 symm_key=symm_key, dec_key=dec_key)
                        LOGGER.debug('attribute_data.attribute_data_enc : {}'
                                     .format(field_value.attribute_data_enc))

    def _populate_attribute(self, field_name, field_attribute, symm_key, dec_key):

        LOGGER.debug("Inside certifier_client._populate_attribute()")
        # if attribute has no value and status is 0
        # then fill the attribute with learner input and issue certificate
        # else only verify and issue certificate

        # Commenting out the _isfilled() check as data will be
        # always inserted/updated by the  certifier
        # if not self._isfilled(field_attribute):

        attribute_data = id_attribute_pb2.AttributeData()
        if field_attribute.attribute_data_enc is not None and \
                field_attribute.attribute_data_enc != b'':
            LOGGER.debug("field_attribute.attribute_data_enc is present {}".format(field_attribute.attribute_data_enc))
            attribute_data.ParseFromString(field_attribute.attribute_data_enc)

        if field_attribute.status == id_attribute_pb2.REQUESTED or \
                field_attribute.status == id_attribute_pb2.ON_UPDATE or \
                field_attribute.status == id_attribute_pb2.DEFAULT:
            # field_attribute.status == id_attribute_pb2.DEFAULT:
            print("\nPlease enter the following detail\n")
            _fill_details(field_name=field_name, attribute_data=attribute_data, symm_key=symm_key,
                          dec_key=dec_key, status=field_attribute.status)

        self._issue_certificate(field_attribute, attribute_data)
        LOGGER.debug('attribute_data.value : {}'.format(attribute_data.value))

    # Modified definition March 9: removing peer_address as parameter
    # def attest_peer(self, request_txn_id=None, peer_address=None):
    def attest_peer(self, request_txn_id=None):

        """This method verifies and attests Digital-id attributes in a peer verification request.
        Sends peer verification response thereafter"""

        LOGGER.debug("Inside attest_peer")
        LOGGER.debug("Certifier public key : {}".format(self.public_key))
        peer_verifier = peer_verification_module.PeerVerificationClass(base_url=self.base_url,
                                                                       events_db_file=self.events_db_file,
                                                                       signer=self._signer,
                                                                       private_key=self._private_key,
                                                                       public_key=self.public_key,
                                                                       score=self._trust_score)

        # if peer_address is not None and request_txn_id is not None:
        if request_txn_id is not None:
            # if peer_verifier.verify_peer_data(peer_address=peer_address, request_txn_id=request_txn_id) is True:
            try:
                if peer_verifier.verify_peer_data(request_txn_id=request_txn_id) is True:
                    # print("Request successfully processed")
                    events_db = db.DB()
                    try:
                        events_db.open(self.events_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
                        key = "peer_verification/request"
                        data = events_db.get(key.encode())
                        if data is not None:
                            request_list = cbor.loads(data)
                            # Modified March 9 : request_list holds a list of transactionIDs
                            if request_list is not None and request_list != []:
                                for req_txn in request_list:
                                    # if hashing.get_pub_key_hash(req['signer_public_key']) == peer_address:
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
        else:
            peer_verifier.serve_peer_requests()

    def serve_id_disable_requests(self, txn_id=None):

        """serve_id_disable_requests method serves pending
        incoming requests for ID invalidation confirmation """

        LOGGER.debug("Inside certifier_client.serve_id_disable_requests")
        # read the event db
        events_db = db.DB()
        try:
            events_db.open(self.events_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
            key = "digitalid/invalidate"
            request_list = events_db.get(key.encode())
            if request_list is not None:
                request_list = cbor.loads(request_list)
        except BaseException as err:
            LOGGER.error("Error while reading event db {}".format(err))
            raise Exception(err)

        if txn_id is not None:
            try:
                isSuccess = self.send_invalidation_ack(txn_id=txn_id)
                if isSuccess is True:
                    print("Successfully Processed")
                    if txn_id in request_list:
                        request_list.remove(txn_id)
                        LOGGER.debug(request_list)
                        events_db.put(key.encode(), cbor.dumps(request_list))
                        # events_db.close()
            except BaseException as err:
                print("Exception due to {}".format(err))
                # traceback.print_exc(sys.stderr)

            finally:
                LOGGER.debug("Inside finally")
                events_db.close()
        else:
            # events_db = db.DB()
            # try:
            # events_db.open(self.events_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
            # key = "digitalid/invalidate"
            # request_list = events_db.get(key.encode())
            # processed = []
            if request_list is not None and len(request_list) != 0:
                # request_events = cbor.loads(request_list)
                pending_list = request_list
                LOGGER.debug(request_list)
                for txn_id in request_list:
                    # address = request_event['address']
                    # txn_id = request_event['transaction_id']
                    # owner_address = request_event['sent_from']
                    resp = input("Process request in transaction {} ? Y/N: ".format(txn_id))
                    if resp.capitalize().strip() == 'Y':
                        try:
                            # isSuccess = self.send_invalidation_ack(owner_address=owner_address,
                            #                                        txn_id=txn_id)
                            isSuccess = self.send_invalidation_ack(txn_id=txn_id)
                            # TODO Handle cases where ack is intentionally not sent
                            if isSuccess is True:
                                # processed.append(request_event)
                                pending_list.remove(txn_id)
                                print("Successfully Processed")
                        # except InvalidTransaction:
                        except BaseException:
                            pending_list.remove(txn_id)
                            # events_db.put(key, cbor.dumps(pending_list))
                            # events_db.close()
                            print("Invalid Transaction - Removed Request from list")
                            continue
                    else:
                        LOGGER.debug("Request from {} skipped".format(txn_id))
                        continue
                    # request_list = [event for event in request_list if event not in processed]

                LOGGER.debug(pending_list)
                events_db.put(key.encode(), cbor.dumps(pending_list))
                events_db.close()
            else:
                print("No ID invalidation verification request pending")

            # except BaseException as err:
            #     LOGGER.error("Error while reading event db {}".format(err))
            #     raise Exception(err)
            # finally:
            #     LOGGER.debug("Inside finally")
            #     events_db.close()

    def send_invalidation_ack(self, txn_id):
        LOGGER.debug("Inside certifier_client.send_invalidation_ack()")

        # retrieve transaction requesting ID invalidation
        txn_response = chain_access_util.get_transaction(base_url=self.base_url, requesting_txn_id=txn_id)
        try:
            txn_header = txn_response['header']
            signer_pub_key_hex = txn_header['signer_public_key']

            # signer_pub_key = digital_id.id_owner_public_key
            owner_address = hashing.get_pub_key_hash(signer_pub_key_hex)
            txn_payload = txn_response['payload']
            digital_id_transaction = DigitalIdTransaction()
            digital_id_transaction.ParseFromString(base64.b64decode(txn_payload))
            owner_signature = digital_id_transaction.owner_signature
            # txn_status = digital_id_transaction.status
            owner_info = digital_id_transaction.owner_info

            # Commenting out: if txn_signer_address != owner_address:
            #                    print("Invalid owner address {} or invalid transaction ID {}".
            #                    format(owner_address, txn_id))
            #                    return False

        except BaseException as err:
            LOGGER.error("Error while reading transaction data {}".format(err))
            raise Exception("Error while reading transaction data")

        owner_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                            pub_key_hash=owner_address,
                                                            key=FAMILY_NAME_CERTIFIER)
        _state_data = chain_access_util.get_state(base_url=self.base_url, address=owner_state_address)
        try:
            invalidation_id_data = _state_data['invalidation_req']
            pending_address_list = _state_data['pending_acks']
            LOGGER.debug("pending_acks from state: {}".format(pending_address_list))
        except BaseException as err:
            LOGGER.error("Error while reading state data : {}".format(err))
            raise Exception("Error while reading state data")

        if self._public_address not in pending_address_list:
            LOGGER.error("Address {} not present in {}", self._public_address, pending_address_list)
            # raise Exception("The current learner not a valid recipient of the request")
            print("The current learner not a valid recipient of the request")
            return False

        if invalidation_id_data is None or invalidation_id_data is b'':
            LOGGER.error("Invalid Digital-ID state")
            raise Exception("Invalid Digital-ID state")

        # TODO debug Added Apr 11
        if digital_id_transaction.digital_id == invalidation_id_data:
            LOGGER.debug("Id data in digital_id_transaction and state matched")
        else:
            LOGGER.debug("Id data in digital_id_transaction and state did not match")

        # check status of the retrieved invalidation request
        disabled_digital_id = digital_id_pb2.DigitalId()
        disabled_digital_id.ParseFromString(invalidation_id_data)
        if disabled_digital_id.status != id_attribute_pb2.Status.INVALID:
            LOGGER.error("invalidation_req in state has non-permitted status of {}", disabled_digital_id.status)
            raise Exception("Invalidation request data in state not valid")

        # review request
        send_ack_resp = review_disable_req(disabled_digital_id, owner_address, txn_id)
        owner_self_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                                 pub_key_hash=owner_address,
                                                                 key='self')
        reply_addresses = [owner_state_address, owner_self_state_address]
        # send transaction to acknowledge disable request
        if send_ack_resp == 'Y':
            result = self._create_n_send_txn(action="ack_invalidation", to_address_list=reply_addresses,
                                             digital_id_msg=invalidation_id_data, dependency_txn_list=[txn_id],
                                             owner_signature=owner_signature, owner_info=owner_info)
        else:
            print('Request cancelled. Acknowledgement would not be sent.')
            return True

        LOGGER.debug(result)
        print(result)
        if result != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
            status = yaml.safe_load(result)['data'][0]['status']
            if status == 'COMMITTED':
                print("Acknowledgement successfully committed")
                return True
            elif status == 'UNKNOWN':
                print("Transaction status unknown")
                return True
            else:
                print("Failed to commit acknowledgement")
                return False
        else:
            return False

    def _create_n_send_txn(self, action, to_address_list, digital_id_msg, dependency_txn_list, owner_signature,
                           owner_info=None, from_address_list=None):

        LOGGER.debug("Inside certifier_client._create_n_send_txn()")
        # constructing the self_address where we'll store our state
        self_address = self._self_state_address
        input_address_list = []
        output_address_list = []
        if to_address_list is not None and len(to_address_list) != 0:
            output_address_list.extend(to_address_list)

        if from_address_list is not None and len(from_address_list) != 0:
            input_address_list.extend(from_address_list)
        else:
            input_address_list.extend(to_address_list)

        # TODO is self_address required?

        if action not in ["ack_invalidation", "ack_confirmation"]:
            input_address_list.extend([self_address])
            output_address_list.extend([self_address])

        # removing: payload = base64.b64encode(pii_credential_msg.SerializeToString())
        # set payload as digital_id_transaction message

        # ack_confirmation sends digital_id_bytes in the field pii_credential_msg
        if action in ["ack_confirmation", "ack_invalidation"]:
            digital_id_bytes = digital_id_msg
        else:
            digital_id_msg.enc_code_id = random.random().hex().encode()
            digital_id_bytes = digital_id_msg.SerializeToString()

        # TODO compress and encrypt with digital_id owner's public key
        # constructing object of DigitalIdTransaction
        digital_id_transaction = DigitalIdTransaction()
        digital_id_transaction.digital_id = digital_id_bytes

        # Apr 3, 2020: set the old owner signature which cannot be verified at this stage
        if owner_signature is not None:
            digital_id_transaction.owner_signature = owner_signature

        # Sign on the hash of the digital id.
        # Verifiable using the transaction signing public key in the certifier_tp
        digital_id_transaction.certifier_signature = self._signer.sign(hashing.get_hash_from_bytes(digital_id_bytes))

        if "issue_certificate" == action:
            LOGGER.debug("Sending Transaction for issue_certificate")
            digital_id_transaction.status = id_attribute_pb2.Status.ON_VERIFICATION
            # digital_id_transaction.verification_quorum = self._trust_score

        if "ack_confirmation" == action:
            LOGGER.debug("Sending Transaction for ack_confirmation")
            digital_id_transaction.status = id_attribute_pb2.Status.ACK_CONFIRMED

        if "ack_invalidation" == action:
            LOGGER.debug("Sending Transaction for ack_invalidation")
            digital_id_transaction.status = id_attribute_pb2.Status.INVALID_ACK

        if owner_info is not None:
            digital_id_transaction.owner_info.CopyFrom(owner_info)

        payload = digital_id_transaction.SerializeToString()

        if "ack_invalidation" == action:
            transaction = self.txn_generator.make_transaction(family=FAMILY_NAME_DIGITALID, payload=payload,
                                                              input_address_list=input_address_list,
                                                              output_address_list=output_address_list,
                                                              dependency_list=dependency_txn_list)
        else:
            transaction = self.txn_generator.make_transaction(family=FAMILY_NAME_CERTIFIER, payload=payload,
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

    def save_client_info(self):
        LOGGER.debug("Inside save_client_info")
        client_info_transaction = client_pb2.ClientInfoSetupTransaction()
        # client = client_pb2.ClientAttributes()
        # client.trust_score = digital_id_constants.MAX_CLIENT_TRUST_SCORE
        client_info_transaction.client_info.trust_score = digital_id_constants.MAX_CLIENT_TRUST_SCORE
        client_info_transaction.client_info.user_address = self._public_address
        payload = client_info_transaction.SerializeToString()
        input_address_list = [self._self_state_address]
        output_address_list = [self._self_state_address]
        transaction = self.txn_generator.make_transaction(family=FAMILY_CERTIFIER_CLIENT, payload=payload,
                                                          input_address_list=input_address_list,
                                                          output_address_list=output_address_list)
        transaction_list = [transaction]
        batch_list = self.txn_generator.make_batch(transaction_list)
        batch_id = batch_list.batches[0].header_signature

        # Send batch_list to the REST API
        response = self.txn_generator.send_to_rest_api("batches", batch_list.SerializeToString(),
                                                       'application/octet-stream')
        LOGGER.debug("Response from Rest-API {}".format(response))

        result = self.txn_generator.wait_for_status(batch_id, CertifierWalletClient.wait_time, response)
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

    def do_request_id_share(self, to_address, data_mode=False):
        LOGGER.debug("Inside do_request_id_share()")

        # TODO take OTP as input and send it to the class to form the output address
        sharing_obj = DigitalIdSharingClass(base_url=self.base_url,
                                            signer=self._signer,
                                            public_key=self.public_key,
                                            to_address=to_address)
        contract_msg = None
        LOGGER.debug("data_mode {}".format(data_mode))
        if data_mode:
            contract_msg = _build_contract()
        sharing_obj.send_id_request(data_mode=data_mode, contract_msg=contract_msg)

    def show_share_response(self, receiver_address, resp_txn):
        txn_response = chain_access_util.get_transaction(base_url=self.base_url, requesting_txn_id=resp_txn)
        sharing_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_SHAREDID,
                                                              pub_key_hash=receiver_address,
                                                              key=self._public_address)
        try:
            txn_header = txn_response['header']
            # id_owner_pub_key = txn_header['signer_public_key']
            txn_to_address_list = txn_header['outputs']
            LOGGER.debug("sharing_state_address {}".format(sharing_state_address))
            if sharing_state_address not in txn_to_address_list:
                print("Invalid share response transaction for address {}".format(receiver_address))
                return False

            txn_payload = txn_response['payload']
            shared_id_transaction = shared_id_pb2.ShareIDTransaction()
            shared_id_transaction.ParseFromString(base64.b64decode(txn_payload))
            action = shared_id_transaction.action
            if action != digital_id_constants.SHARE_ID_RESPONSE:
                print("Invalid Transaction action For ID Share Response.")
                return False
        except BaseException as err:
            LOGGER.error("Error while reading transaction data {}".format(err))
            raise Exception("Error while reading transaction data")
        share_state_data = chain_access_util.get_state(base_url=self.base_url, address=sharing_state_address)
        if share_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            print("State {} does not exist".format(sharing_state_address))
            return False
        else:
            id_confirmation_txn = share_state_data['id_confirmation_txn']
            print("id_confirmation_txn : {}".format(id_confirmation_txn))
            txn_response = chain_access_util.get_transaction(base_url=self.base_url, requesting_txn_id=id_confirmation_txn)
            try:
                txn_payload = txn_response['payload']
                digital_id_transaction = DigitalIdTransaction()
                digital_id_transaction.ParseFromString(base64.b64decode(txn_payload))
                txn_status = digital_id_transaction.status
                print("\nShared transaction ID {}".format(id_confirmation_txn))
                print("\nTransaction status {}".format(STATUS_ENUM.get(txn_status)))
                id_owner_info = digital_id_transaction.owner_info
                print("\nClient address {}".format(id_owner_info.user_address))
                print("\nClient trust_score {}".format(id_owner_info.trust_score))
                digital_id_bytes = digital_id_transaction.digital_id
                digital_id_msg = digital_id_pb2.DigitalId()
                digital_id_msg.ParseFromString(digital_id_bytes)
                print("\nSaved ID : \n")
                _display_id(digital_id_msg=digital_id_msg)
            except BaseException as err:
                LOGGER.error("Error while reading transaction data {}".format(err))
                raise Exception("Error while reading transaction data")

    # def get_symmetric_key(self, id_owner_public_key):
    #     priv_bytes = self._private_key.as_bytes()
    #     public_key = Secp256k1PublicKey.from_hex(id_owner_public_key)
    #     pub_key_instance = public_key.secp256k1_public_key
    #     symm_key = pub_key_instance.tweak_mul(priv_bytes)
    #     return symm_key
