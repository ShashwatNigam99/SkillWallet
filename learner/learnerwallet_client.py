#!/usr/bin/env python3

"""This class contains code for creating learner wallet and creating and submitting transactions by interfacing with
sawtooth through the REST API. It accepts input from a _client CLI interface.
"""
import json
import logging
import os
import random
import shutil
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
from protobuf import id_attribute_pb2, digital_id_pb2
from protobuf.digital_id_transaction_pb2 import DigitalIdTransaction
from protobuf.client_pb2 import ClientAttributes
from util import hashing, chain_access_util
from constants import digital_id_constants
from util.transaction_generator import TransactionGenerator

# The transaction family name


FAMILY_NAME_LEARNER = 'learner'
FAMILY_NAME_CERTIFY = "certifier"
DEFAULT_KEY_FILE_NAME = 'skill_wallet'
FAMILY_NAME_CLIENT = 'client_info'
# FAMILY_NAME_SHAREDID = 'shared_id'

# LOGGER = logging.getLogger(__name__)
LOGGER = logging.getLogger("learnerwallet.client")
# LOGGER.setLevel(logging.INFO)
LEARNER_DB_FILE = 'learner_wallet_db'
EVENTS_DB_FILE = 'learner_events_db'
REGISTRY_DB_FILE = 'user_registry_db'
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


def _get_id_from_state(state_data):
    LOGGER.debug("Inside learnerwallet_client._get_id_from_state()")
    pii_credential_msg = None
    if state_data is not None:
        id_data = state_data['pii_credential']
        pii_credential_msg = digital_id_pb2.PII_credential()
        pii_credential_msg.ParseFromString(id_data)
        LOGGER.debug("ID data: {}".format(pii_credential_msg))
    return pii_credential_msg


def print_file(file_path):
    try:
        with open(file_path) as fd:
            for line in fd:
                line = line.strip()
                if line.startswith('#') or line == '':
                    continue
                print(line)
    except OSError as err:
        print('Failed to read file {}: {}'.format(file_path, str(err)))


def _get_encoded_hash(field_name, val, code_dict):
    LOGGER.debug("inside _get_encoded_hash")
    r = os.urandom(32)
    r_i = int.from_bytes(r, 'big')
    print("encoding code: {}".format(r_i))
    LOGGER.debug("encoding code: {}".format(r_i))
    code_dict[field_name] = r_i
    encoded_val = hashing.get_encoding(val.lower(), r)
    return encoded_val


def _display_id(pii_credential_msg):
    status = pii_credential_msg.status
    print("ID processing status: {}".format(STATUS_ENUM[status]))
    # Retrieve the fields of attribute_set_msg using listField
    # print overall status
    attribute_set_msg = pii_credential_msg.attribute_set
    attribute_fields = attribute_set_msg.ListFields()
    is_success = True

    for attribute_field in attribute_fields:
        if attribute_field[0].name != 'others':
            field_name = attribute_field[0].name
            field_value = attribute_field[1]
            value_attr_data = field_value.attribute_data_enc
            attribute_struct = id_attribute_pb2.AttributeData()
            attribute_struct.ParseFromString(value_attr_data)
            print("\nDetails of field {}: \n".format(field_name.capitalize()))
            print("Status: {}".format(STATUS_ENUM[field_value.status]))
            # --old code --print("Value: {}".format(attribute_struct.value.decode('utf-8').capitalize()))
            print("Value: {}".format(attribute_struct.value))
            print("Issuer's public key: {}".format(str(attribute_struct.signer_pub_key)))
            print("Issue Timestamp: {}".format(str(attribute_struct.sign_timestamp)))
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
                # --old-- print("Value: {}".format(str(attribute_struct.value.decode('utf-8').capitalize())))
                print("Value: {}".format(str(attribute_struct.value)))
                print("Issuer's public key: {}".format(str(attribute_struct.signer_pub_key)))
                print("Issue Timestamp: {}".format(str(attribute_struct.sign_timestamp)))
    return is_success


def _display(state_data):
    LOGGER.debug("Inside userwallet_client._display()")
    pii_credential_msg = _get_id_from_state(state_data)
    if pii_credential_msg is not None:
        _display_id(pii_credential_msg)


class LearnerWalletClient(object):
    """ Client User Wallet class """
    wait_time = 100

    def __init__(self, base_url, command, key_file_name=DEFAULT_KEY_FILE_NAME):

        """Initialize the _client class, get the key pair and compute the address. """
        LOGGER.debug("Inside LearnerWalletClient.__init__")
        self.base_url = base_url
        self._key_file = _get_private_key_file(key_file_name)
        self.command = command
        pwd = os.path.expanduser(".")
        user_dir = os.path.join(pwd, key_file_name)
        self.code_file = '{}/{}'.format(user_dir, digital_id_constants.CODE_FILE_NAME)
        try:
            with open(self._key_file) as fd:
                private_key_str = fd.read().strip()
        except OSError as err:
            raise Exception('Failed to read private key {}: {}'.format(self._key_file, str(err)))

        try:
            self._private_key = Secp256k1PrivateKey.from_hex(private_key_str)
        except ParseError as err:
            raise Exception('Failed to load private key:{}'.format(str(err)))

        self._signer = CryptoFactory(create_context('secp256k1')).new_signer(self._private_key)
        self.public_key = self._signer.get_public_key().as_hex()
        self.public_address = hashing.get_pub_key_hash(self.public_key)
        LOGGER.debug("Public key hash : {}".format(self.public_address))
        print("\nPublic Key of key profile {} : {}".format(key_file_name, self.public_key))
        print("\nBlockchain address of key profile {} : {}".format(key_file_name, self.public_address))
        self._self_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_LEARNER,
                                                                 key='self',
                                                                 pub_key_hash=self.public_address)

        self._id_creation_state = None
        self._digital_id_msg = None
        self._last_acting_txn_id = ""
        self._enable_register = None
        self._enable_skill_register = None
        self._id_status = id_attribute_pb2.Status.DEFAULT
        self.txn_generator = TransactionGenerator(base_url=self.base_url, public_key=self.public_key,
                                                  signer=self._signer)
        self.user_dir = os.path.join(os.getcwd(), key_file_name)
        if os.path.isdir(self.user_dir) is False:
            os.mkdir(key_file_name)
        self.events_db_file = os.path.join(self.user_dir, EVENTS_DB_FILE)
        self.learner_db_file = os.path.join(self.user_dir, LEARNER_DB_FILE)
        self.registry_db_file = os.path.join(pwd, 'shared', REGISTRY_DB_FILE)

        # if the flags exist in the db read and initialize from the db

        learner_wallet_db = db.DB()
        learner_wallet_db.open(self.learner_db_file, None, db.DB_HASH, db.DB_CREATE)
        state_info_bin = learner_wallet_db.get('state_info'.encode())

        if state_info_bin is not None:
            LOGGER.debug("From user_wallet_db -> read self.state_info_dict: ")
            self.state_info_dict = cbor.loads(state_info_bin)
            LOGGER.debug(self.state_info_dict)
        else:
            LOGGER.debug("No key 'state_info' exist in user_wallet_db")
            LOGGER.debug("Initializing state_info_dict")
            # initialize state_info of object
            self.state_info_dict = {
                "enable_register": False,
                "enable_skill_register": False,
                "validation_req_sent": False,
            }

        learner_wallet_db.close()
        self._refresh_state()

    def load_id_status(self):
        """This method gets the latest ID status from the corresponding state"""

        LOGGER.debug("inside LearnerWalletClient.load_id_status")
        state_response = chain_access_util.get_state(self.base_url, self._self_state_address)
        if state_response == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            self._id_creation_state = digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE
            self._enable_register = True
            self._enable_skill_register = False
        else:  # data
            self._id_creation_state = state_response

        LOGGER.debug("_id_creation_state {}".format(self._id_creation_state))
        if self._enable_register is True:
            self.register_pii()
            self._enable_register = False  # TODO

        LOGGER.debug("enable_request: {}".format(self.state_info_dict['enable_request']))

    def register_pii(self):
        LOGGER.debug("inside LearnerWalletClient.register_pii")
        if self.command == 'skill_wallet' and self.refresh_exit:
            self._refresh_state()
        if self.state_info_dict['enable_register'] is True:
            try:
                print("\nCreating register_id transaction...\n")
                result = self._send_digital_id_txn(action="register_pii")
            except InvalidTransaction as err:
                print("Received InvalidTransaction exception {}".format(err))
                return False
            LOGGER.debug(result)
            print(result)
            if result != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
                status = yaml.safe_load(result)['data'][0]['status']
                if status == 'COMMITTED':
                    print("Request successfully submitted")
                    self.state_info_dict['enable_register'] = False
                    self.state_info_dict['enable_register_skill'] = True
                    user_wallet_db = db.DB()
                    user_wallet_db.open(self.learner_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
                    user_wallet_db.put('state_info'.encode(), cbor.dumps(self.state_info_dict))
                    user_wallet_db.close()
                    return True
                elif status == 'UNKNOWN':
                    print("Transaction status unknown")
                    return True
                else:
                    print("Failed to commit request")
                    return False
            else:
                return False

    def register_skill(self):
        LOGGER.debug("inside LearnerWalletClient.register_skill")
        if self.command == 'id_wallet' and self.refresh_exit:
            self._refresh_state()
        if self.state_info_dict['enable_skill_register'] is True:
            try:
                print("\nCreating register_skill transaction...\n")
                result = self._send_digital_id_txn(action="register_skill")
            except InvalidTransaction as err:
                print("Received InvalidTransaction exception {}".format(err))
                return False
            LOGGER.debug(result)
            print(result)
            if result != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
                status = yaml.safe_load(result)['data'][0]['status']
                if status == 'COMMITTED':
                    print("Request successfully submitted")
                    return True
                elif status == 'UNKNOWN':
                    print("Transaction status unknown")
                    return True
                else:
                    print("Failed to commit request")
                    return False
            else:
                return False

    def display_id(self):
        LOGGER.debug("inside LearnerWalletClient.display_id")
        if self.command == 'skill_wallet' and self.refresh_exit:
            self._refresh_state()
        # get the state and display details in console
        state_resp = chain_access_util.get_state(self.base_url, self._self_state_address)
        # Checking if state was found
        if state_resp != digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            _display(state_resp)
        else:
            print("ID not found")
        return


    def _send_digital_id_txn(self, action, owner_info=None):
        LOGGER.debug("inside LearnerWalletClient._send_digital_id_txn")
        # Generate payload as digital_id protobuf encoded string
        digital_id_transaction = DigitalIdTransaction()

        input_address_list = []
        output_address_list = []
        dependency_list = []

        # set client_info
        client_info = ClientAttributes()
        if owner_info is not None:
            client_info.CopyFrom(owner_info)
        else:
            client_info.user_address = self.public_address
            # client_info.family_name = FAMILY_NAME_LEARNER

        if "register_pii" == action:
            pii_msg = digital_id_pb2.PII_credential()
            resp = input("Press 'Y' to include additional attributes. To ignore, press any other key: ")
            if resp.capitalize().strip() == 'Y':
                attr_list = input("Please enter additional attribute list : ")
                attr_list = attr_list.split(',')
                others_map = pii_msg.attribute_set.others
                for attr in attr_list:
                    LOGGER.debug("Initializing {} ".format(attr.strip()))
                    others_map.get_or_create(attr.strip())
                    attr_value = others_map[attr.strip()]
                    attr_value.status = id_attribute_pb2.REGISTERED
            print("Please fill the following detail: ")
            self._set_user_id(pii_msg.attribute_set)
            pii_msg.status = id_attribute_pb2.REGISTERED
            pii_msg.id_owner_public_key = self.public_key
            pii_msg.enc_code_id = random.random().hex().encode()

            digital_id_bytes = pii_msg.SerializeToString()
            digital_id_transaction.status = id_attribute_pb2.PII_REGISTERED
            digital_id_transaction.owner_info.CopyFrom(client_info)

            digital_id_transaction.digital_id = digital_id_bytes
            digital_id_transaction.owner_signature = self._signer.sign(hashing.get_hash_from_bytes(digital_id_bytes))

            input_address_list.append(self._self_state_address)
            output_address_list.append(self._self_state_address)

        if "register_skill" == action:
            learning_cred = digital_id_pb2.learning_credential()
            print("Please input the following details: ")
            self._set_learning_credentials(learning_cred.course_attribute_set)
            certifier_address = input("Please enter course provider's skill-wallet address: ")
            shared_certifier_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_LEARNER,
                                                                     key=certifier_address,
                                                                     pub_key_hash=self.public_address)
            learning_cred.id_owner_public_key = self.public_key
            learning_cred.enc_code_id = random.random().hex().encode()

            digital_id_bytes = learning_cred.SerializeToString()
            digital_id_transaction.status = id_attribute_pb2.SKILL_REGISTERED
            digital_id_transaction.owner_info.CopyFrom(client_info)

            digital_id_transaction.digital_id = digital_id_bytes
            digital_id_transaction.owner_signature = self._signer.sign(hashing.get_hash_from_bytes(digital_id_bytes))
            digital_id_transaction.receiver_address = certifier_address
            input_address_list.append(self._self_state_address)
            output_address_list.append(shared_certifier_address)

        # if dependency_txns is not None:
        #     dependency_list.extend(dependency_txns)
        # elif self._last_acting_txn_id is not "":
        #     dependency_list.append(self._last_acting_txn_id)

        payload = digital_id_transaction.SerializeToString()
        transaction = self.txn_generator.make_transaction(family=FAMILY_NAME_LEARNER, payload=payload,
                                                          input_address_list=input_address_list,
                                                          output_address_list=output_address_list,
                                                          dependency_list=dependency_list)
        transaction_list = [transaction]
        batch_list = self.txn_generator.make_batch(transaction_list)
        batch_id = batch_list.batches[0].header_signature

        # Send batch_list to the REST API
        result = self.txn_generator.send_to_rest_api("batches", batch_list.SerializeToString(),
                                                     'application/octet-stream')
        LOGGER.debug("Result from Rest-API {}".format(result))

        return self.txn_generator.wait_for_status(batch_id, LearnerWalletClient.wait_time, result)

    def _refresh_state(self):
        LOGGER.debug("Inside learnerwallet_client._refresh_state()")
        print("\n--Refreshing State--\n")
        self.refresh_exit = False

        self.load_id_status()

        user_wallet_db = db.DB()
        user_wallet_db.open(self.learner_db_file, None, db.DB_HASH, db.DB_CREATE)
        self.state_info_dict['enable_skill_register'] = self._enable_skill_register
        self.state_info_dict['enable_register'] = self._enable_register
        user_wallet_db.put('state_info'.encode(), cbor.dumps(self.state_info_dict))
        user_wallet_db.close()
        self.refresh_exit = True


    def _set_learning_credentials(self, course_attribute_set):
        LOGGER.debug("inside _set_learning_credentials")
        code_dict = {}

        # Take course details as input from user
        course_details_struct = id_attribute_pb2.CourseDetails()
        print("Please enter the following details: \n")

        course_details_struct.enc_code = random.random().hex().encode()

        val = input("{}: ".format('course_ID: '))
        val = val.strip()
        course_details_struct.course_ID = val.lower().encode('utf-8')

        course_provider_name = input("{}: ".format('course provider name: '))
        course_provider_name = course_provider_name.strip()
        course_details_struct.course_provider_name = course_provider_name.lower().encode('utf-8')

        course_name_val = input("{}: ".format('course name: '))
        course_name_val = course_name_val.strip()
        course_details_struct.course_name = course_name_val.lower().encode('utf-8')

        val = input("{}: ".format('course description: '))
        val = val.strip()
        course_details_struct.course_description = val.lower().encode('utf-8')

        val = input("{}: ".format('course start date: '))
        val = val.strip()
        course_details_struct.course_start_date = val.lower().encode('utf-8')

        val = input("{}: ".format('course finish date: '))
        val = val.strip()
        course_details_struct.course_finish_date = val.lower().encode('utf-8')

        val = input("{}: ".format('content creators: '))
        val = val.strip()
        course_details_struct.content_creator_list = val.lower().encode('utf-8')

        val = input("{}: ".format('score: '))
        val = val.strip()
        course_details_struct.score = val.lower().encode('utf-8')

        val = input("{}: ".format('course_cert_hash: '))
        val = val.strip()
        course_details_struct.course_cert_hash = val.lower().encode('utf-8')

        course_key = course_name_val.lower() + '_' + course_provider_name.lower()

        # populate course data
        course_attribute_set.get_or_create(course_key)
        course_data = course_attribute_set[course_key]
        course_data.course_details = course_details_struct.SerializeToString()
        course_data.status = id_attribute_pb2.SKILL_REGISTERED

    def _set_user_id(self, id_attribute_set):
        LOGGER.debug("inside _set_user_id")
        code_dict = {}
        id_attribute_set.name.status = id_attribute_pb2.REGISTERED
        id_attribute_set.date_of_birth.status = id_attribute_pb2.REGISTERED
        id_attribute_set.address_permanent.status = id_attribute_pb2.REGISTERED
        id_attribute_set.nationality.status = id_attribute_pb2.REGISTERED
        id_attribute_set.gender.status = id_attribute_pb2.REGISTERED
        id_attribute_set.email.status = id_attribute_pb2.REGISTERED
        id_attribute_set.phone.status = id_attribute_pb2.REGISTERED
        attribute_fields = id_attribute_set.ListFields()
        for attribute_field in attribute_fields:
            field_name = attribute_field[0].name
            if field_name != 'others':
                print("\nfield_name: {}".format(field_name))
                LOGGER.debug("field_name: {}".format(field_name))
                field_value = attribute_field[1]
                r = os.urandom(32)  # random code to append with data bytes
                r_i = int.from_bytes(r, 'big')
                print("encoding code: {}".format(r_i))
                LOGGER.debug("encoding code: {}".format(r))
                code_dict[field_name] = r_i
                field_value.status = id_attribute_pb2.REGISTERED
                val = input("{}: ".format(field_name))
                attribute_data = id_attribute_pb2.AttributeData()
                attribute_data.value = hashing.get_encoding(val.lower(), r)
                field_value.attribute_data_enc = attribute_data.SerializeToString()
            elif field_name == 'others':
                others_map = attribute_field[1]
                for field_name in others_map:
                    print("\nfield_name: {}".format(field_name))
                    LOGGER.debug("field_name: {}".format(field_name))
                    field_value = others_map[field_name]
                    r = os.urandom(32)
                    r_i = int.from_bytes(r, 'big')
                    print("encoding code: {}".format(r_i))
                    LOGGER.debug("encoding code: {}".format(r_i))
                    code_dict[field_name] = r_i
                    field_value.status = id_attribute_pb2.REGISTERED
                    val = input("{}: ".format(field_name))
                    attribute_data = id_attribute_pb2.AttributeData()
                    attribute_data.value = hashing.get_encoding(val.lower(), r)
                    field_value.attribute_data_enc = attribute_data.SerializeToString()

        serialized_code = json.dumps(code_dict)
        LOGGER.debug("serialized_code {}".format(serialized_code))
        file_handle = open(self.code_file, "w+")
        file_handle.write(serialized_code)
        file_handle.close()

    def print_code_file(self):
        file_handle = open(self.code_file, "r+")
        code_str = file_handle.readline()
        code_dict = json.loads(code_str)
        for key in code_dict:
            print("{}: {}\n".format(key, code_dict[key]))

    def generate_dec_key(self, recvr_public_key, code_file_path):
        # TODO
        # if code_file_path is None:
        #     code_str = input("Please enter the code string: ")
        # else:
        code_file_path = '{}/{}'.format(self.user_dir, code_file_path)
        LOGGER.debug("code_file_path {}".format(code_file_path))
        file_handle = open(code_file_path, "r+")
        code_str = file_handle.readline()
        LOGGER.debug("code_str {}".format(code_str))
        code_dict = json.loads(code_str)
        print("Generating shareable keys for {}".format(recvr_public_key))
        dec_key_dict = {}
        for key in code_dict:
            print("{}: {}\n".format(key, code_dict.get(key)))
            private_key_bytes = self._private_key.as_bytes()
            symm_key = hashing.get_symmetric_key(private_key_bytes, recvr_public_key)
            dec_key_bytes = hashing.gen_decode_key(symm_key=symm_key, code=code_dict.get(key))
            print("Generated key for attribute {}: {}".format(key, dec_key_bytes))
            dec_key_dict[key] = dec_key_bytes

        serialized_dec_key_dict = json.dumps(dec_key_dict)
        LOGGER.debug("serialized dec_key_dict {}".format(serialized_dec_key_dict))
        dec_code_file = '{}/{}'.format(self.user_dir, str(hashing.get_pub_key_hash(recvr_public_key)))
        file_handle = open(dec_code_file, "w+")
        file_handle.write(serialized_dec_key_dict)
        file_handle.close()

    def share_code_file(self):
        LOGGER.debug("inside share_code_file")
        pwd = os.path.expanduser(".")
        receiver_address = input("Please enter receiver's blockchain address: ")
        receiving_dir = os.path.join(pwd, "shared", receiver_address)
        if not os.path.isdir(s=receiving_dir):
            LOGGER.debug("location {} does not exist.\n".format(receiving_dir))
            os.mkdir(receiving_dir)
        shared_file_path = '{}/{}'.format(receiving_dir,
                                          self.public_address + "_" + digital_id_constants.CODE_FILE_NAME)
        share_path = shutil.copy(self.code_file, shared_file_path)
        LOGGER.debug("Path of copied file: {}".format(share_path))
        print("Path of copied file: {}".format(share_path))
        return
