#!/usr/bin/env python3

"""This class contains code for creating learner wallet and creating and submitting transactions by interfacing with
sawtooth through the REST API. It accepts input from a _client CLI interface.
"""
import base64
import logging
import math
import os
import random
import sys
import time
import traceback
from datetime import datetime
from sys import path

import cbor
import yaml
from bsddb3 import db
from bsddb3._pybsddb import DBNoSuchFileError
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_signing import CryptoFactory
from sawtooth_signing import ParseError
from sawtooth_signing import create_context
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey

path.append(os.getcwd())
from protobuf import id_attribute_pb2, peer_verification_pb2, digital_id_pb2, client_pb2, shared_id_pb2
from protobuf.digital_id_transaction_pb2 import DigitalIdTransaction
from protobuf.client_pb2 import ClientAttributes
from util import hashing, chain_access_util
from constants import digital_id_constants
from learner import peer_verification_module
from util.transaction_generator import TransactionGenerator
from learner.id_share_module import DigitalIdSharingClass

# The transaction family name


FAMILY_NAME_DIGITALID = 'digitalid'  # 2122d3
FAMILY_NAME_PEER_VERIFY = 'peer_verification'
FAMILY_NAME_CERTIFY = "digitalid_certifier"
DEFAULT_KEY_FILE_NAME = 'digitalid'
FAMILY_NAME_DIGITALID_CLIENT = 'digitalid_client_info'
FAMILY_NAME_SHAREDID = 'shared_id'

# LOGGER = logging.getLogger(__name__)
LOGGER = logging.getLogger("userwallet.client")
# LOGGER.setLevel(logging.INFO)
USER_DB_FILE = 'user_wallet_db'
EVENTS_DB_FILE = 'user_events_db'
REGISTRY_DB_FILE = 'user_registry_db'
STATUS_ENUM = {0: 'DEFAULT',
               1: 'REQUESTED',
               2: 'ON_VERIFICATION',
               3: 'ON_UPDATE',
               4: 'CONFIRMED',
               5: 'EXPIRED',
               6: 'ACK_CONFIRMED',
               7: 'INVALID',
               8: 'INVALID_ACK',
               9: 'RECOVERY_REQ'}
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
    LOGGER.debug("Inside userwallet_client._get_id_from_state()")
    digital_id_msg = None
    if state_data is not None:
        id_data = state_data['digital_id']
        # TODO decrypt and de-compress _state_data
        digital_id_msg = digital_id_pb2.DigitalId()
        digital_id_msg.ParseFromString(id_data)
        LOGGER.debug("ID data: {}".format(digital_id_msg))
    return digital_id_msg


def _display_id(digital_id_msg):
    status = digital_id_msg.status
    valid_years = digital_id_msg.validity_in_years
    print("ID processing status: {}".format(STATUS_ENUM[status]))
    print("ID valid for : {} years from issuance".format(valid_years))
    # Retrieve the fields of attribute_set_msg using listField
    # print overall status
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
            print("Value: {}".format(attribute_struct.value.decode('utf-8').capitalize()))
            print("Issuer's public key: {}".format(str(attribute_struct.signer_pub_key)))
            print("Issue Timestamp: {}".format(str(attribute_struct.sign_timestamp)))
            # print("Validity: {}".format(str(attribute_struct.valid_till)))
            # print("Verification quorum: {}".format(str(field_value.verification_quorum)))
            # Added credibility_strength to represent score gathered from peer verification
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
                print("Value: {}".format(str(attribute_struct.value.decode('utf-8').capitalize())))
                print("Issuer's public key: {}".format(str(attribute_struct.signer_pub_key)))
                print("Issue Timestamp: {}".format(str(attribute_struct.sign_timestamp)))
                # print("Validity: {}".format(str(attribute_struct.valid_till)))
                # print("Verification quorum: {}".format(str(field_value.verification_quorum)))
                # Added credibility_strength to represent score gathered from peer verification
                print("Credibility score: {}".format(str(field_value.credibility_strength)))
                client_info = client_pb2.ClientAttributes()
                verifier_list = []
                for verifier in field_value.verifier_list:
                    client_info.ParseFromString(verifier)
                    verifier_info = client_info.user_address + " (" + \
                                    FAMILY_ENUM[client_info.family_name] + ")"
                    verifier_list.append(verifier_info)
                print("Verifier list: {}".format(verifier_list))


def _display(state_data):
    LOGGER.debug("Inside userwallet_client._display()")
    digital_id_msg = _get_id_from_state(state_data)
    if digital_id_msg is not None:
        _display_id(digital_id_msg)


def _build_contract():
    LOGGER.debug("Inside userwallet_client._build_contract()")
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


# def _confirm_digital_id(digital_id_msg, peer_verification_quorums, user_trust_score, verification_dict):
def _confirm_digital_id(digital_id_msg, peer_verification_quorums, verification_dict):
    LOGGER.debug("Inside userwallet_client._confirm_digital_id()")
    # new_id = digital_id_pb2.DigitalId()
    # new_id.CopyFrom(digital_id_msg)
    digital_id_msg.status = id_attribute_pb2.Status.CONFIRMED
    attribute_set_msg = digital_id_msg.attribute_set
    attribute_fields = attribute_set_msg.ListFields()

    for attribute_field in attribute_fields:
        field_name = attribute_field[0].name
        if field_name != 'others':
            if attribute_field[1].status == id_attribute_pb2.Status.ON_VERIFICATION:
                attribute_field[1].status = id_attribute_pb2.Status.CONFIRMED
                LOGGER.debug("Attribute {} is confirmed".format(attribute_field[0].name))
                # peer_verification_quorums = self._attribute_quorum_dict
                # quorum = attribute_field[1].verification_quorum \
                #          + peer_verification_quorums[attribute_field[0].name] \
                #          + user_trust_score
                # attribute_field[1].verification_quorum = quorum
                # TODO setting credibility_strength
                attribute_field[1].credibility_strength = peer_verification_quorums[field_name]
                # TODO set verifier_list per attribute
                if verification_dict.get(field_name) is not None:
                    attribute_field[1].verifier_list.extend(verification_dict.get(field_name))

        elif field_name == 'others':
            attr_map = attribute_field[1]
            for field_name in attr_map:
                field_value = attr_map[field_name]
                LOGGER.debug("Setting field in dictionary 'others': %s", field_name)
                if field_value.status == id_attribute_pb2.Status.ON_VERIFICATION:
                    field_value.status = id_attribute_pb2.Status.CONFIRMED
                    LOGGER.debug("Attribute {} is confirmed".format(field_name))
                    # quorum = field_value.verification_quorum \
                    #          + peer_verification_quorums[field_name] \
                    #          + user_trust_score
                    # field_value.verification_quorum = quorum
                    # TODO setting credibility_strength
                    field_value.credibility_strength = peer_verification_quorums[field_name]
                    # TODO set verifier_list per attribute
                    if verification_dict.get(field_name) is not None:
                        field_value.verifier_list.extend(verification_dict.get(field_name))

                LOGGER.debug('{} : {}'.format(field_value, attr_map[field_name]))


def _invalidate_digital_id(digital_id_msg):
    LOGGER.debug("Inside userwallet_client._invalidate_digital_id()")
    digital_id_msg.status = id_attribute_pb2.Status.INVALID
    attribute_set_msg = digital_id_msg.attribute_set
    attribute_fields = attribute_set_msg.ListFields()

    for attribute_field in attribute_fields:
        field_name = attribute_field[0].name
        if field_name != 'others':
            attribute_field[1].status = id_attribute_pb2.Status.INVALID
            LOGGER.debug("Attribute {} is invalidated".format(field_name))

        elif field_name == 'others':
            attr_map = attribute_field[1]
            for field_name in attr_map:
                field_value = attr_map[field_name]
                LOGGER.debug("Setting field in dictionary 'others': %s", field_name)
                field_value.status = id_attribute_pb2.Status.INVALID
                LOGGER.debug("Attribute {} is invalidated".format(field_name))


def set_id_for_peer_verify(digital_id_msg, attribute_req_list=None):  # attribute_del_list=None):
    LOGGER.debug("Inside userwallet_client.set_id_for_peer_verify()")
    new_id = digital_id_pb2.DigitalId()
    new_id.CopyFrom(digital_id_msg)
    # LOGGER.debug("attribute_del_list {}".format(attribute_del_list))
    LOGGER.debug("attribute_req_list {}".format(attribute_req_list))
    # if attribute_del_list is not None and attribute_del_list != []:
    #     for attr in attribute_del_list:
    #         attr = attr.strip()
    #         try:
    #             if new_id.attribute_set.HasField(attr):
    #                 new_id.attribute_set.ClearField(attr)
    #         except ValueError:
    #             if new_id.attribute_set.others.get(attr) is not None:
    #                 # attr_val = new_id.attribute_set.others.get(attr)
    #                 LOGGER.debug("Removing 'others' attribute {}".format(attr))
    #                 del new_id.attribute_set.others[attr]

    attribute_fields = new_id.attribute_set.ListFields()
    map_del_list = []
    for attribute_field in attribute_fields:
        field_name = attribute_field[0].name
        if field_name != 'others':
            if field_name in attribute_req_list:
                field_value = attribute_field[1]
                field_value.status = id_attribute_pb2.Status.REQUESTED
                LOGGER.debug("Setting field: %s", field_name)
            else:
                new_id.attribute_set.ClearField(field_name)

        elif field_name == 'others':
            attr_map = attribute_field[1]
            for field_name in attr_map:
                if field_name in attribute_req_list:
                    field_value = attr_map[field_name]
                    LOGGER.debug("Setting field in map 'others': %s", field_name)
                    LOGGER.debug(field_value)
                    field_value.status = id_attribute_pb2.Status.REQUESTED
                else:
                    # LOGGER.debug("Removing 'others' attribute {}".format(field_name))
                    map_del_list.append(field_name)

    LOGGER.debug("map_del_list {}".format(map_del_list))
    for key in map_del_list:
        LOGGER.debug("Removing 'others' attribute {}".format(key))
        del new_id.attribute_set.others[key]

    return new_id


def _get_certification_address_prefix():
    """
    Return the namespace prefix of a digital id transactor from the digitalid TF.

    The address is the first 6 hex characters from the hash SHA-512(TF name),
    plus the FAMILY_NAME_CERTIFY.
    """
    return str(hashing.hash512(FAMILY_NAME_DIGITALID.encode('utf-8'))[0:6] +
               hashing.hash512((FAMILY_NAME_CERTIFY.encode('utf-8'))[0:24]))


def _get_peer_verification_address_prefix():
    """
    Return the namespace prefix of peer-verification TF.

    The address is the first 6 hex characters from the hash SHA-512(TF name),

    """
    return str(hashing.hash512(FAMILY_NAME_PEER_VERIFY.encode('utf-8'))[0:6])


def select_peers(peer_dictionary, is_trust_based=True, is_vote_based=True):
    """selects peers for an ID attribute verification.
    called for each attribute present in the ID"""

    LOGGER.debug("Inside select_peers()")
    selected_peers = []
    total_score = 0
    peer_dict = dict.copy(peer_dictionary)
    while 1:

        print('\npeer list: {}'.format(peer_dict))
        if is_trust_based is True:

            selected_keys_str = input('\nSelect peers based on trust scores [min peer count {}, max peer count {}] '
                                      'from peer list by entering keys: '
                                      .format(digital_id_constants.MIN_PEER_COUNT,
                                              digital_id_constants.MAX_PEER_COUNT))
        else:
            selected_keys_str = input('\nSelect peers [max peer count {}] '
                                      'from peer list by entering keys: '
                                      .format(digital_id_constants.MAX_PEER_COUNT))
        selected_keys = selected_keys_str.split(',')
        # min_quorum = MIN_PEER_COUNT * MAX_AVG_TRUST_SCORE
        total_peer = len(selected_keys) + len(selected_peers)

        # if is_vote_based:
        # if is_trust_based and total_peer < digital_id_constants.MIN_PEER_COUNT:
        if is_vote_based is True and total_peer < digital_id_constants.MIN_PEER_COUNT:
            print(
                "\nInput Error: Minimum peer requirement of {} peers has not reached\n"
                    .format(digital_id_constants.MIN_PEER_COUNT))
            continue
            # Not using below logic for ID invalidation (not trust_score_based) request.
            # elif not is_trust_based and total_peer < digital_id_constants.MAX_PEER_COUNT:
            #     print(
            #         "\nInput Error: Minimum peer requirement of {} peers has not reached\n"
            #             .format(digital_id_constants.MAX_PEER_COUNT))
            #     continue

        if total_peer > digital_id_constants.MAX_PEER_COUNT:
            print("\nInput Error: You can select only up to {} peers\n".format(digital_id_constants.MAX_PEER_COUNT))
            continue
        flag = 0
        # for k in selected_keys:
        for peer_address in selected_keys:
            try:
                # (peer_address, trust_val) = peer_dict.get(k.strip()).split(',')
                peer_address = peer_address.strip()
                (trust_str, alias_str) = peer_dict.get(peer_address).split(',')
                LOGGER.debug("trust_str {}".format(trust_str))
                LOGGER.debug("alias_str {}".format(alias_str))
                # score = trust_val.split('=')[1].strip()
                score = trust_str.split('=')[1].strip()
                LOGGER.debug("score {}".format(score))
                total_score = total_score + int(score)
                selected_peers.append(peer_address)
                # peer_dict.pop(k.strip())
                peer_dict.pop(peer_address)
                LOGGER.debug(peer_dict)
            except AttributeError:
                print("\nInvalid key selection. Please choose from the given list.\n")
                selected_peers = []  # 27 Apr: resetting selected_peers list
                flag = 1
                break

        if flag == 1:
            continue

        if is_trust_based is True:
            # selected_peers.append(peer_dictionary.get(k.strip()).split(',')[0])
            print("Maximum total score that can be reached {}".format(total_score))

            # N = total_peer + count({digitalid_certifier, learner})
            N = total_peer + 1
            # super_majority_num = math.floor(2 * (total_peer) / 3)
            # super_majority_num = math.floor(2 * (N - 1) / 3) + 1
            super_majority_num = 2 * math.floor((N - 1) / 3) + 1
            LOGGER.debug("super_majority_num {}".format(super_majority_num))

            # target_peer_quorum = (super_majority_num - 1) * digital_id_constants.MAX_CLIENT_TRUST_SCORE
            target_peer_quorum = super_majority_num * digital_id_constants.MAX_CLIENT_TRUST_SCORE
            LOGGER.debug("target peer quorum {}".format(target_peer_quorum))
            print("Target peer quorum {}".format(target_peer_quorum))

            if total_score < target_peer_quorum:
                print("\nMinimum quorum requirement of {} cannot be reached by the selected peers".
                      format(target_peer_quorum)
                      )
                print("\nPlease add more peers from the list")
                continue
            else:
                return selected_peers
        else:
            return selected_peers


def _set_id_for_update(digital_id_msg, attr_names):
    LOGGER.debug("Inside userwallet_client._set_id_for_update()")
    # new_id = digital_id_pb2.DigitalId()
    # new_id.CopyFrom(digital_id_msg)
    # if digital_id_msg.attribute_set.name.status == id_attribute_pb2.DEFAULT:
    #     digital_id_msg.attribute_set.name.status = id_attribute_pb2.ON_UPDATE
    #
    # if digital_id_msg.attribute_set.date_of_birth.status == id_attribute_pb2.DEFAULT:
    #     digital_id_msg.attribute_set.date_of_birth.status = id_attribute_pb2.ON_UPDATE
    #
    # if digital_id_msg.attribute_set.address_permanent.status == id_attribute_pb2.DEFAULT:
    #     digital_id_msg.attribute_set.address_permanent.status = id_attribute_pb2.ON_UPDATE
    #
    # if digital_id_msg.attribute_set.nationality.status == id_attribute_pb2.DEFAULT:
    #     digital_id_msg.attribute_set.nationality.status = id_attribute_pb2.ON_UPDATE
    #
    # if digital_id_msg.attribute_set.gender.status == id_attribute_pb2.DEFAULT:
    #     digital_id_msg.attribute_set.gender.status = id_attribute_pb2.ON_UPDATE

    id_attribute_fields = digital_id_msg.attribute_set.ListFields()
    LOGGER.debug("id_attribute_fields {}".format(id_attribute_fields))
    for attr_field in id_attribute_fields:
        if attr_field[0].name != 'others':
            if attr_field[0].name.capitalize() in attr_names:
                LOGGER.debug("Updating field : %s", attr_field[0].name)
                attr_field[1].status = id_attribute_pb2.Status.ON_UPDATE
                # attr_field[1].verifier_list.clear()
                attr_field[1].ClearField('verifier_list')
                # LOGGER.debug("Updated field status: %s", new_id.attribute_set.name.status)
        elif attr_field[0].name == 'others':
            attr_map = attr_field[1]
            LOGGER.debug(attr_map)
            for key_name in attr_map:
                LOGGER.debug("Checking field in dictionary 'others': %s", key_name)
                if key_name.capitalize() in attr_names:
                    LOGGER.debug("Updating field : %s", key_name)
                    field_value = attr_map[key_name]
                    field_value.status = id_attribute_pb2.Status.ON_UPDATE
                    # field_value.verifier_list.clear()
                    field_value.ClearField('verifier_list')

    # Added 30 Apr, 2020
    resp = input("Do you want to include additional attributes? Y/N: ")
    if resp.capitalize().strip() == 'Y':
        attr_list = input("Please enter additional attribute list : ")
        attr_list = attr_list.split(',')
        others_map = digital_id_msg.attribute_set.others
        for attr in attr_list:
            LOGGER.debug("Initializing {} ".format(attr.strip()))
            others_map.get_or_create(attr.strip())


def review_disable_req(disabled_digital_id, owner_address, txn_id):
    LOGGER.debug("Inside userwallet_client.review_disable_req()")

    print("Disable ID request received from address {}".format(owner_address))
    print("Transaction ID {}".format(txn_id))

    _display_id(disabled_digital_id)
    send_ack_resp = input("Send acknowledgement? Y/N :")
    return send_ack_resp.capitalize().strip()


def _get_dependency_transaction(old_state_address, base_url):
    _state_data = chain_access_util.get_state(base_url=base_url, address=old_state_address)

    if _state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
        print("Recovery of ID not possible - ID state {} not found".format(old_state_address))
        return None

    try:
        digital_id_data = _state_data['digital_id']
    except BaseException as err:
        LOGGER.error("Error while reading state data : {}".format(err))
        print("Digital Id cannot be retrieved")
        print("Error while reading state data {}".format(err))
        return None

    if digital_id_data is None or digital_id_data is b'':
        LOGGER.error("Invalid Digital-ID state")
        print("Digital-ID cannot be found")
        return None
    else:
        # check status of the retrieved digital_id_data
        retrieved_digital_id = digital_id_pb2.DigitalId()
        retrieved_digital_id.ParseFromString(digital_id_data)
        # if retrieved_digital_id.status != id_attribute_pb2.Status.RECOVERY_REQ:
        if retrieved_digital_id.status != id_attribute_pb2.Status.INVALID:
            LOGGER.error("Retrieved digital ID from state of {} has non-permitted status of {}",
                         old_state_address, retrieved_digital_id.status)
            print("Requested Digital ID is not invalidated yet. Retrieved status {}".format(
                retrieved_digital_id.status))
            return None
        else:
            dependency_txn = _state_data["acting_transaction_id"]
            return dependency_txn


class UserWalletClient(object):
    """ Client User Wallet class """
    wait_time = 100

    def __init__(self, base_url, command, key_file_name=DEFAULT_KEY_FILE_NAME):

        """Initialize the _client class, get the key pair and compute the address. """
        LOGGER.debug("Inside UserWalletClient.__init__")
        self.base_url = base_url
        self._key_file = _get_private_key_file(key_file_name)
        self.command = command
        pwd = os.path.expanduser(".")
        # peer_dir = os.path.join(pwd, "learner") -- old code --
        peer_dir = os.path.join(pwd, key_file_name)
        self.peer_file = '{}/{}.txt'.format(peer_dir, digital_id_constants.PEER_FILE_NAME)
        # creating database with hash access method
        # try:do_attest_peer
        #     self.user_wallet_db = db.DB()
        #     self.user_wallet_db.open(USER_DB_FILE, None, db.DB_HASH, db.DB_CREATE)
        # except Exception as err:
        #     print(err)
        #     LOGGER.error(err)
        try:
            with open(self._key_file) as fd:
                private_key_str = fd.read().strip()
        except OSError as err:
            raise Exception('Failed to read private key {}: {}'.format(self._key_file, str(err)))

        try:
            private_key = Secp256k1PrivateKey.from_hex(private_key_str)
        except ParseError as err:
            raise Exception('Failed to load private key:{}'.format(str(err)))

        self._signer = CryptoFactory(create_context('secp256k1')).new_signer(private_key)
        self.public_key = self._signer.get_public_key().as_hex()
        self.public_address = hashing.get_pub_key_hash(self.public_key)
        LOGGER.debug("Public key hash : {}".format(self.public_address))
        print("\nPublic Key of key profile {} : {}".format(key_file_name, self.public_key))
        print("\nBlockchain address of key profile {} : {}".format(key_file_name, self.public_address))
        self._self_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                                 key='self',
                                                                 pub_key_hash=self.public_address)
        self._id_creation_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                                  key=FAMILY_NAME_CERTIFY,
                                                                  pub_key_hash=self.public_address)
        self._id_creation_state = None
        self._digital_id_msg = None
        self._last_acting_txn_id = ""
        self._id_status = id_attribute_pb2.Status.DEFAULT
        self.txn_generator = TransactionGenerator(base_url=self.base_url, public_key=self.public_key,
                                                  signer=self._signer)
        user_dir = os.path.join(os.getcwd(), key_file_name)
        if os.path.isdir(user_dir) is False:
            os.mkdir(key_file_name)
        self.events_db_file = os.path.join(user_dir, EVENTS_DB_FILE)
        self.user_db_file = os.path.join(user_dir, USER_DB_FILE)
        self.registry_db_file = os.path.join(pwd, REGISTRY_DB_FILE)
        self.black_list = []
        self.update_blacklist_flag = True
        registry_db = db.DB()
        registry_db.open(self.registry_db_file, None, db.DB_HASH, db.DB_CREATE)
        if registry_db.get('black_list'.encode()) is not None:
            self.black_list = cbor.loads(registry_db.get('black_list'.encode()))
        LOGGER.debug("self.black_list : {}".format(self.black_list))
        registry_db.close()

        # if the flags exist in the db read and initialize from the db

        user_wallet_db = db.DB()
        user_wallet_db.open(self.user_db_file, None, db.DB_HASH, db.DB_CREATE)

        if user_wallet_db.get('black_list'.encode()) is not None:
            prev_black_list = cbor.loads(user_wallet_db.get('black_list'.encode()))
            if len(set(self.black_list).difference(set(prev_black_list))) > 0:
                self.update_blacklist_flag = True

        LOGGER.debug("update_blacklist_flag : {}".format(self.update_blacklist_flag))

        state_info_bin = user_wallet_db.get('state_info'.encode())

        if state_info_bin is not None:
            LOGGER.debug("From user_wallet_db -> read self.state_info_dict: ")
            self.state_info_dict = cbor.loads(state_info_bin)
            LOGGER.debug(self.state_info_dict)
        else:
            LOGGER.debug("No key 'state_info' exist in user_wallet_db")
            LOGGER.debug("Initializing state_info_dict")
            # initialize state_info of object
            self.state_info_dict = {
                "trust_score": 0,
                "enable_confirm": False,
                "enable_request": False,
                "enable_update": False,
                "self_verified": False,
                "peer_verification_request_sent": False,
                "enable_peer_verify": False,
                "enable_recovery": False,
                "peer_response_awaiting": False,
                "peer_quorum_reached": False,
                "finalized_id_present": False,
                "invalidation_req_sent": False,
                "on_update": False  # added 27 Apr
            }
        if self.state_info_dict.get('on_update') is None:
            self.state_info_dict['on_update'] = False  # added 27 Apr

        # _id_finalized is true when the confirmed ID receives acknowledgement
        self._id_finalized = False

        peer_verification_info_bin = user_wallet_db.get('peer_verification_info'.encode())
        if peer_verification_info_bin is not None:
            LOGGER.debug("From user_wallet_db -> read self.peer_verification_info: ")
            self.peer_verification_info = cbor.loads(peer_verification_info_bin)
            LOGGER.debug(self.peer_verification_info)
        else:
            LOGGER.debug("No key 'peer_verification_info' exist in user_wallet_db")
            LOGGER.debug("Initializing peer_verification_info")
            # initialize state_info of object
            self.peer_verification_info = {
                "id_dependency_txn": None,
                "peer_requests_sent": [],
                "peer_responses": [],
                "id_verification_detail": {}
            }
        # load end-timer value for peer verification response from db
        self.peer_timer_end = None
        peer_timer_end = user_wallet_db.get('peer_request_timer_end'.encode())
        if peer_timer_end is not None:
            self.peer_timer_end = cbor.loads(peer_timer_end)
        else:
            self.peer_timer_end = 0
        # Apr 9, 2020:
        self.credibility_inc_info = {}
        # self.credibility_inc_info = {
        #     "latest_resp_txns": [],
        #     "latest_verifier_dict": {}
        # }
        # peer address: FAMILY_NAME_PEER_VERIFY[0:6] + FAMILY_NAME_DIGITALID[0:24] + owner_public_key_hash[0:40]
        self._quorum_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_PEER_VERIFY,
                                                             pub_key_hash=self.public_address,
                                                             key=FAMILY_NAME_DIGITALID)

        LOGGER.debug("quorum_address {}".format(self._quorum_address))
        self._attribute_quorum_dict = None
        user_wallet_db.close()
        self._refresh_state()

        # if self._id_status == id_attribute_pb2.ACK_CONFIRMED:
        #     # self.trust_score = 20
        #     self.state_info_dict['trust_score'] = 20
        # TODO code to award trust score for each successful peer verification
        # and penalty otherwise, timestamp

        # TODO initialize stored state in user_wallet_db
        # self.user_wallet_db.put("peer_verification_request_sent".encode(), self.peer_verification_request_sent)
        # self.user_wallet_db.put("peer_response_awaiting".encode(), self.peer_response_awaiting)
        # if self.user_wallet_db.get("trust_score".encode()) is None:
        #     self.user_wallet_db.put("trust_score".encode(), self.trust_score)
        # queue = multiprocessing.queues

        # transferred to userwallet
        # self.proc_event_listener = multiprocessing.Process(target=_start_events_listener, args=(self.public_address, ))
        # self.proc_event_listener.start()

    def add_verifier_strength(self, field_name, attribute_data):
        LOGGER.debug("Inside add_verifier_strength()")
        additional_verifier_dict = self.credibility_inc_info["latest_verifier_dict"]
        new_verifier_list = additional_verifier_dict.get(field_name)
        LOGGER.debug("new_verifier_list {}".format(new_verifier_list))
        additional_strength = 0
        if new_verifier_list is not None:
            verifier_infos = attribute_data.verifier_list
            for verifier in new_verifier_list:
                if verifier not in verifier_infos:
                    attribute_data.verifier_list.append(verifier)
                    verifier_client_info = client_pb2.ClientAttributes()
                    verifier_client_info.ParseFromString(verifier)
                    additional_strength = additional_strength + verifier_client_info.trust_score

        LOGGER.debug("extended verifier_list {} for {} field : ".format(attribute_data.verifier_list, field_name))
        LOGGER.debug("additional_strength {} for {} field : ".format(additional_strength, field_name))
        return additional_strength

    def deduct_verifier_strength(self, field_name, attribute_data):
        LOGGER.debug("Inside deduct_verifier_strength()")
        deduce_strength = 0
        verifier_infos = attribute_data.verifier_list
        LOGGER.debug("self.black_list {}".format(self.black_list))
        for verifier in verifier_infos:
            verifier_client_info = client_pb2.ClientAttributes()
            verifier_client_info.ParseFromString(verifier)
            if verifier_client_info.user_address in self.black_list:
                LOGGER.debug("bad_verifier {}".format(verifier_client_info.user_address))
                attribute_data.verifier_list.remove(verifier)
                deduce_strength = deduce_strength + verifier_client_info.trust_score
        LOGGER.debug("updated verifier_list {} for {} field".format(attribute_data.verifier_list, field_name))
        LOGGER.debug("deduce_strength {} for {} field".format(deduce_strength, field_name))

        return deduce_strength

    def update_id_verifiers(self, add_verifier_flag):
        LOGGER.debug("Inside update_id_verifiers()")
        LOGGER.debug("blacklist_updated_flag {}".format(self.update_blacklist_flag))
        LOGGER.debug("add_verifier_flag {}".format(add_verifier_flag))
        # test on self._digital_id_msg as well
        digital_id_msg = digital_id_pb2.DigitalId()
        digital_id_msg.CopyFrom(self._digital_id_msg)
        attribute_set_msg = digital_id_msg.attribute_set
        attribute_fields = attribute_set_msg.ListFields()
        update_flag = False
        demote_id_trust_flag = False
        min_peer_vote_req = math.floor(2 * digital_id_constants.MIN_PEER_COUNT / 3) + 1
        min_target_peer_quorum = (min_peer_vote_req - 1) * digital_id_constants.MAX_CLIENT_TRUST_SCORE
        additional_verifier_dict = None
        if add_verifier_flag is True:
            additional_verifier_dict = self.credibility_inc_info["latest_verifier_dict"]

        for attribute_field in attribute_fields:
            if attribute_field[0].name != 'others':
                additional_strength = 0
                deduce_strength = 0
                if add_verifier_flag is True and additional_verifier_dict is not None:
                    additional_strength = self.add_verifier_strength(field_name=attribute_field[0].name,
                                                                     attribute_data=attribute_field[1])

                if self.update_blacklist_flag is True:
                    deduce_strength = self.deduct_verifier_strength(field_name=attribute_field[0].name,
                                                                    attribute_data=attribute_field[1])

                if additional_strength != 0 or deduce_strength != 0:
                    update_flag = True
                    attribute_field[1].credibility_strength = attribute_field[1].credibility_strength \
                                                              + additional_strength - deduce_strength
                    if min_target_peer_quorum > attribute_field[1].credibility_strength:
                        # minimum credibility requirement not met
                        attribute_field[1].status = id_attribute_pb2.ON_VERIFICATION
                        demote_id_trust_flag = True

                    # attribute_field[1].verification_quorum = attribute_field[1].verification_quorum \
                    #                                          + additional_strength - deduce_strength
                    # LOGGER.debug("updated verification_quorum {}".format(attribute_field[1].verification_quorum))
                    LOGGER.debug("updated credibility_strength {}".format(attribute_field[1].credibility_strength))
                    LOGGER.debug("updated verifier list {}".format(attribute_field[1].verifier_list))

            else:
                attr_map = attribute_field[1]
                for field_name in attr_map:
                    # field_name is the key
                    additional_strength = 0
                    deduce_strength = 0

                    if add_verifier_flag is True and additional_verifier_dict is not None:
                        additional_strength = self.add_verifier_strength(field_name=field_name,
                                                                         attribute_data=attr_map[field_name])

                    if self.update_blacklist_flag is True:
                        deduce_strength = self.deduct_verifier_strength(field_name=field_name,
                                                                        attribute_data=attr_map[field_name])

                    if additional_strength != 0 or deduce_strength != 0:
                        update_flag = True
                        attr_map[field_name].credibility_strength = \
                            attr_map[field_name].credibility_strength + additional_strength - deduce_strength

                        if min_target_peer_quorum > attr_map[field_name].credibility_strength:
                            # minimum credibility requirement not met
                            attr_map[field_name].status = id_attribute_pb2.ON_VERIFICATION
                            demote_id_trust_flag = True
                        LOGGER.debug("demote_id_trust_flag {}".format(demote_id_trust_flag))
                        # attr_map[field_name].verification_quorum = \
                        #     attr_map[field_name].verification_quorum + additional_strength - deduce_strength
                        # LOGGER.debug("updated verification_quorum {}".format(attr_map[field_name].verification_quorum))
                        LOGGER.debug(
                            "updated credibility_strength {}".format(attr_map[field_name].credibility_strength))
                        LOGGER.debug("updated verifier list {}".format(attr_map[field_name].verifier_list))
        LOGGER.debug("update_flag {}".format(update_flag))
        if update_flag is True:
            # send transaction with CONFIRM status/ON_VERIFICATION status
            last_confirmed_txn = self._id_creation_state['user_confirmation_txn']
            LOGGER.debug("demote_id_trust_flag {}".format(demote_id_trust_flag))
            if demote_id_trust_flag is True:  # check if the ID still meets the quorum requirement
                # ID trust-score to be set to 1
                digital_id_msg.status = id_attribute_pb2.ON_VERIFICATION
                result = self._send_digital_id_txn(action="demote_id_strength", id_to_send=digital_id_msg,
                                                   dependency_txns=[last_confirmed_txn])
            else:
                # ID trust-score to remain same

                result = self._send_digital_id_txn(action="update_id_strength", id_to_send=digital_id_msg,
                                                   dependency_txns=[last_confirmed_txn])
            LOGGER.debug(result)
            print(result)
            if result != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
                status = yaml.safe_load(result)['data'][0]['status']
                if status == 'COMMITTED':
                    print("ID confirmation successfully committed")
                    # Added 30 Apr, 2020
                    if demote_id_trust_flag is True:
                        self.state_info_dict['on_update'] = True
                        user_wallet_db = db.DB()
                        user_wallet_db.open(self.user_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
                        user_wallet_db.put('state_info'.encode(), cbor.dumps(self.state_info_dict))
                        user_wallet_db.close()
                    return True
                else:
                    print("Failed to commit ID confirmation")
                    return False
            else:
                return False

    def load_peers(self):
        LOGGER.debug("inside load_peers()")
        peer_dict = {}
        registry_db = db.DB()
        registry_db.open(self.registry_db_file, None, db.DB_HASH, db.DB_RDONLY)
        try:
            with open(self.peer_file) as fd:
                for line in fd:
                    line = line.strip()
                    if line.startswith('#') or line == '':
                        continue
                    (peer_key, value) = line.split(':')
                    # peer_key is peer's blockchain address
                    # value contains the alias information
                    # if value is not None or "":
                    key = peer_key.strip()
                    if registry_db.get(key.encode()) is not None and key not in self.black_list:
                        peer_trust_score = int.from_bytes(registry_db.get(key.encode()), byteorder='big')
                        if peer_trust_score == digital_id_constants.MAX_CLIENT_TRUST_SCORE or \
                                peer_trust_score == digital_id_constants.CONFIRMED_ID_TRUST_SCORE:
                            # peer_dict[peer_key] = value + ", trust-score = " + str(peer_trust_score) -- old format --
                            peer_dict[key] = "trust-score = " + str(peer_trust_score) + ", alias = " + value.strip()
        except OSError as err:
            raise Exception('Failed to read peer list {}: {}'.format(self.peer_file, str(err)))
        finally:
            registry_db.close()
        return peer_dict

    def peer_verify(self):
        # read peers from peer.txt
        # Get selected peer list from file /learner/peer.txt.txt
        LOGGER.debug("Inside userwallet_client.peer_verify")

        if self.command == 'id_wallet' and self.refresh_exit:
            self._refresh_state()

        # self.self_verify()
        if self.state_info_dict['self_verified'] is False:
            self.self_verify()

        # self.state_info_dict['enable_peer_verify'] = True
        if self.state_info_dict['self_verified'] is True and \
                self.state_info_dict['enable_peer_verify'] is True:
            print("\nDigital ID details are self-verified.\n")
            peer_dict = self.load_peers()
            req_list_dict = {}

            # display each field from current id and select peers for individual fields
            attribute_set_msg = self._digital_id_msg.attribute_set
            attribute_fields = attribute_set_msg.ListFields()
            # attribute_names = [x[0].name for x in attribute_fields]
            attribute_names = []
            for attribute_field in attribute_fields:
                if attribute_field[0].name != 'others':
                    if attribute_field[1].status == id_attribute_pb2.Status.ON_VERIFICATION:
                        field_name = attribute_field[0].name
                        attribute_names.append(field_name)
                        print("\nSelect peers to vote for {}".format(field_name.capitalize()))
                        selected_peers = select_peers(peer_dictionary=peer_dict)
                        for peer in selected_peers:
                            if req_list_dict.get(peer) is None:
                                req_list_dict[peer] = [field_name]
                            else:
                                req_list_dict.get(peer).append(field_name)
                else:
                    attr_map = attribute_field[1]
                    for field_name in attr_map:
                        # field_name is the key
                        if attr_map[field_name].status == id_attribute_pb2.Status.ON_VERIFICATION:
                            attribute_names.append(field_name)
                            print("\nSelect peers to vote for {}\n".format(field_name.capitalize()))
                            selected_peers = select_peers(peer_dictionary=peer_dict)
                            for peer in selected_peers:
                                if req_list_dict.get(peer) is None:
                                    req_list_dict[peer] = [field_name]
                                else:
                                    req_list_dict.get(peer).append(field_name)

            # send peer verification request to all the selected peers
            LOGGER.debug("\nreq_list_dict {}\n".format(req_list_dict))
            result = self._send_peer_verification_request(req_list_dict=req_list_dict,
                                                          # attribute_names=attribute_names,
                                                          action_type=digital_id_constants.TYPE_ID_CREATE)
            LOGGER.debug(result)
            print(result)
            if result != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
                status = yaml.safe_load(result)['data'][0]['status']
                if status == 'COMMITTED':
                    print("Batch of requests successfully committed")
                    # current_time = datetime.now()
                    # timestamp = str(current_time.isoformat())
                    timer_start = time.time()
                    timer_expiry = digital_id_constants.PEER_VERIFY_TIMER  # time in seconds
                    timer_end = timer_start + timer_expiry
                    self.state_info_dict['peer_verification_request_sent'] = True
                    self.state_info_dict['on_update'] = False
                    user_wallet_db = db.DB()
                    user_wallet_db.open(self.user_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
                    user_wallet_db.put('state_info'.encode(), cbor.dumps(self.state_info_dict))
                    user_wallet_db.put('peer_verification_info'.encode(), cbor.dumps(self.peer_verification_info))
                    # adding request time-stamp to the database
                    user_wallet_db.put('peer_request_timer_end'.encode(), cbor.dumps(timer_end))
                    user_wallet_db.close()
                    return True
                else:
                    print("Failed to commit request batch")
                    return False
            else:
                return False
            # else:
            #     self.state_info_dict['peer_verification_request_sent'] = False

            # wait until required quorum is obtained or timer times out

    def load_id_status(self):
        """This method gets the latest ID status from the corresponding state"""

        LOGGER.debug("inside UserWalletClient.load_id_status")
        state_response = chain_access_util.get_state(self.base_url, self._id_creation_address)
        if state_response == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            self._id_creation_state = digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE
            self.state_info_dict['trust_score'] = 0
        else:  # data
            self._id_creation_state = state_response

        LOGGER.debug("_id_creation_state {}".format(self._id_creation_state))
        self._digital_id_msg = None
        if self._id_creation_state is not None \
                and self._id_creation_state != digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            self._last_acting_txn_id = self._id_creation_state['acting_transaction_id']
            self._digital_id_msg = _get_id_from_state(self._id_creation_state)
            self._id_status = self._digital_id_msg.status
            LOGGER.debug("self._id_status {}".format(self._id_status))

            # code to retrieve trust score from saved state to be moved self.check_id_verifiers()?
            trust_score = self._id_creation_state['trust_score']
            self.state_info_dict['trust_score'] = trust_score

            # put the trust-score in registry_db
            registry_db = db.DB()
            registry_db.open(self.registry_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
            if registry_db.get(self.public_address.encode()) is None:
                # if self._id_status == id_attribute_pb2.Status.CONFIRMED and self._id_finalized is True:
                registry_db.put(self.public_address.encode(), trust_score.to_bytes(length=2, byteorder='big'))
            elif registry_db.get(self.public_address.encode()).decode != trust_score:
                registry_db.put(self.public_address.encode(), trust_score.to_bytes(length=2, byteorder='big'))

            registry_db.close()

        else:
            self._last_acting_txn_id = ""
            self._id_status = id_attribute_pb2.Status.DEFAULT

        if self._id_status == id_attribute_pb2.Status.DEFAULT:
            # TODO or self._id_status == id_attribute_pb2.Status.EXPIRED:
            # self.enable_request = True
            print("Please request a new Digital-ID")
            self.state_info_dict['enable_request'] = True
            self.state_info_dict['enable_recovery'] = True
            self.state_info_dict['self_verified'] = False
        else:
            self.state_info_dict['enable_request'] = False

        # ------Apr 16, 2020: commenting this block as recovery from the
        # same profile that invalidates it is not being allowed----------------
        # if self._id_status == id_attribute_pb2.Status.INVALID:
        #     self.state_info_dict['enable_recovery'] = True

        if self._id_status != id_attribute_pb2.Status.ON_VERIFICATION and \
                self._id_status != id_attribute_pb2.Status.CONFIRMED:
            self.state_info_dict['self_verified'] = False

        LOGGER.debug("enable_request: {}".format(self.state_info_dict['enable_request']))

        # --commented : start --------------
        # if self._id_status == id_attribute_pb2.Status.REQUESTED:
        #     print("Digital-ID request under processing")
        # if self._id_status == id_attribute_pb2.Status.ON_UPDATE:
        #     print("Digital-ID update request under processing")
        # if self._id_status == id_attribute_pb2.Status.CONFIRMED:
        #     # Apr 4, 2020: update self.black-list if needed
        #     registry_db = db.DB()
        #     registry_db.open(self.registry_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
        #     black_list_frm_db = registry_db.get('black_list'.encode()).decode()
        #     if self.black_list != black_list_frm_db:
        #         self.black_list = black_list_frm_db
        #         # checking if any of the ID-verifiers is blacklisted
        #         self.check_id_verifiers()
        #     registry_db.close()
        #     self.save_ack_receipt()
        #     self.state_info_dict['finalized_id_present'] = self._id_finalized

        # added enable_update flag to check if update operation is allowed

        # if (self._id_status == id_attribute_pb2.Status.ON_VERIFICATION and self.state_info_dict[
        #     'self_verified'] is False and
        #     self.state_info_dict['peer_verification_request_sent'] is False) \
        #         or self._id_status == id_attribute_pb2.Status.CONFIRMED and self._id_finalized is True:
        #     self.state_info_dict['enable_update'] = True
        # else:  # if self._id_status == id_attribute_pb2.Status.INVALID or id_attribute_pb2.Status.ON_REQUEST or 'any
        #     # other cases'
        #     self.state_info_dict['enable_update'] = False
        # --commented : end --------------

    def request_id(self):
        LOGGER.debug("inside UserWalletClient.request_id")
        if self.command == 'id_wallet' and self.refresh_exit:
            self._refresh_state()
        if self.state_info_dict['enable_request'] is True:
            try:
                result = self._send_digital_id_txn(action="request_id")
            except InvalidTransaction as err:
                print("Received InvalidTransaction exception {}".format(err))
                return False
            LOGGER.debug(result)
            print(result)
            if result != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
                status = yaml.safe_load(result)['data'][0]['status']
                if status == 'COMMITTED':
                    print("Request successfully submitted")
                    self.state_info_dict['enable_request'] = False
                    self.state_info_dict['self_verified'] = False
                    user_wallet_db = db.DB()
                    user_wallet_db.open(self.user_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
                    user_wallet_db.put('state_info'.encode(), cbor.dumps(self.state_info_dict))
                    user_wallet_db.put('peer_verification_info'.encode(), cbor.dumps(self.peer_verification_info))
                    user_wallet_db.close()
                    return True
                else:
                    print("Failed to commit request")
                    return False
            else:
                return False

    def confirm_id(self):
        LOGGER.debug("inside UserWalletClient.confirm_id")
        # get the state, check status = verified,
        # send transaction to  change the status to confirmed
        # read the event db

        # update 'enable_confirm'

        try:

            if self.command == 'id_wallet' and self.refresh_exit:
                self._refresh_state()

            if self.state_info_dict['self_verified'] is False:
                self.self_verify()

            if self.state_info_dict['self_verified'] is True and \
                    self.state_info_dict['enable_confirm'] is False:

                if self.state_info_dict['enable_peer_verify'] is True:
                    self.peer_verify()
                else:
                    if self.state_info_dict['peer_verification_request_sent'] is True and self.refresh_exit:
                        # self.get_id_quorum_state()
                        # self._update_state_vars()
                        self._refresh_state()

                        # if self.state_info_dict['peer_quorum_reached'] is True:
                        #     self.state_info_dict['enable_peer_verify'] = False
                        #     self.state_info_dict['enable_confirm'] = True
                        # elif self.state_info_dict['peer_quorum_reached'] is False \
                        #         and self.state_info_dict['peer_response_awaiting'] is False:
                        #     self.state_info_dict['enable_peer_verify'] = False
                        #     self.state_info_dict['enable_confirm'] = False
                        #     print("Invalid ID data. Please update to get it confirmed.")
                        # self.user_wallet_db.put("enable_confirm".encode(), self.enable_confirm)
                        # TODO elif self.state_info_dict['peer_quorum_reached'] is False and
                        #  self.state_info_dict['peer_response_awaiting'] is True: wait till the timer times out

            if self.state_info_dict['enable_confirm'] is True:
                # Commented 27 Apr : TODO test impact
                # and self.state_info_dict['trust_score'] == digital_id_constants.PRIMARY_CERTIFIED_TRUST_SCORE:
                LOGGER.debug("enable_confirm is true")
                # TODO send peer verification request if not done yet
                # self.state_info_dict['trust_score'] = digital_id_constants.CONFIRMED_ID_TRUST_SCORE
                # self.user_wallet_db.put("trust_score".encode(), self.state_info_dict['trust_score'])
                result = self._send_digital_id_txn("confirm_id")
                LOGGER.debug(result)
                print(result)
                if result != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
                    status = yaml.safe_load(result)['data'][0]['status']
                    if status == 'COMMITTED':
                        print("ID confirmation successfully committed")
                        user_wallet_db = db.DB()
                        user_wallet_db.open(self.user_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
                        user_wallet_db.put('state_info'.encode(), cbor.dumps(self.state_info_dict))
                        user_wallet_db.put('peer_verification_info'.encode(), cbor.dumps(self.peer_verification_info))
                        user_wallet_db.close()
                        return True
                    else:
                        print("Failed to commit ID confirmation")
                        return False
                else:
                    return False
            else:
                print("Operation not allowed at this stage")
                return False

        except BaseException as err:
            LOGGER.error(err)

    def self_verify(self):
        LOGGER.debug("Inside self_verify()")
        if self.state_info_dict['self_verified'] is False:

            if self._id_status == id_attribute_pb2.Status.ON_VERIFICATION:

                self.display_id()
                is_correct = input("The data displayed is correct? Y/N :")
                if is_correct.capitalize().strip() == 'Y':
                    self.state_info_dict['self_verified'] = True
                    self.state_info_dict['enable_peer_verify'] = True
                    user_wallet_db = db.DB()
                    user_wallet_db.open(self.user_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
                    user_wallet_db.put('state_info'.encode(), cbor.dumps(self.state_info_dict))
                    user_wallet_db.close()
                else:
                    edit_choice = input("Edit details to update ID? Y/N :")
                    if edit_choice.capitalize().strip() == 'Y':
                        self.do_update_id()
                        # should have self.state_info_dict['enable_update']=True after state refresh
                    else:
                        print('You have chosen not to update the ID.')
                        return
            else:
                print('Operation not allowed')
                return

        else:
            print('Already self-verified')

    def do_update_id(self):
        LOGGER.debug("inside UserWalletClient.update_id")

        if self.command == 'id_wallet' and self.refresh_exit:
            self._refresh_state()

        if self.state_info_dict['enable_update'] is True:

            try:
                result = self._send_digital_id_txn("update_id")
            except InvalidTransaction as err:
                print("Received InvalidTransaction exception {}".format(err))
                return False
            LOGGER.debug(result)
            print(result)
            if result != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
                status = yaml.safe_load(result)['data'][0]['status']
                if status == 'COMMITTED':
                    print("Update request successfully submitted")
                    self.state_info_dict['enable_update'] = False
                    self.state_info_dict['self_verified'] = False
                    self.state_info_dict['on_update'] = True
                    user_wallet_db = db.DB()
                    user_wallet_db.open(self.user_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
                    user_wallet_db.put('state_info'.encode(), cbor.dumps(self.state_info_dict))
                    user_wallet_db.put('peer_verification_info'.encode(), cbor.dumps(self.peer_verification_info))
                    user_wallet_db.close()
                    return True
                else:
                    print("Failed to commit update request")
                    return False
            else:
                return False
        else:
            print('Update operation not allowed.')
            return

    def invalidate_id(self):
        LOGGER.debug("inside UserWalletClient.invalidate_id")

        if self.command == 'id_wallet' and self.refresh_exit:
            self._refresh_state()

        try:
            result = self._send_digital_id_txn("invalidate_id")
        except InvalidTransaction as err:
            print("Received InvalidTransaction exception {}".format(err))
            return False

        LOGGER.debug(result)
        print(result)
        if result != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
            status = yaml.safe_load(result)['data'][0]['status']
            if status == 'COMMITTED':
                print("Update request successfully submitted")
                user_wallet_db = db.DB()
                self.state_info_dict['invalidation_req_sent'] = True
                user_wallet_db.open(self.user_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
                user_wallet_db.put('state_info'.encode(), cbor.dumps(self.state_info_dict))
                user_wallet_db.put('peer_verification_info'.encode(), cbor.dumps(self.peer_verification_info))
                user_wallet_db.close()
                return True
            else:
                print("Failed to commit request")
                return False
        else:
            return False

    def recover_id(self):
        LOGGER.debug("inside UserWalletClient.recover_id")
        if self.command == 'id_wallet' and self.refresh_exit:
            self._refresh_state()
        if self.state_info_dict['enable_recovery'] is True:
            try:
                digital_id_msg = digital_id_pb2.DigitalId()
                digital_id_msg.status = id_attribute_pb2.Status.RECOVERY_REQ
                resp = input("Please enter the public key of the profile to be recovered: ")
                # fetch the related state to check if the status of the digital id is INVALID
                # and return the invalidation request as the dependency_txn
                invalidated_address = hashing.get_pub_key_hash(resp.strip())
                state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                              pub_key_hash=invalidated_address,
                                                              key=FAMILY_NAME_CERTIFY)
                dependency_txn = _get_dependency_transaction(old_state_address=state_address, base_url=self.base_url)
                LOGGER.debug("dependency_txn {}".format(dependency_txn))
                if dependency_txn is None:
                    return False
                digital_id_msg.id_owner_public_key = resp.strip()  # old public key
                result = self._send_digital_id_txn(action="recover_id", id_to_send=digital_id_msg,
                                                   dependency_txns=[dependency_txn],
                                                   state_address_list=[invalidated_address])
            except InvalidTransaction as err:
                print("Received InvalidTransaction exception {}".format(err))
                return False
            LOGGER.debug(result)
            print(result)
            if result != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
                status = yaml.safe_load(result)['data'][0]['status']
                if status == 'COMMITTED':
                    print("Request successfully submitted")
                    self.state_info_dict['enable_recovery'] = False
                    user_wallet_db = db.DB()
                    user_wallet_db.open(self.user_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
                    user_wallet_db.put('state_info'.encode(), cbor.dumps(self.state_info_dict))
                    user_wallet_db.put('peer_verification_info'.encode(), cbor.dumps(self.peer_verification_info))
                    user_wallet_db.close()
                    return True
                else:
                    print("Failed to commit request")
                    return False
            else:  # TRANSACTION_TIMED_OUT_ERROR
                return False

    def display_id(self):
        LOGGER.debug("inside UserWalletClient.display_id")
        if self.command == 'id_wallet' and self.refresh_exit:
            self._refresh_state()
        # get the state and display details in console
        state_resp = chain_access_util.get_state(self.base_url, self._id_creation_address)
        # Checking if state was found
        if state_resp != digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            _display(state_resp)
        else:
            print("ID not found")
        return

    def save_ack_receipt(self):
        LOGGER.debug("inside UserWalletClient.save_ack_receipt")

        # check validity of self-state
        # is_self_state_valid = False
        self_state_data = chain_access_util.get_state(base_url=self.base_url, address=self._self_state_address)
        if self_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            print("Self-state not valid for save_ack_receipt operation.")
            return False
        else:
            digital_id_bytes = self_state_data['digital_id']
            digital_id = digital_id_pb2.DigitalId()
            digital_id.ParseFromString(digital_id_bytes)
            if digital_id.status == id_attribute_pb2.Status.CONFIRMED \
                    and self_state_data['ack_number'] is None \
                    and self_state_data['trust_score'] == digital_id_constants.CONFIRMED_ID_TRUST_SCORE:

                # is_self_state_valid = True
                print("\nProcessing to save ID acknowledgement number...\n")
                ack_event_found = False
                # try:
                LOGGER.debug("Looking for an acknowledgement event in the event database")
                events_db = db.DB()
                try:
                    events_db.open(self.events_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
                    key = "digitalid_certifier/acknowledged"
                    event_data = events_db.get(key.encode())
                    if event_data is not None:
                        even_attr = cbor.loads(event_data)
                        # txn_id = even_attr['transaction_id']
                        # certifier_address = even_attr['sent_from']
                        address = even_attr['address']
                        ack_txn_id = even_attr['transaction_id']
                        if address == self._id_creation_address:
                            ack_event_found = True
                            is_success = self._send_save_update(event_data, ack_txn_id)
                            if is_success is True:
                                events_db.delete(key.encode())
                        else:
                            print("Invalid acknowledgement event found in the database")
                except DBNoSuchFileError:
                    LOGGER.debug('events_db_file not present')
                except BaseException as err:
                    LOGGER.error("Error while reading event db {}".format(err))
                    raise Exception(err)

                if not ack_event_found:
                    LOGGER.debug("Corresponding acknowledgement event not present in the event database")
                    print("Looking for acknowledgement transaction in the ID_creation state")
                    if self._id_status == id_attribute_pb2.CONFIRMED and \
                            self._id_creation_state['user_confirmation_txn'] == self_state_data['user_confirmation_txn']:
                        # check if self._last_acting_txn_id has status id_attribute_pb2.ACK_CONFIRMED
                        txn_response = chain_access_util.get_transaction(base_url=self.base_url,
                                                                         requesting_txn_id=self._last_acting_txn_id)
                        try:
                            txn_payload = txn_response['payload']
                            digital_id_transaction = DigitalIdTransaction()
                            digital_id_transaction.ParseFromString(base64.b64decode(txn_payload))
                            txn_status = digital_id_transaction.status
                            LOGGER.debug("txn_status {}".format(txn_status))
                        except BaseException as err:
                            LOGGER.error("Error while reading transaction data {}".format(err))
                            raise Exception("Error while reading transaction data {}".format(err))
                        if txn_status == id_attribute_pb2.ACK_CONFIRMED:
                            txn_data = {'address': self._id_creation_address,
                                        'transaction_id': self._last_acting_txn_id}
                            txn_data_bytes = cbor.dumps(txn_data)
                            is_success = self._send_save_update(txn_data_bytes, self._last_acting_txn_id)
                            return is_success
                        else:
                            print("Acknowledgement not yet present for last confirmed ID.")
                    else:
                        print("ID creation state not congruent to save_ack_receipt operation")

                events_db.close()
                # except BaseException as err:
                #     LOGGER.error("Error while reading event db {}".format(err))
                #     raise Exception(err)

            elif digital_id.status == id_attribute_pb2.Status.CONFIRMED \
                    and self_state_data['ack_number'] is not None \
                    and self_state_data['trust_score'] == digital_id_constants.CONFIRMED_ID_TRUST_SCORE:
                # TODO check the _last_txn_id as well
                self._id_finalized = True
                self.state_info_dict['finalized_id_present'] = self._id_finalized   # added 2nd Jul, 2020
                # print("\nDigital-ID is confirmed and acknowledged. No action required.")
                return False

    def _send_save_update(self, data, ack_txn_id):
        LOGGER.debug("inside UserWalletClient.send_save_update")
        state_update_transaction = client_pb2.StateUpdateTransaction()
        state_update_transaction.action = digital_id_constants.UPDATE_STATE_ACK
        state_update_transaction.data = data
        payload = state_update_transaction.SerializeToString()
        input_address_list = [self._id_creation_address]
        output_address_list = [self._self_state_address, self._quorum_address]
        transaction = self.txn_generator.make_transaction(family=FAMILY_NAME_DIGITALID_CLIENT,
                                                          payload=payload,
                                                          input_address_list=input_address_list,
                                                          output_address_list=output_address_list,
                                                          dependency_list=[ack_txn_id])
        transaction_list = [transaction]
        batch_list = self.txn_generator.make_batch(transaction_list)
        batch_id = batch_list.batches[0].header_signature
        result = None
        try:
            # Send batch_list to the REST API
            response = self.txn_generator.send_to_rest_api("batches", batch_list.SerializeToString(),
                                                           'application/octet-stream')
            LOGGER.debug("Response from Rest-API {}".format(response))

            result = self.txn_generator.wait_for_status(batch_id, UserWalletClient.wait_time, result)
        except InvalidTransaction:
            return False

        LOGGER.debug(result)
        print(result)
        if result != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
            status = yaml.safe_load(result)['data'][0]['status']
            if status == 'COMMITTED':
                print("Acknowledgement successfully saved")
                return True
            else:
                print("Failed to save Acknowledgement")
                return False
        else:
            return False
        # if response != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
        #     return True
        # else:
        #     return False

    def get_id_quorum_state(self):
        LOGGER.debug("Inside userwallet_client.get_id_quorum_state")
        self.credibility_inc_info = {}
        try:
            quorum_state_data = chain_access_util.get_state(self.base_url, self._quorum_address)
            if quorum_state_data != digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE \
                    and quorum_state_data is not None:
                LOGGER.debug("quorum_state_data {}".format(quorum_state_data))
                # Apr 9: Added check for operation_type
                operation_type = quorum_state_data['operation_type']
                if operation_type == digital_id_constants.TYPE_ID_CREATE:
                    # check if self._last_acting_txn_id == self.peer_verification_info['id_dependency_txn']
                    self.peer_verification_info['id_dependency_txn'] = quorum_state_data['dependency']
                    # TODO 'id_dependency_txn' is top_up flow?
                    if self.peer_verification_info['id_dependency_txn'] == self._last_acting_txn_id:
                        # quorum state is updated for current ID generation
                        self.state_info_dict['peer_verification_request_sent'] = True
                        self.state_info_dict['self_verified'] = True
                        self._attribute_quorum_dict = quorum_state_data['attribute_quorum']
                        # if 'id_quorum_reached' in quorum_state_data.keys():
                        if quorum_state_data['id_quorum_reached'] is not None:
                            self.state_info_dict['peer_quorum_reached'] = quorum_state_data['id_quorum_reached']
                            if quorum_state_data['id_quorum_reached'] is True:
                                self.peer_verification_info['id_verification_detail'] = quorum_state_data[
                                    'verification_detail']

                        # pending_requests = []
                        pending_requests = quorum_state_data['peer_request_txn_ids']

                        if 'peer_response_txn_ids' in quorum_state_data.keys():
                            self.peer_verification_info['peer_responses'] = quorum_state_data['peer_response_txn_ids']

                        if pending_requests is not None and len(pending_requests) > 0:
                            self.state_info_dict['peer_response_awaiting'] = True
                    else:
                        #  quorum state out of date
                        self.state_info_dict['peer_verification_request_sent'] = False
                elif operation_type == digital_id_constants.TYPE_CREDIBILITY_INC:
                    if quorum_state_data['dependency'] == self._id_creation_state['user_confirmation_txn']:
                        self.credibility_inc_info["latest_resp_txns"] = quorum_state_data['peer_response_txn_ids']
                        self.credibility_inc_info["latest_verifier_dict"] = quorum_state_data['verification_detail']
                        # self.peer_verification_info['peer_responses'].extend(quorum_state_data['peer_response_txn_ids'])
                    # else ignore
            else:
                # TODO change
                self.state_info_dict['peer_verification_request_sent'] = False
        except KeyError as err:
            LOGGER.error("Quorum state access problem {}".format(err))

    # Modified definition March 9: removing peer_address as parameter
    # def attest_peer(self, request_txn_id=None, peer_address=None):
    def attest_peer(self, request_txn_id=None):
        LOGGER.debug("Inside attest_peer")
        LOGGER.debug("User public key : {}".format(self.public_key))
        peer_verifier = peer_verification_module.PeerVerificationClass(base_url=self.base_url,
                                                                       events_db_file=self.events_db_file,
                                                                       signer=self._signer,
                                                                       public_key=self.public_key,
                                                                       score=self.state_info_dict["trust_score"])

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

        # if response is True:
        #     self.user_wallet_db.put('state_info'.encode(), cbor.dumps(self.state_info_dict))
        #     self.user_wallet_db.put('peer_verification_info'.encode(), cbor.dumps(self.peer_verification_info))

    def serve_id_disable_requests(self, txn_id=None):
        """serve_id_disable_requests method serves pending
            incoming requests for ID invalidation confirmation """

        LOGGER.debug("Inside userwallet_client.serve_id_disable_requests")

        if self.command == 'id_wallet' and self.refresh_exit:
            self._refresh_state()

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
                    # remove corresponding transaction from db
                    if txn_id in request_list:
                        request_list.remove(txn_id)
                        LOGGER.debug(request_list)
                        events_db.put(key.encode(), cbor.dumps(request_list))
                        # events_db.close()
                    print("Successfully Processed")
            # except InvalidTransaction:
            except BaseException as err:
                print("Failed to commit transaction due to {}".format(err))
            finally:
                LOGGER.debug("Inside finally")
                events_db.close()
        else:
            # events_db = db.DB()
            # try:
            #     events_db.open(self.events_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
            #     key = "digitalid/invalidate"
            #     request_list = events_db.get(key.encode())
            # processed = []
            if request_list is not None:
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

    # removing owner_address parameter and retrieving it from provided txn_id
    def send_invalidation_ack(self, txn_id):
        LOGGER.debug("Inside userwallet_client.send_ack()")

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
                                                            key=FAMILY_NAME_CERTIFY)
        owner_self_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                                 pub_key_hash=owner_address,
                                                                 key='self')
        _state_data = chain_access_util.get_state(base_url=self.base_url, address=owner_state_address)
        try:
            invalidation_id_data = _state_data['invalidation_req']
            pending_address_list = _state_data['pending_acks']
            LOGGER.debug("pending_acks from state: {}".format(pending_address_list))
        except BaseException as err:
            LOGGER.error("Error while reading state data : {}".format(err))
            raise Exception("Error while reading state data")

        if self.public_address not in pending_address_list:
            LOGGER.error("Address {} not present in {}", self.public_address, pending_address_list)
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
        reply_addresses = [owner_state_address, owner_self_state_address]
        # send transaction to acknowledge disable request
        if send_ack_resp == 'Y':
            result = self._send_digital_id_txn(action="ack_invalidation", id_to_send=invalidation_id_data,
                                               dependency_txns=[txn_id], state_address_list=reply_addresses,
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
            else:
                print("Failed to commit acknowledgement")
                return False
        else:
            return False

    def _send_digital_id_txn(self, action, id_to_send=None, dependency_txns=None, state_address_list=None,
                             owner_signature=None, owner_info=None):
        LOGGER.debug("inside UserWalletClient._send_digital_id_txn")
        # Generate payload as digital_id protobuf encoded string
        digital_id_transaction = DigitalIdTransaction()
        digital_id_msg = digital_id_pb2.DigitalId()

        # TODO test change of code
        # if action != "ack_invalidation" and self._digital_id_msg is not None:
        #     digital_id_msg.CopyFrom(self._digital_id_msg)
        # elif action == "ack_invalidation" and id_to_send is not None:
        #     digital_id_msg.CopyFrom(id_to_send)

        # dynamically setting digital_id_msg depending on if id_to_send parameter is set
        # if action not in ["ack_invalidation"]:
        if id_to_send is None and self._digital_id_msg is not None:
            digital_id_msg.CopyFrom(self._digital_id_msg)
        elif id_to_send is not None and action not in ["ack_invalidation"]:
            # 'ack_invalidation' sends serialized form of digital_id_msg which is set later in the method
            digital_id_msg.CopyFrom(id_to_send)

        # set client_info
        client_info = ClientAttributes()
        if owner_info is not None and "ack_invalidation" == action:
            client_info.CopyFrom(owner_info)
        else:
            client_info.user_address = self.public_address

        if "request_id" == action:
            # prompt for extra attributes: -- reverted back changes 18 Apr ---------
            # digital_id_msg.attribute_set.name.status = id_attribute_pb2.REQUESTED
            # digital_id_msg.attribute_set.date_of_birth.status = id_attribute_pb2.REQUESTED
            # digital_id_msg.attribute_set.address_permanent.status = id_attribute_pb2.REQUESTED
            # digital_id_msg.attribute_set.nationality.status = id_attribute_pb2.REQUESTED
            # digital_id_msg.attribute_set.gender.status = id_attribute_pb2.REQUESTED
            resp = input("Press 'Y' to include additional attributes. To ignore, press any other key: ")
            if resp.capitalize().strip() == 'Y':
                attr_list = input("Please enter additional attribute list : ")
                attr_list = attr_list.split(',')
                others_map = digital_id_msg.attribute_set.others
                for attr in attr_list:
                    LOGGER.debug("Initializing {} ".format(attr.strip()))
                    others_map.get_or_create(attr.strip())
            digital_id_msg.status = id_attribute_pb2.Status.REQUESTED
            digital_id_msg.id_owner_public_key = self.public_key
            client_info.trust_score = digital_id_constants.UNINITIATED_ID_TRUST_SCORE
            digital_id_transaction.status = id_attribute_pb2.Status.REQUESTED
            digital_id_transaction.owner_info.CopyFrom(client_info)

        if "confirm_id" == action:
            # remove: digital_id_msg = self._digital_id_msg
            if self._attribute_quorum_dict is None:
                self.get_id_quorum_state()
            # Apr 7, 2020: updated method _confirm_digital_id() to set verifier_list for each attribute
            # added parameter verification_dict to send verifier list details
            verification_dict = self.peer_verification_info['id_verification_detail']
            _confirm_digital_id(digital_id_msg, self._attribute_quorum_dict, verification_dict)
                                # self.state_info_dict['trust_score'], verification_dict)
            digital_id_transaction.status = id_attribute_pb2.Status.CONFIRMED
            client_info.trust_score = digital_id_constants.CONFIRMED_ID_TRUST_SCORE
            digital_id_transaction.peer_verification_txns.extend(self.peer_verification_info['peer_responses'])
            digital_id_transaction.owner_info.CopyFrom(client_info)

        if "update_id" == action:
            attr_names = self.select_attribute_for_update()
            _set_id_for_update(digital_id_msg, attr_names)
            LOGGER.debug("Updated field status: %s", digital_id_msg.attribute_set.name.status)
            LOGGER.debug("Old field status: %s", self._digital_id_msg.attribute_set.name.status)
            client_info.trust_score = self._id_creation_state['trust_score']
            digital_id_msg.status = id_attribute_pb2.Status.ON_UPDATE
            # TODO test : commented following line
            # digital_id_msg.id_owner_public_key = self.public_key
            digital_id_transaction.status = id_attribute_pb2.Status.ON_UPDATE
            digital_id_transaction.owner_info.CopyFrom(client_info)

        if "invalidate_id" == action:
            peer_dict = self.load_peers()
            selected_peers = select_peers(peer_dictionary=peer_dict, is_trust_based=False)
            LOGGER.debug("selected peers : {}".format(selected_peers))
            # remove digital_id_msg = self._digital_id_msg
            _invalidate_digital_id(digital_id_msg)
            digital_id_transaction.status = id_attribute_pb2.Status.INVALID
            digital_id_transaction.receiver_group.extend(selected_peers)
            client_info.trust_score = digital_id_constants.UNINITIATED_ID_TRUST_SCORE
            digital_id_transaction.owner_info.CopyFrom(client_info)

        if "ack_invalidation" == action:
            digital_id_transaction.status = id_attribute_pb2.Status.INVALID_ACK
            # client_info copied from the owner_info present in the invalidation request
            # client_info.trust_score = self._id_creation_state['trust_score']

        if "recover_id" == action:
            digital_id_msg.status = id_attribute_pb2.Status.RECOVERY_REQ
            client_info.trust_score = digital_id_constants.UNINITIATED_ID_TRUST_SCORE
            digital_id_transaction.status = id_attribute_pb2.Status.RECOVERY_REQ
            digital_id_transaction.owner_info.CopyFrom(client_info)

        # if digital_id_constants.PEER_VERIFICATION_REQUEST == action:
        #     digital_id_transaction.status = id_attribute_pb2.Status.PEER_REQUEST
        #     client_info.trust_score = self._id_creation_state['trust_score']
        #     digital_id_transaction.owner_info.CopyFrom(client_info)
        #     digital_id_transaction.receiver_group.extend(receiver_address)

        if "demote_id_strength" == action:
            digital_id_transaction.status = id_attribute_pb2.Status.VERIFIER_UPDATE
            client_info.trust_score = digital_id_constants.PRIMARY_CERTIFIED_TRUST_SCORE
            digital_id_transaction.owner_info.CopyFrom(client_info)
            if self.credibility_inc_info.get("latest_resp_txns") is not None:
                digital_id_transaction.peer_verification_txns.extend(self.credibility_inc_info["latest_resp_txns"])

        if "update_id_strength" == action:
            digital_id_transaction.status = id_attribute_pb2.Status.VERIFIER_UPDATE
            client_info.trust_score = self._id_creation_state['trust_score']
            digital_id_transaction.owner_info.CopyFrom(client_info)
            if self.credibility_inc_info.get("latest_resp_txns") is not None:
                digital_id_transaction.peer_verification_txns.extend(self.credibility_inc_info["latest_resp_txns"])

        # digital_id_transaction.owner_info.CopyFrom(client_info)

        # current_time = datetime.now()
        # TODO set new property of digital_id_msg time_stamp ?
        if action not in ["ack_invalidation"]:
            digital_id_msg.enc_code_id = random.random().hex().encode()
            digital_id_bytes = digital_id_msg.SerializeToString()
        else:
            digital_id_bytes = id_to_send

        digital_id_transaction.digital_id = digital_id_bytes

        # TODO add compression code
        # TODO code to encrypt state_data goes here
        # Changed code to sign on the hash of the digital_id_msg

        input_address_list = []
        output_address_list = []
        dependency_list = []

        if "ack_invalidation" == action:
            digital_id_transaction.owner_signature = owner_signature
            digital_id_transaction.certifier_signature = self._signer.sign(
                hashing.get_hash_from_bytes(digital_id_bytes))
            if state_address_list is not None:
                input_address_list.extend(state_address_list)
                output_address_list.extend(state_address_list)
            if dependency_txns is not None:
                dependency_list.extend(dependency_txns)
        else:
            digital_id_transaction.owner_signature = self._signer.sign(hashing.get_hash_from_bytes(digital_id_bytes))
            #  constructing the address where we'll store the digital id in state
            input_address_list.append(self._self_state_address)
            input_address_list.append(self._id_creation_address)
            output_address_list.append(self._self_state_address)
            output_address_list.append(self._id_creation_address)
            if "recover_id" == action:
                input_address_list.extend(state_address_list)
            if dependency_txns is not None:
                dependency_list.extend(dependency_txns)
            elif self._last_acting_txn_id is not "":
                dependency_list.append(self._last_acting_txn_id)

        # if action in ["request_id", "confirm_id", "update_id", "invalidate_id", "recover_id",
        #                       digital_id_constants.PEER_VERIFICATION_REQUEST]:
        # elif "ack_invalidation" == action:

        payload = digital_id_transaction.SerializeToString()
        transaction = self.txn_generator.make_transaction(family=FAMILY_NAME_DIGITALID, payload=payload,
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

        return self.txn_generator.wait_for_status(batch_id, UserWalletClient.wait_time, result)

        # return result

    def _send_peer_verification_request(self, req_list_dict, action_type):  # attribute_names
        LOGGER.debug("Inside userwallet_client._send_peer_verification_request()")
        transaction_list = []
        # db_key = "peer_requests_txns_sent"
        # txn_id_list = []
        peer_list = req_list_dict.keys()
        LOGGER.debug("peer_list {}".format(peer_list))
        timestamp = str(time.time())
        commit_flag = False
        for peer_pub_key_hash in peer_list:
            LOGGER.debug("Processing peer with address {}".format(peer_pub_key_hash))
            digital_id_msg = self._digital_id_msg
            # removal_list_str = input('Please enter list of attribute to remove: ')
            # removal_list = set(attribute_names) - set(req_list_dict.get(peer_pub_key_hash))
            # LOGGER.debug("removal_list_str {}".format(removal_list_dict))
            # LOGGER.debug("removal_list_str {}".format(removal_list))
            req_list = set(req_list_dict.get(peer_pub_key_hash))
            LOGGER.debug("req_list_str {}".format(req_list_dict.get(peer_pub_key_hash)))
            print("\nCreating peer verification request transaction for {} "
                  "with attributes {}".format(peer_pub_key_hash, req_list_dict.get(peer_pub_key_hash)))
            remark = input('\nPlease input remarks if any: ')

            # construct a new id with the attributes that need to be peer-verified
            # new_id = set_id_for_peer_verify(digital_id_msg, removal_list)
            new_id = set_id_for_peer_verify(digital_id_msg, req_list)
            digital_id_bytes = new_id.SerializeToString()
            # TODO compress and encrypt with digital_id owner's public key
            if action_type == digital_id_constants.TYPE_ID_CREATE:
                # Send all transactions as a single batch of transactions
                transaction = self.get_peer_verify_family_txn(action=digital_id_constants.PEER_VERIFICATION_REQUEST,
                                                              action_type=digital_id_constants.TYPE_ID_CREATE,
                                                              digital_id_bytes=digital_id_bytes, remark=remark,
                                                              peer_address=peer_pub_key_hash,
                                                              total_peer_request_count=len(peer_list),
                                                              timestamp=timestamp)

                # txn_id_list.append(transaction.header_signature)
                transaction_list.append(transaction)
            elif action_type == digital_id_constants.TYPE_CREDIBILITY_INC:
                dependency_txn = self._id_creation_state['user_confirmation_txn']
                # Send each transaction as a separate batch
                transaction = self.get_peer_verify_family_txn(action=digital_id_constants.PEER_VERIFICATION_REQUEST,
                                                              action_type=digital_id_constants.TYPE_CREDIBILITY_INC,
                                                              digital_id_bytes=digital_id_bytes, remark=remark,
                                                              peer_address=peer_pub_key_hash,
                                                              total_peer_request_count=1, timestamp=str(time.time()),
                                                              dependency_txn=dependency_txn)
                batch_list = self.txn_generator.make_batch(transaction_list=[transaction])
                batch_id = batch_list.batches[0].header_signature
                # Send batch_list to the REST API
                result = self.txn_generator.send_to_rest_api("batches", batch_list.SerializeToString(),
                                                             'application/octet-stream')
                LOGGER.debug("Result from rest api: {}".format(result))
                result = self.txn_generator.wait_for_status(batch_id, UserWalletClient.wait_time, result)
                LOGGER.debug(result)
                print(result)
                if result != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
                    status = yaml.safe_load(result)['data'][0]['status']
                    if status == 'COMMITTED':
                        commit_flag = True
                        print("Transaction for ID verification request to {} successfully committed".format(
                            peer_pub_key_hash))
                    else:
                        print("Failed to commit ID verification request transaction to {}".format(peer_pub_key_hash))
                else:
                    print("ID verification request transaction to {} timed out".format(peer_pub_key_hash))

        if action_type == digital_id_constants.TYPE_ID_CREATE:
            batch_list = self.txn_generator.make_batch(transaction_list=transaction_list)
            batch_id = batch_list.batches[0].header_signature
            # Send batch_list to the REST API
            result = self.txn_generator.send_to_rest_api("batches", batch_list.SerializeToString(),
                                                         'application/octet-stream')
            LOGGER.debug("Result from rest api: {}".format(result))
            return self.txn_generator.wait_for_status(batch_id, UserWalletClient.wait_time, result)
        elif action_type == digital_id_constants.TYPE_CREDIBILITY_INC:
            return commit_flag

    def _refresh_state(self):
        LOGGER.debug("Inside userwallet_client._refresh_state()")
        self.refresh_exit = False

        # call load_id_status() to set _id_status, _last_acting_txn_id, _digital_id_msg, enable_request, enable_confirm,
        # trust_score, self_verified

        self.load_id_status()

        if self.state_info_dict['enable_request'] is False:
            #  self.state_info_dict['enable_update'] is False:
            # quorum already reached or timer expired
            self.get_id_quorum_state()

        if self._id_status == id_attribute_pb2.Status.REQUESTED:
            print("Digital-ID request under processing")
        if self._id_status == id_attribute_pb2.Status.ON_UPDATE:
            print("Digital-ID update request under processing")
        if self._id_status == id_attribute_pb2.Status.CONFIRMED:
            add_verifier_flag = False
            # update_blacklist_flag = False
            LOGGER.debug("updated credibility_inc_info from state: {}".format(self.credibility_inc_info))
            if self.credibility_inc_info != {}:
                txn_response = chain_access_util.get_transaction(base_url=self.base_url,
                                                                 requesting_txn_id=self._last_acting_txn_id)
                try:
                    txn_payload = txn_response['payload']
                    digital_id_transaction = DigitalIdTransaction()
                    digital_id_transaction.ParseFromString(base64.b64decode(txn_payload))
                    peer_verification_txns = digital_id_transaction.peer_verification_txns
                    if set(self.credibility_inc_info['latest_resp_txns']).isdisjoint(set(peer_verification_txns)):
                        add_verifier_flag = True
                    LOGGER.debug("add_verifier_flag {}".format(add_verifier_flag))
                except BaseException as err:
                    LOGGER.error("Error while reading transaction data {}".format(err))
                    raise Exception("Error while reading transaction data {}".format(err))

            # Apr 4, 2020: update self.black-list if needed
            LOGGER.debug("self.black_list before update: {}".format(self.black_list))
            # registry_db = db.DB()
            # registry_db.open(self.registry_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
            # if registry_db.get('black_list'.encode()) is not None:
            #     black_list_frm_db = cbor.loads(registry_db.get('black_list'.encode()))
            #     LOGGER.debug("black_list_frm_db : {}".format(black_list_frm_db))
            #     if len(set(black_list_frm_db).difference(set(self.black_list))) > 0:
            #         update_blacklist_flag = True
            #     self.black_list = black_list_frm_db
            # LOGGER.debug("update_blacklist_flag : {}".format(update_blacklist_flag))
            LOGGER.debug("add_verifier_flag : {}".format(add_verifier_flag))

            if self.update_blacklist_flag is True or add_verifier_flag is True:
                # checking if any of the ID-verifiers is blacklisted
                result = self.update_id_verifiers(add_verifier_flag)
                if result is False:
                    print("Could not send transaction to update ID verifiers.")
                    print("Please retry")

            self.save_ack_receipt()

            if self._id_finalized:   # added 2nd Jul, 2020
                print("\nDigital-ID is confirmed and acknowledged. No action required.\n")

        # call get_id_quorum_state() to set peer_verification_request_sent, peer_quorum_reached, _quorum_dependency,
        # peer_response_awaiting
        # TODO if self.state_info_dict[invalidation_req_sent] is True and invalidation attempt unsuccessful reset here
        # TODO else don't allow other operations
        # if self.state_info_dict['enable_request'] is False or \
        #         self.state_info_dict['enable_update'] is False:  # quorum already reached or timer expired
        #     self.get_id_quorum_state()

        LOGGER.debug("updated state_info_dict from state: {}".format(self.state_info_dict))
        LOGGER.debug("updated peer_verification_info from state: {}".format(self.peer_verification_info))

        if self._id_status == id_attribute_pb2.Status.ON_VERIFICATION:
            self._update_state_vars()
        else:
            # self.state_info_dict['self_verified'] = True
            self.state_info_dict['enable_peer_verify'] = False
            self.state_info_dict['enable_confirm'] = False

        if (self._id_status == id_attribute_pb2.Status.ON_VERIFICATION and self.state_info_dict[
            'self_verified'] is False and self.state_info_dict['peer_verification_request_sent'] is False) \
                or (self._id_status == id_attribute_pb2.Status.CONFIRMED and
                    self._id_finalized is True):
            self.state_info_dict['enable_update'] = True
        else:  # if self._id_status == id_attribute_pb2.Status.INVALID or id_attribute_pb2.Status.ON_REQUEST or 'any
            # other cases'
            self.state_info_dict['enable_update'] = False

        # print("\nTrust-score of address {} is : {}\n".format(self.public_address, self.state_info_dict[
        # 'trust_score']))

        user_wallet_db = db.DB()
        user_wallet_db.open(self.user_db_file, None, db.DB_HASH, db.DB_CREATE)
        user_wallet_db.put('peer_request_timer_end'.encode(), cbor.dumps(self.peer_timer_end))
        user_wallet_db.put('state_info'.encode(), cbor.dumps(self.state_info_dict))
        user_wallet_db.put('peer_verification_info'.encode(), cbor.dumps(self.peer_verification_info))
        user_wallet_db.put('black_list'.encode(), cbor.dumps(self.black_list))
        user_wallet_db.close()
        self.refresh_exit = True

    def _update_state_vars(self):
        # --TODO check is put before calling the method --
        #  if self._id_status == id_attribute_pb2.Status.ON_VERIFICATION:
        curtime = time.time()
        # if self.state_info_dict['finalized_id_present'] is True:  # indicates an update flow
        if self.state_info_dict['on_update'] is False and \
                self.state_info_dict['peer_quorum_reached'] is True and self.state_info_dict['self_verified'] is False:
            self.state_info_dict['on_update'] = True
            LOGGER.debug("'on_update' set to True")
        LOGGER.debug("value of 'on_update' {}".format(self.state_info_dict['on_update']))

        # relocated code segment: 30 Apr, 2020
        if self.state_info_dict['peer_quorum_reached'] is False or \
                self.state_info_dict['on_update']:
            if self.state_info_dict['peer_verification_request_sent'] is False:
                if self.state_info_dict['peer_quorum_reached'] is False or \
                        self.state_info_dict['on_update']:
                    # if the ON_VERIFICATION ID is self-verified, go for peer verification
                    # print("Please peer_verify your Digital-ID.")
                    print("Peer_verification of Digital-ID pending.\n")
                    if self.state_info_dict['self_verified'] is True:
                        self.state_info_dict['enable_peer_verify'] = True
                    else:
                        self.state_info_dict['enable_peer_verify'] = False
            elif self.state_info_dict['peer_verification_request_sent'] is True:
                self.state_info_dict['enable_peer_verify'] = False
                if self.state_info_dict['on_update']:
                    self.state_info_dict['on_update'] = False
                    LOGGER.debug("'on_update' set to False")
        if self.state_info_dict['peer_quorum_reached'] is False and \
                self.state_info_dict['on_update'] is False and \
                self.state_info_dict['peer_verification_request_sent'] is True:

            # if self.state_info_dict['peer_verification_request_sent'] is False:
            #
            #     # if the ON_VERIFICATION ID is self-verified, go for peer verification
            #     print("Please peer_verify your Digital-ID.")
            #     if self.state_info_dict['self_verified'] is True:
            #         self.state_info_dict['enable_peer_verify'] = True
            #     else:
            #         self.state_info_dict['enable_peer_verify'] = False

            # if self.state_info_dict['peer_verification_request_sent'] is True:
            # self.state_info_dict['enable_peer_verify'] = False
            # if self.state_info_dict['on_update']:
            #     self.state_info_dict['on_update'] = False
            #     LOGGER.debug("'on_update' set to False")

            # wait for responses to come if there is pending request
            if self.state_info_dict['peer_response_awaiting'] is False:
                # cause of failure can be checked here.
                print('ID could not be verified by peers. Please recheck details')
                self.state_info_dict['enable_update'] = True
                # update flow
                resp = input("Press 'Y' to update ID attributes. To ignore, press any key.")
                if resp.capitalize().strip() == 'Y':
                    self.do_update_id()
                # k = 1 # k is number of attempts
                # trust_score = trust_score - pow(2, k) * digital_id_constants.PEER_VERIFICATION_REWARD

            elif self.state_info_dict['peer_response_awaiting'] is True:
                if self.peer_timer_end < curtime:
                    print("\nTimer expired. ID could not be peer-verified.")
                    # self.peer_timer_end = 0
                    self.state_info_dict['self_verified'] = False
                    # TODO set false ?
                    self.state_info_dict['enable_peer_verify'] = True
                else:
                    print('Peer verification request sent.')
                    print('Peer response awaited. Please recheck later.')
                # TODO wait for some time and recheck. set timer logic

        elif self.state_info_dict['peer_quorum_reached'] is True and \
                self.state_info_dict['on_update'] is False:
            print("Your ID successfully peer verified. Please send confirmation.")
            # self.peer_timer_end = 0
            self.state_info_dict['self_verified'] = True
            self.state_info_dict['enable_peer_verify'] = False
            self.state_info_dict['enable_confirm'] = True

    def do_request_id_share(self, to_address, data_mode=False):
        LOGGER.debug("Inside do_request_id_share()")
        if self.command == 'id_wallet' and self.refresh_exit:
            self._refresh_state()
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

    def do_respond_id_share(self, to_address, txn_id):
        LOGGER.debug("Inside do_respond_id_share()")
        if self.command == 'id_wallet' and self.refresh_exit:
            self._refresh_state()
        # get self-state to obtain current id, check validity of the stored id
        self_state_data = chain_access_util.get_state(base_url=self.base_url, address=self._self_state_address)
        if self_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            print("A Shareable Digital-ID does not exist.")
            return False
        else:
            digital_id_bytes = self_state_data['digital_id']
            digital_id = digital_id_pb2.DigitalId()
            digital_id.ParseFromString(digital_id_bytes)
            if digital_id.status == id_attribute_pb2.Status.CONFIRMED \
                    and self_state_data['ack_number'] is not None \
                    and self_state_data['trust_score'] == digital_id_constants.CONFIRMED_ID_TRUST_SCORE:
                # match to_address with the sender of txn_id. and verify its certificate (optional)
                txn_response = chain_access_util.get_transaction(base_url=self.base_url, requesting_txn_id=txn_id)
                try:
                    txn_header = txn_response['header']
                    id_owner_pub_key = txn_header['signer_public_key']
                    requester_address = hashing.get_pub_key_hash(id_owner_pub_key)
                    if requester_address != to_address:
                        print("Invalid requesting address")
                        return False

                    txn_payload = txn_response['payload']
                    shared_id_transaction = shared_id_pb2.ShareIDTransaction()
                    shared_id_transaction.ParseFromString(base64.b64decode(txn_payload))
                    action = shared_id_transaction.action
                    if action != digital_id_constants.SHARE_ID_REQUEST:
                        print("Invalid Transaction For ID Share Request.")
                        return False
                    req_payload = shared_id_transaction.payload
                    id_request = shared_id_pb2.ShareIdRequest()
                    id_request.ParseFromString(req_payload)
                    data_mode_flag = id_request.ID_data_requested
                    if data_mode_flag:
                        # display contract
                        print('\nDetails of data contract sent in the message:\n')
                        contract_bytes = id_request.contract_detail
                        contract_msg = shared_id_pb2.contract()
                        if contract_bytes is not None and contract_bytes != b'':
                            contract_msg.ParseFromString(contract_bytes)
                            attr_set_msg = contract_msg.attribute_set
                            attr_list = attr_set_msg.ListFields()
                            for attribute_field in attr_list:
                                if attribute_field[0].name != 'others':
                                    field_name = attribute_field[0].name
                                    field_value = attribute_field[1]
                                    print("\nField name {}: \n".format(field_name.capitalize()))
                                    print("Status: {}".format(STATUS_ENUM[field_value.status]))
                                else:
                                    attr_map = attribute_field[1]
                                    for field_name in attr_map:
                                        # field_name is the key
                                        field_value = attr_map[field_name]
                                        print("\nField name : {}\n".format(field_name.capitalize()))
                                        print("Status: {}".format(STATUS_ENUM[field_value.status]))
                            print("\nContract validity : {} year".format(contract_msg.validity_in_years))
                            print("\nContract create_timestamp : {}".format(contract_msg.create_timestamp))
                        else:
                            print('No contract is sent in the ID request message')
                    recv_from_address = id_request.recv_id_from_address
                    if recv_from_address != self.public_address:
                        print("Invalid Transaction ID. Not the intended receiver.")
                except BaseException as err:
                    LOGGER.error("Error while reading transaction data {}".format(err))
                    raise Exception("Error while reading transaction data")
                sharing_obj = DigitalIdSharingClass(base_url=self.base_url,
                                                    signer=self._signer,
                                                    public_key=self.public_key,
                                                    to_address=to_address)
                sharing_obj.send_id_response(data_mode=data_mode_flag)

            else:
                print("A Digital-ID does not exist.")
                return False

    def show_share_response(self, receiver_address, resp_txn):
        if self.command == 'id_wallet' and self.refresh_exit:
            self._refresh_state()
        txn_response = chain_access_util.get_transaction(base_url=self.base_url, requesting_txn_id=resp_txn)
        sharing_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_SHAREDID,
                                                              pub_key_hash=receiver_address,
                                                              key=self.public_address)
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

    def select_attribute_for_update(self):
        LOGGER.debug("Inside method select_attribute_for_update()")
        attribute_names = []
        attribute_set_msg = self._digital_id_msg.attribute_set
        attribute_fields = attribute_set_msg.ListFields()
        # initialized_fields = [x[0].name for x in attribute_fields]
        # uninitialized_mandatory_field = {"name", "date_of_birth", "address_permanent", "nationality", "gender"} \
        #                                 - set(initialized_fields)
        # attribute_names.extend(uninitialized_mandatory_field)

        for attribute_field in attribute_fields:
            if attribute_field[0].name != 'others':
                # if field value status is not
                if attribute_field[1].status != id_attribute_pb2.Status.ON_UPDATE:
                    field_name = attribute_field[0].name
                    attribute_names.append(field_name.capitalize().strip())
            else:
                attr_map = attribute_field[1]
                for field_name in attr_map:
                    # field_name is the key
                    if attr_map[field_name].status != id_attribute_pb2.Status.ON_UPDATE:
                        attribute_names.append(field_name.capitalize().strip())

        print("Select attributes from {}".format(attribute_names))
        # take input from users and put inside a select_peers dictionary

        attr_names = input("Enter the list of attributes to update: ")
        LOGGER.debug("Selected attributes: {}".format(attr_names))
        attr_names = attr_names.split(",")
        attr_names = [x.strip().capitalize() for x in attr_names]
        LOGGER.debug("Selected attributes for update {} ".format(attr_names))
        return attr_names

    def add_verifier(self):
        LOGGER.debug("Inside userwallet_client.add_verifier")

        if self.command == 'id_wallet' and self.refresh_exit:
            self._refresh_state()

        if self._id_status == id_attribute_pb2.Status.CONFIRMED:
            LOGGER.debug("\nDigital ID details are confirmed.\n")
            peer_dict = self.load_peers()
            req_list_dict = {}
            attribute_set_msg = self._digital_id_msg.attribute_set
            attribute_fields = attribute_set_msg.ListFields()
            attribute_names = []
            for attribute_field in attribute_fields:
                if attribute_field[0].name != 'others':
                    attribute_names.append(attribute_field[0].name)
                    if attribute_field[1].status == id_attribute_pb2.Status.CONFIRMED:
                        field_name = attribute_field[0].name
                        print("\nField Name : {}".format(field_name.capitalize()))
                        print(
                            "\nExisting credibility_strength : {}".format(attribute_field[1].credibility_strength))
                        if attribute_field[1].credibility_strength < digital_id_constants.MAX_ATTRIBUTE_STRENGTH:
                            resp = input("\nSend additional attestation request? Y/N: ")
                            if resp.capitalize().strip() == 'Y':
                                verifier_list = attribute_field[1].verifier_list
                                LOGGER.debug("verifier_list {}".format(verifier_list))
                                # existing_peers = []
                                temp_dict = dict.copy(peer_dict)
                                for verifier in verifier_list:
                                    verifier_client_info = client_pb2.ClientAttributes()
                                    verifier_client_info.ParseFromString(verifier)
                                    # existing_peers.append(verifier_client_info.user_address)
                                    existing_peer = verifier_client_info.user_address
                                    LOGGER.debug("existing peer {}".format(existing_peer))
                                    # eliminate existing peers from temp_dict
                                    if existing_peer in temp_dict.keys():
                                        temp_dict.pop(existing_peer)

                                # existing_peers = [x.user_address for x in verifier_list]
                                # populate permissible peer list for verifying the attribute
                                # by eliminating the existing verifier peers

                                # for peer in peer_dict.keys():
                                #     if peer in existing_peers:
                                #         temp_dict.pop(peer)

                                if len(temp_dict.keys()) != 0:
                                    print("\nSelect peers to vote for {}".format(field_name.capitalize()))
                                    selected_peers = select_peers(peer_dictionary=temp_dict, is_trust_based=False,
                                                                  is_vote_based=False)
                                    for peer in selected_peers:
                                        if req_list_dict.get(peer) is None:
                                            req_list_dict[peer] = [field_name]
                                        else:
                                            req_list_dict.get(peer).append(field_name)
                                else:
                                    print("No new peer available in your peer list.")
                else:
                    attr_map = attribute_field[1]
                    for field_name in attr_map:
                        # field_name is the key
                        attribute_names.append(field_name)
                        if attr_map[field_name].status == id_attribute_pb2.Status.CONFIRMED:
                            print("\nField Name : {}".format(field_name.capitalize()))
                            print("\nExisting credibility_strength : {}".format(
                                attr_map[field_name].credibility_strength))
                            if attr_map[field_name].credibility_strength < digital_id_constants.MAX_ATTRIBUTE_STRENGTH:
                                resp = input("\nSend additional attestation request? Y/N: ")
                                if resp.capitalize().strip() == 'Y':
                                    verifier_list = attr_map[field_name].verifier_list
                                    LOGGER.debug("verifier_list {}".format(verifier_list))
                                    temp_dict = dict.copy(peer_dict)
                                    # existing_peers = []
                                    for verifier in verifier_list:
                                        verifier_client_info = client_pb2.ClientAttributes()
                                        verifier_client_info.ParseFromString(verifier)
                                        # existing_peers.append(verifier_client_info.user_address)
                                        existing_peer = verifier_client_info.user_address
                                        LOGGER.debug("existing peer {}".format(existing_peer))
                                        # eliminate existing peers from temp_dict
                                        if existing_peer in temp_dict.keys():
                                            temp_dict.pop(existing_peer)

                                    # existing_peers = [x.user_address for x in verifier_list]
                                    # populate permissible peer list for verifying the attribute
                                    # temp_dict = dict.copy(peer_dict)
                                    # for peer in peer_dict.keys():
                                    #     if peer in existing_peers:
                                    #         temp_dict.pop(peer)

                                    if len(temp_dict.keys()) != 0:
                                        print("\nSelect peers to vote for {}".format(field_name.capitalize()))
                                        selected_peers = select_peers(peer_dictionary=temp_dict, is_trust_based=False,
                                                                      is_vote_based=False)
                                        for peer in selected_peers:
                                            if req_list_dict.get(peer) is None:
                                                req_list_dict[peer] = [field_name]
                                            else:
                                                req_list_dict.get(peer).append(field_name)
                                    else:
                                        print("No new peer available in your peer list.")
                                else:
                                    continue

            # send peer verification request to all the selected peers
            LOGGER.debug("\nreq_list_dict {}\n".format(req_list_dict))
            result = self._send_peer_verification_request(req_list_dict=req_list_dict,
                                                          # attribute_names=attribute_names,
                                                          action_type=digital_id_constants.TYPE_CREDIBILITY_INC)
            if result is True:
                user_wallet_db = db.DB()
                user_wallet_db.open(self.user_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
                user_wallet_db.put('state_info'.encode(), cbor.dumps(self.state_info_dict))
                user_wallet_db.put('peer_verification_info'.encode(), cbor.dumps(self.peer_verification_info))
                user_wallet_db.close()
                return True
            else:
                return False

    def get_peer_verify_family_txn(self, action, action_type, digital_id_bytes, remark, peer_address,
                                   total_peer_request_count, timestamp, dependency_txn=None):
        # send new_id to peers. construct peer_verification_request message
        # construct peer verification request
        if action == digital_id_constants.PEER_VERIFICATION_REQUEST:
            peer_verification_request = peer_verification_pb2.PeerVerificationRequest()
            peer_verification_request.digital_id = digital_id_bytes
            peer_verification_request.owner_signature = self._signer.sign(hashing.get_hash_from_bytes(digital_id_bytes))
            peer_verification_request.remark = remark
            peer_verification_request.peer_address = peer_address
            peer_verification_request.create_timestamp = str(timestamp)
            peer_verification_payload = peer_verification_request.SerializeToString()

            peer_verification_transaction = peer_verification_pb2.PeerVerificationTransaction()
            peer_verification_transaction.payload = peer_verification_payload
            peer_verification_transaction.action = digital_id_constants.PEER_VERIFICATION_REQUEST
            # Apr 8, 2020: type field added
            peer_verification_transaction.type = action_type
            peer_verification_transaction.total_peer_request_count = total_peer_request_count
            txn_payload = peer_verification_transaction.SerializeToString()

            # set dependency transaction
            dependencies = []
            if dependency_txn is None:
                dependencies.append(self._last_acting_txn_id)
            else:
                dependencies.append(dependency_txn)

            # set input and output address

            # peer address: FAMILY_NAME_PEER_VERIFY[0:6] + send_from_pub_key_hash [

            input_address_list = [self._self_state_address, self._quorum_address]
            output_address_list = [self._quorum_address]
            transaction = self.txn_generator.make_transaction(family=FAMILY_NAME_PEER_VERIFY,
                                                              payload=txn_payload,
                                                              input_address_list=input_address_list,
                                                              output_address_list=output_address_list,
                                                              dependency_list=dependencies)
            return transaction

