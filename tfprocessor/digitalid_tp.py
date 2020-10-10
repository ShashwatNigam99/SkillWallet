#!/usr/bin/env python3

"""
DigitalIdTransactionHandler class interfaces for digitalid Transaction Family.

"""
import argparse
import base64
import logging
import math
import os
import sys
import traceback
import cbor
from sys import path

from colorlog import ColoredFormatter
from sawtooth_sdk.processor.core import TransactionProcessor
from sawtooth_sdk.processor.exceptions import InternalError
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_signing import create_context
from sawtooth_signing.secp256k1 import Secp256k1PublicKey

# home = os.path.expanduser("~")
# proj_dir = os.path.join(home, "digital-id")
# path.append(proj_dir)

path.append(os.getcwd())
from constants import digital_id_constants
from protobuf import digital_id_transaction_pb2, digital_id_pb2, id_attribute_pb2, client_pb2
from util import chain_access_util, hashing

DEFAULT_VALIDATOR_URL = 'tcp://localhost:4004'
DEFAULT_REST_API_URL = 'http://localhost:8008'

LOGGER = logging.getLogger('digitalid_tp')
LOGGER.setLevel(logging.INFO)  # Default log level if setup_logger not used

FAMILY_NAME_DIGITALID = "digitalid"
FAMILY_NAME_CERTIFY = "digitalid_certifier"
FAMILY_NAME_PEER_VERIFY = "peer_verification"
FAMILY_NAME_DIGITALID_CLIENT = 'digitalid_client_info'


def _get_public_key_file(key_file_name):
    """Get the private key from key_file_name."""
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")
    return '{}/{}.pub'.format(key_dir, key_file_name)


def _read_certifier_config():
    pwd = os.path.expanduser(".")
    config_dir = os.path.join(pwd, "tfprocessor")
    config_file = '{}/{}'.format(config_dir, digital_id_constants.CERTIFIER_CONFIG_FILE)
    certifier_dict = {}
    try:
        with open(config_file) as fd:
            for line in fd:
                line = line.strip()
                if line.startswith('#') or line == '':
                    continue
                (key, value) = line.split(': ')
                # value has file name in the form 'certifier.pub'
                # read public key from 'certifier.pub'
                key_file = _get_public_key_file(value)
                try:
                    with open(key_file) as fd:
                        pub_key_str = fd.read().strip()
                except OSError as err:
                    raise Exception('Failed to read public key {}: {}'.format(key_file, str(err)))

                # setting pub_key_str in certifier_dict
                certifier_dict[key] = pub_key_str
                # certifier_dict[key] = value.strip()
    except OSError as err:
        raise Exception('Failed to read certifier config file {}: {}'.format(config_file, str(err)))
    if certifier_dict.get('primary_certifier_pubkey') is None:
        raise Exception("Invalid certifier configuration: 'primary_certifier_pubkey' not set")
    LOGGER.debug("primary_certifier_pubkey : {}".format(certifier_dict.get('primary_certifier_pubkey')))
    return certifier_dict


def _verify_digital_id_txn(digital_id_transaction):
    LOGGER.debug("Inside _verify_digital_id_txn")
    flag = True
    attribute_fields = digital_id_transaction.ListFields()
    for attr in attribute_fields:
        print('Field name : {}'.format(attr[0].name))
        print('value : {}'.format(attr[1]))
    try:
        if digital_id_transaction.digital_id is b'':
            flag = False
            LOGGER.error("digital_id_transaction.digital_id is 0")
        # TODO check
        if digital_id_transaction.owner_signature is "" and digital_id_transaction.certifier_signature is "":
            flag = False
            LOGGER.error("Both digital_id_transaction.owner_signature "
                         "and digital_id_transaction.certifier_signature is empty")

        if digital_id_transaction.status == 0:
            flag = False
            LOGGER.error("digital_id_transaction.status is empty")
            LOGGER.debug("Flag value: {}".format(flag))
        if flag is False:
            LOGGER.error("Invalid digital_id_transaction")
            raise InvalidTransaction("Invalid digital_id_transaction")
    except AttributeError:
        raise InvalidTransaction("Invalid message structure for DigitalIdTransaction")


def _verify_message_signature(digital_id_byte, owner_sig_str, signer_pub_key_hex):
    LOGGER.debug("Inside _verify_message_signature")
    signer_pub_key = Secp256k1PublicKey.from_hex(signer_pub_key_hex)
    context_obj = create_context('secp256k1')
    digital_id_hash = hashing.get_hash_from_bytes(digital_id_byte)
    result = context_obj.verify(owner_sig_str, digital_id_hash, signer_pub_key)
    return result


def create_console_handler(verbose_level=0):
    """Setup console logging."""
    clog = logging.StreamHandler()
    formatter = ColoredFormatter(
        "%(log_color)s[%(asctime)s %(levelname)-8s%(module)s]%(reset)s "
        "%(white)s%(message)s",
        datefmt="%H:%M:%S",
        reset=True,
        log_colors={
            'DEBUG': 'cyan',  # 3
            'INFO': 'green',  # 2
            'WARNING': 'yellow',  # 1
            'ERROR': 'red',  # 0
            'CRITICAL': 'red',  # 0
        })

    clog.setFormatter(formatter)
    # set level according to verbose_level
    if verbose_level == 0:
        clog.setLevel(logging.CRITICAL)
        clog.setLevel(logging.ERROR)
    elif verbose_level == 1:
        clog.setLevel(logging.WARNING)
    elif verbose_level == 2:
        clog.setLevel(logging.INFO)
    elif verbose_level == 3:
        clog.setLevel(logging.DEBUG)

    # clog.setLevel(logging.DEBUG)
    return clog


def create_file_handler():
    # configure logger
    file_handler = logging.FileHandler('digitalid_tp.log')
    file_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    return file_handler


def setup_loggers(verbose_level=0):
    """Setup logging."""
    # logger = logging.getLogger()
    # LOGGER.setLevel(logging.DEBUG)
    if verbose_level == 0:
        LOGGER.setLevel(logging.CRITICAL)
        LOGGER.setLevel(logging.ERROR)
    elif verbose_level == 1:
        LOGGER.setLevel(logging.WARNING)
    elif verbose_level == 2:
        LOGGER.setLevel(logging.INFO)
    elif verbose_level == 3:
        LOGGER.setLevel(logging.DEBUG)
    LOGGER.addHandler(create_console_handler(verbose_level))
    LOGGER.addHandler(create_file_handler())


def verify_with_prev_id(operation_type, quorum_map, field_name, field_value, prev_field_value, verification_dict=None):
    flag = True
    min_peer_vote_req = math.floor(2 * digital_id_constants.MIN_PEER_COUNT / 3) + 1
    min_target_peer_quorum = (min_peer_vote_req - 1) * digital_id_constants.MAX_CLIENT_TRUST_SCORE
    if prev_field_value.certificate != field_value.certificate:
        LOGGER.debug("certificate in transaction does not match with stored certificate")
        flag = False
    if prev_field_value.attribute_data_enc != field_value.attribute_data_enc:
        LOGGER.debug("attribute_data_enc in transaction does not match with stored attribute_data_enc")
        flag = False
    if operation_type == 'confirm_id':
        if field_value.status != id_attribute_pb2.Status.CONFIRMED:
            flag = False
            LOGGER.debug("Attribute {} is not confirmed".format(field_name))
        # else: 27 Apr changes
        elif prev_field_value.status == id_attribute_pb2.ON_VERIFICATION:
            if quorum_map is not None and quorum_map.get(field_name) is None:
                LOGGER.debug(
                    "{} is not peer verified".format(field_name))
                flag = False
            # if verification_dict.get(field_name) is None:
            #     LOGGER.debug(
            #         "Verifier list not found for {}".format(field_name))
            #     flag = False
            else:
                try:
                    if prev_field_value.verifier_list is not None:

                        try:
                            LOGGER.debug("previous verifier list {}".format(prev_field_value.verifier_list))
                            added_verifiers = set(field_value.verifier_list) - set(prev_field_value.verifier_list)
                            LOGGER.debug("added_verifiers {}".format(added_verifiers))
                            if len(added_verifiers) != 0 and\
                                    (not set(added_verifiers).issubset(set(verification_dict.get(field_name)))):
                                LOGGER.debug(
                                    "Added Verifier list of {} is not matching with the quorum state data: {}".
                                        format(field_name, verification_dict.get(added_verifiers)))
                                flag = False
                        except AttributeError as err:
                            LOGGER.debug("Attribute error {}".format(err))
                            flag = False
                        except BaseException as err:
                            LOGGER.debug("Exception caught {}".format(err))
                            flag = False

                    elif not (set(field_value.verifier_list).issubset(set(verification_dict.get(field_name)))):
                        LOGGER.debug("verifier list not set in the previous ID")
                        LOGGER.debug(
                            "Verifier list of {} is not matching with the quorum state data: {}".
                                format(field_name, verification_dict.get(field_name)))
                        flag = False
                    else:  # check crediblity_strength value
                        # cred_score = sum([verifier.trust_score for verifier in attribute_field[1].verifier_list])
                        cred_score = 0

                        for verifier in field_value.verifier_list:
                            client_info_msg = client_pb2.ClientAttributes()
                            client_info_msg.ParseFromString(verifier)
                            cred_score = cred_score + client_info_msg.trust_score

                        if cred_score != field_value.credibility_strength:
                            LOGGER.debug(
                                "calculated credibility_strength of {} is not matching with credibility_strength "
                                "in ID".format(field_name))
                            LOGGER.debug("Calculated strength {}".format(cred_score))
                            LOGGER.debug(
                                "credibility_strength in ID {}".format(field_value.credibility_strength))
                            flag = False
                        if min_target_peer_quorum > field_value.credibility_strength:
                            LOGGER.debug("credibility_strength is less than expected minimum of {}. "
                                         "for CONFIRMED attribute {}".
                                         format(min_target_peer_quorum, field_name))
                            flag = False
                except BaseException as err:
                    LOGGER.debug("Exception caught {}".format(err))
                    flag = False

    elif operation_type == 'demote_id':
        # if quorum_map is not None and quorum_map.get(field_name) is None:
        #     LOGGER.debug(
        #         "{} is not peer verified".format(field_name))
        #     flag = False
        if prev_field_value.verifier_list is None:
            LOGGER.debug("verifier list not set in the previous ID")
            flag = False
        else:
            LOGGER.debug("previous verifier list {}".format(prev_field_value.verifier_list))
            if not set(field_value.verifier_list).issubset(set(prev_field_value.verifier_list)):
                LOGGER.debug(
                    "Verifier list of {} is not a subset of stored ID verifier_list: {}".
                        format(field_name, prev_field_value.verifier_list))
                flag = False
            elif min_target_peer_quorum > field_value.credibility_strength and \
                    field_value.status != id_attribute_pb2.ON_VERIFICATION:
                LOGGER.debug("credibility_strength is less than expected minimum of {} "
                             "for CONFIRMED attribute {}".
                             format(min_target_peer_quorum, field_name))
                flag = False
            if min_target_peer_quorum < field_value.credibility_strength and \
                    field_value.status != id_attribute_pb2.CONFIRMED:
                LOGGER.debug("credibility_strength is exceeds than expected minimum of {}. "
                             "Invalid status for attribute {}".
                             format(min_target_peer_quorum, field_name))
                flag = False

    return flag


def _verify_digital_id(prev_id, cur_id, operation_type, verification_dict=None, quorum_map=None):
    flag = True
    if prev_id.id_owner_public_key != cur_id.id_owner_public_key:
        LOGGER.debug("id_owner_public_key in transaction does not match with stored id_owner_public_key")
        LOGGER.debug("prev_id.id_owner_public_key {}".format(prev_id.id_owner_public_key))
        LOGGER.debug("cur_id.id_owner_public_key {}".format(cur_id.id_owner_public_key))
        flag = False
    if prev_id.validity_in_years != cur_id.validity_in_years:
        LOGGER.debug("validity_in_years in transaction does not match with stored validity_in_years")
        flag = False
    prev_attribute_fields = prev_id.attribute_set.ListFields()
    cur_attribute_fields = cur_id.attribute_set.ListFields()
    prev_field_names = [x[0].name for x in prev_attribute_fields]
    cur_field_names = [x[0].name for x in cur_attribute_fields]
    if set(prev_field_names) != set(cur_field_names):
        LOGGER.debug("attribute_set in transaction does not have same fields as in stored ID")
        flag = False
    else:
        for attribute_field in cur_attribute_fields:
            field_name = attribute_field[0].name
            prev_field_value = [x[1] for x in prev_attribute_fields if x[0] == attribute_field[0]][0]
            if field_name != 'others':
                LOGGER.debug("Checking field in attribute_set: %s", field_name)
                flag = verify_with_prev_id(operation_type=operation_type,
                                           quorum_map=quorum_map, field_name=field_name,
                                           field_value=attribute_field[1], prev_field_value=prev_field_value,
                                           verification_dict=verification_dict)
                LOGGER.debug("verification flag status is {} for {}".format(flag, field_name))
                if flag is False:
                    break

            elif field_name == 'others':
                attr_map = attribute_field[1]
                for key_name in attr_map:
                    LOGGER.debug("Checking field in dictionary 'others': %s", key_name)
                    prev_value = prev_field_value.get(key_name)
                    flag = verify_with_prev_id(operation_type=operation_type,
                                               quorum_map=quorum_map, field_name=key_name,
                                               field_value=attr_map[key_name], prev_field_value=prev_value,
                                               verification_dict=verification_dict)
                    LOGGER.debug("verification flag status is {} for {}".format(flag, key_name))
                    if flag is False:
                        break
    if flag is False:
        raise InvalidTransaction("Invalid Digital ID in transaction")


class DigitalIdClientTransactionHandler(TransactionHandler):
    certifier_dict = _read_certifier_config()
    primary_certifier_pubkey = certifier_dict.get('primary_certifier_pubkey')
    LOGGER.debug("primary_certifier_pubkey : {}".format(primary_certifier_pubkey))
    primary_certifier_address = hashing.get_pub_key_hash(primary_certifier_pubkey)
    LOGGER.debug("primary_certifier_address: {}".format(primary_certifier_address))
    rest_api_url = None
    LOGGER.debug("rest_api_url {}".format(rest_api_url))

    def __init__(self, namespace_prefix):
        self._namespace_prefix = namespace_prefix

    @property
    def family_name(self):
        """Return Transaction Family name string."""
        return FAMILY_NAME_DIGITALID_CLIENT

    @property
    def family_versions(self):
        """Return Transaction Family version string."""
        return ['1.0']

    @property
    def namespaces(self):
        """Return Transaction Family namespace 6-character prefix."""
        return self._namespace_prefix

    def apply(self, transaction, context):
        LOGGER.debug("Inside apply()")
        header = transaction.header

        if len(header.outputs) == 0:
            raise InvalidTransaction("Invalid transaction output list")

        if len(header.inputs) == 0:
            raise InvalidTransaction("Invalid transaction input list")

        signer_pub_key_hex = header.signer_public_key
        public_address = hashing.get_pub_key_hash(signer_pub_key_hex)
        payload = transaction.payload

        try:
            state_update_transaction = client_pb2.StateUpdateTransaction()
            state_update_transaction.ParseFromString(payload)
            action = state_update_transaction.action
            # if state_update_transaction.HasField('data'):
            txn_data = state_update_transaction.data

        except BaseException as err:
            raise Exception(err)

        if action == digital_id_constants.UPDATE_STATE_ACK:

            # to_address = header.outputs[0]
            # if len(header.outputs) == 2:
            #     quorum_address = header.outputs[1]
            # LOGGER.debug("quorum_address {}".format(quorum_address))
            from_address = header.inputs[0]
            if len(header.dependencies) != 1:
                raise InvalidTransaction("Invalid transaction dependency list")
            dependency = header.dependencies[0]
            self._update_ack(context, header.outputs, from_address, public_address, dependency, txn_data)
        else:
            raise InvalidTransaction("Operation not allowed")

    @classmethod
    def _update_ack(cls, context, to_addresses, from_address, public_address, dependency, txn_data):
        LOGGER.debug("Inside _update_ack")

        # verify the self state address
        self_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                           key='self',
                                                           pub_key_hash=public_address)

        LOGGER.debug("Self State address {}".format(self_state_address))
        id_creation_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                            key=FAMILY_NAME_CERTIFY,
                                                            pub_key_hash=public_address)
        if id_creation_address != from_address:
            LOGGER.debug("Expected id_creation_address {}".format(id_creation_address))
            raise InvalidTransaction("Invalid transaction input address")

        # if self_state_address != to_address:
        if self_state_address not in to_addresses:
            LOGGER.debug("Expected self_state_address {}".format(self_state_address))
            raise InvalidTransaction("Invalid transaction output address")

        data_dict = cbor.loads(txn_data)
        # is data_dict redundant?
        if data_dict['address'] != id_creation_address:
            raise InvalidTransaction("Invalid operation - invalid state address in data")

        # get quorum_state data, then update the quorums
        id_state_data = chain_access_util.get_state(cls.rest_api_url, id_creation_address)

        LOGGER.debug("Existing id_state_data : {}".format(id_state_data))

        if id_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            raise InvalidTransaction("ID creation state invalid")

        self_state_data = chain_access_util.get_state(cls.rest_api_url, self_state_address)

        LOGGER.debug("Existing self_state_data : {}".format(self_state_data))

        if self_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            raise InvalidTransaction("Invalid operation - self state not initiated")

        # Added changes Apr 11
        digital_id_byte = self_state_data['digital_id']
        if digital_id_byte is None or digital_id_byte == b'':
            raise InvalidTransaction("digital_id in self_state is not set")

        if dependency != id_state_data['acting_transaction_id']:
            raise InvalidTransaction("Invalid Transaction ID in dependency")

        if data_dict['transaction_id'] != id_state_data['acting_transaction_id']:
            raise InvalidTransaction("Invalid acknowledgement number in data")

        #  checking if user_confirmation_txn are same in both id_creation_state and self_state

        if self_state_data['user_confirmation_txn'] != id_state_data['user_confirmation_txn']:
            raise InvalidTransaction("Self state is not updated with the latest confirmed ID")

        txn_response = chain_access_util.get_transaction(base_url=cls.rest_api_url, requesting_txn_id=dependency)
        txn_header = txn_response['header']
        transactor_pub_key = txn_header['signer_public_key']
        LOGGER.debug("transactor_pub_key: {}".format(transactor_pub_key))
        if transactor_pub_key != cls.primary_certifier_pubkey:
            raise InvalidTransaction("The dependency transaction is not signed by primary certifier")
        LOGGER.debug("Dependency of acknowledgement transaction: {}".format(txn_header['dependencies']))
        LOGGER.debug("user_confirmation_txn: {}".format(self_state_data['user_confirmation_txn']))
        if self_state_data['user_confirmation_txn'] != txn_header['dependencies'][0]:
            raise InvalidTransaction("The acknowledgement transaction does not have a valid dependency confirmation")
        try:
            txn_payload = txn_response['payload']
            digital_id_transaction = digital_id_transaction_pb2.DigitalIdTransaction()
            digital_id_transaction.ParseFromString(base64.b64decode(txn_payload))
            _verify_digital_id_txn(digital_id_transaction)
            transaction_status = digital_id_transaction.status
            certifier_signature = digital_id_transaction.certifier_signature

            # verify if the dependency txn status ACK_CONFIRMED
            if transaction_status != id_attribute_pb2.ACK_CONFIRMED:
                raise InvalidTransaction("The dependency transaction is not a valid ID confirmation acknowledgement")

            # checking if certifier-signature can be verified with the stored data
            is_verified = _verify_message_signature(digital_id_byte, certifier_signature, transactor_pub_key)
            if is_verified == 0:
                LOGGER.error('DigitalIdTransaction.certifier_signature invalid')
                raise InvalidTransaction('DigitalIdTransaction.certifier_signature invalid')
        except BaseException as err:
            LOGGER.error("Error while reading transaction data {}".format(err))
            raise InvalidTransaction("Error while reading dependency transaction data")

        self_state_data['ack_number'] = id_state_data['acting_transaction_id']

        addresses = context.set_state({self_state_address: cbor.dumps(self_state_data)})

        if len(addresses) < 1:
            raise InternalError("State Error")
        LOGGER.debug("state updated")

        # Apr 8: removing code to delete peer_verification address

        # peer_verification_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_PEER_VERIFY,
        #                                                           pub_key_hash=public_address,
        #                                                           key=FAMILY_NAME_DIGITALID)
        # # if peer_verification_address != quorum_address:
        # if peer_verification_address not in to_addresses:
        #     LOGGER.debug("Expected peer_verification_address {}".format(peer_verification_address))
        #     raise InvalidTransaction("Invalid transaction output address")
        # addresses = context.delete_state([peer_verification_address])
        # if len(addresses) < 1:
        #     LOGGER.debug("Peer verification state could not be deleted")
        #     raise InternalError("State Deletion Error")


class DigitalIdTransactionHandler(TransactionHandler):
    """
    Transaction Processor class for the DigitalID Transaction Family.

    This TP communicates with the Validator using the accept/get/set functions.

    """
    certifier_dict = _read_certifier_config()
    primary_certifier_pubkey = certifier_dict.get('primary_certifier_pubkey')
    LOGGER.debug("primary_certifier_pubkey : {}".format(primary_certifier_pubkey))
    primary_certifier_address = hashing.get_pub_key_hash(primary_certifier_pubkey)
    LOGGER.debug("primary_certifier_address: {}".format(primary_certifier_address))
    rest_api_url = None
    LOGGER.debug("rest-api-url : {}", rest_api_url)

    def __init__(self, namespace_prefix):
        """Initialize the transaction handler class.
           This is setting the "digitalid" TF namespace prefix.
        """
        self._namespace_prefix = namespace_prefix

    @property
    def family_name(self):
        """Return Transaction Family name string."""
        return FAMILY_NAME_DIGITALID

    @property
    def family_versions(self):
        """Return Transaction Family version string."""
        return ['1.0']

    @property
    def namespaces(self):
        """Return Transaction Family namespace 6-character prefix."""
        return self._namespace_prefix

    def apply(self, transaction, context):
        """This implements the apply function for the TransactionHandler class.

           The apply function does most of the work for this class by
           processing a transaction for the digitalid transaction family.
        """

        # Get the payload
        # extract the digital id-specific information
        # verify the structure of digital-id transaction message
        header = transaction.header
        # removing the following logic. Derive the to_address based on the information available
        # we add a verification if the derived address belongs to header.outputs or not
        if len(header.inputs) == 0:
            raise InvalidTransaction("Invalid transaction input list")

        if len(header.outputs) == 0:
            raise InvalidTransaction("Invalid transaction output list")

        to_address_list = header.outputs
        LOGGER.debug("to-address: {}".format(to_address_list))

        transaction_id = transaction.signature
        LOGGER.debug("transaction id: {}".format(transaction_id))
        payload = transaction.payload
        try:
            digital_id_transaction = digital_id_transaction_pb2.DigitalIdTransaction()
            digital_id_transaction.ParseFromString(payload)
        except BaseException as err:
            raise Exception(err)

        # verify the digital_id_transaction structure
        _verify_digital_id_txn(digital_id_transaction)

        # Get the signer's public key, sent in the header from the _client.
        signer_pub_key_hex = header.signer_public_key

        digital_id_byte = digital_id_transaction.digital_id
        LOGGER.debug("digital_id_byte = %s.", digital_id_byte)

        # verify the digital_id status and owner's public key with the transaction level information
        try:
            digital_id = digital_id_pb2.DigitalId()
            # TODO de-compress digital_id_bytes
            digital_id.ParseFromString(digital_id_byte)

        except BaseException as err:
            raise Exception(err)

        # if signer_pub_key != digital_id.id_owner_public_key:
        #     raise InvalidTransaction("ID owner's public key not matching with transaction signer's")

        # retrieve owner_info
        client_info = digital_id_transaction.owner_info
        client_trust_score = client_info.trust_score
        LOGGER.debug('client_trust_score {}'.format(client_trust_score))
        status = digital_id_transaction.status

        # verify the digital id status and signatures
        if status == id_attribute_pb2.Status.INVALID_ACK:
            LOGGER.debug("digital_id.status {}".format(digital_id.status))
            if id_attribute_pb2.Status.INVALID != digital_id.status:
                raise InvalidTransaction("The digital id status is not valid for the transaction status INVALID_ACK")
            try:
                certifier_sig_str = digital_id_transaction.certifier_signature
                LOGGER.debug("certifier_signature = %s.", certifier_sig_str)
                is_verified = _verify_message_signature(digital_id_byte, certifier_sig_str, signer_pub_key_hex)
                if is_verified == 0:
                    LOGGER.error('DigitalIdTransaction.certifier_signature invalid')
                    raise InvalidTransaction('DigitalIdTransaction.owner_signature invalid')
            except AttributeError:
                raise InvalidTransaction("Invalid message structure for DigitalIdTransaction: "
                                         "certifier_signature not set")
            try:
                owner_sig_str = digital_id_transaction.owner_signature
                LOGGER.debug("owner_signature = %s.", owner_sig_str)
                is_verified = _verify_message_signature(digital_id_byte, owner_sig_str, digital_id.id_owner_public_key)
                if is_verified == 0:
                    LOGGER.error('DigitalIdTransaction.owner_signature invalid')
                    raise InvalidTransaction('DigitalIdTransaction.owner_signature invalid')

            except AttributeError:
                raise InvalidTransaction("Invalid message structure for DigitalIdTransaction: "
                                         "certifier_signature not set")
        else:
            if status != id_attribute_pb2.Status.VERIFIER_UPDATE and \
                    digital_id_transaction.status != digital_id.status:
                LOGGER.debug("digital_id.status {}".format(digital_id.status))
                raise InvalidTransaction("The digital id status is not valid for the transaction status {}".format(
                    digital_id_transaction.status))

            if status != id_attribute_pb2.RECOVERY_REQ and \
                    signer_pub_key_hex != digital_id.id_owner_public_key:
                raise InvalidTransaction("ID owner's public key not matching with transaction signer's")

            owner_sig_str = digital_id_transaction.owner_signature
            LOGGER.debug("owner_sig_str = %s.", owner_sig_str)

            # Moved the code to new method _verify_message_signature
            is_verified = _verify_message_signature(digital_id_byte, owner_sig_str, signer_pub_key_hex)
            if is_verified == 0:
                LOGGER.error('DigitalIdTransaction.owner_signature invalid')
                raise InvalidTransaction('DigitalIdTransaction.owner_signature invalid')

            # removed code to intercept digital_id_pb2.DigitalId()
            # digital_id_msg cannot be intercepted at this stage as the id
            # is encrypted

        if status == id_attribute_pb2.Status.REQUESTED:
            self._request_id(context, to_address_list, transaction_id,
                             digital_id_byte,  # owner_sig_str,
                             signer_pub_key_hex, client_trust_score)

        elif status == id_attribute_pb2.Status.ON_UPDATE:
            if len(header.dependencies) != 1:
                raise InvalidTransaction("Invalid transaction dependency list")

            dependent_txn = header.dependencies[0]
            self._update_id(context, to_address_list, transaction_id,
                            digital_id_byte,  # owner_sig_str,
                            signer_pub_key_hex, client_trust_score, dependent_txn)

        elif status == id_attribute_pb2.Status.CONFIRMED:

            if len(header.dependencies) != 1:
                raise InvalidTransaction("Invalid transaction dependency list")

            dependent_txn = header.dependencies[0]
            peer_response_txns = digital_id_transaction.peer_verification_txns
            self._confirm_id(context, to_address_list, transaction_id, digital_id_byte,  # owner_sig_str,
                             signer_pub_key_hex, client_trust_score, dependent_txn,
                             peer_response_txns)

        elif status == id_attribute_pb2.Status.VERIFIER_UPDATE:

            if len(header.dependencies) != 1:
                raise InvalidTransaction("Invalid transaction dependency list")

            dependent_txn = header.dependencies[0]
            peer_response_txns = digital_id_transaction.peer_verification_txns
            self._update_id_verifier(context, to_address_list, transaction_id, digital_id_byte,  # owner_sig_str,
                                     signer_pub_key_hex, client_trust_score, dependent_txn,
                                     peer_response_txns)

        elif status == id_attribute_pb2.Status.INVALID:
            if len(header.dependencies) != 1:
                raise InvalidTransaction("Invalid transaction dependency list")

            dependent_txn = header.dependencies[0]
            try:
                receiver_grp = digital_id_transaction.receiver_group
            except AttributeError:
                raise InvalidTransaction("Invalid message structure for DigitalIdTransaction: "
                                         "receiver_group not set")

            self._invalidate_id(context, to_address_list, transaction_id,
                                digital_id_byte, signer_pub_key_hex,
                                dependent_txn, receiver_grp)

        elif status == id_attribute_pb2.Status.INVALID_ACK:
            if len(header.dependencies) != 1:
                raise InvalidTransaction("Invalid transaction dependency list")

            dependent_txn = header.dependencies[0]

            self._invalidate_acks(context, to_address_list, transaction_id,
                                  signer_pub_key_hex, dependent_txn)

        elif status == id_attribute_pb2.Status.RECOVERY_REQ:
            if len(header.dependencies) != 1:
                raise InvalidTransaction("Invalid transaction dependency list")

            dependent_txn = header.dependencies[0]
            from_address_list = header.inputs
            self._recover_id(context, to_address_list, from_address_list, transaction_id,
                             digital_id_byte, signer_pub_key_hex, client_trust_score, dependent_txn)
        else:
            LOGGER.debug("Unhandled action. Action should be request or confirm or update")
            raise InvalidTransaction('Unhandled action: {}'.format(status))

    @classmethod
    def _request_id(cls, context, to_address_list, transaction_id, digital_id_byte,  # owner_sig_str,
                    signer_pub_key_hex, trust_score):

        LOGGER.debug("Inside _request_id method")

        # Verify if the requested address is valid for REQUEST action
        signer_pub_key_hash = hashing.get_pub_key_hash(signer_pub_key_hex)
        request_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                        pub_key_hash=signer_pub_key_hash,
                                                        key=FAMILY_NAME_CERTIFY)
        LOGGER.debug("request_address : {}".format(request_address))
        if request_address not in to_address_list:
            raise InvalidTransaction("Output Address not valid")

        # saving trust_score in state
        LOGGER.debug("trust_score : {}".format(trust_score))
        if trust_score != digital_id_constants.UNINITIATED_ID_TRUST_SCORE:
            InvalidTransaction("Invalid ID owner trust score")

        state_data = cbor.dumps({
            'digital_id': digital_id_byte,
            'acting_transaction_id': transaction_id,
            'trust_score': trust_score
        })
        LOGGER.debug("State-data : {}".format(state_data))
        addresses = context.set_state({request_address: state_data})

        if len(addresses) < 1:
            raise InternalError("State Error")
        LOGGER.debug("state updated")

        context.add_event(
            event_type='digitalid/request',
            attributes=[
                ('address', str(request_address)),
                ('signer_public_key', str(signer_pub_key_hex)),  # why send with event?
                ('transaction_id', str(transaction_id)),
                ('send_to', str(cls.primary_certifier_address))
            ]
            # data=owner_sig_str.encode('utf-8')
        )

    @classmethod
    def _update_id(cls, context, to_address_list, transaction_id, digital_id_byte,  # owner_sig_str,
                   signer_pub_key_hex, trust_score, dependency):

        LOGGER.debug("Inside _update_id method")

        # Verify if the requested address is valid for UPDATE
        signer_pub_key_hash = hashing.get_pub_key_hash(signer_pub_key_hex)
        id_creation_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                            pub_key_hash=signer_pub_key_hash,
                                                            key=FAMILY_NAME_CERTIFY)
        LOGGER.debug("id_creation_address : {}".format(id_creation_address))
        if id_creation_address not in to_address_list:
            raise InvalidTransaction("Output Address not valid")

        # get state data to validate and update
        id_state_data = chain_access_util.get_state(cls.rest_api_url, id_creation_address)

        LOGGER.debug("Existing id_state_data : {}".format(id_state_data))

        # TODO check this : if not needed we can just update the state
        if id_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            raise InvalidTransaction("ID creation state invalid")

        if dependency != id_state_data['acting_transaction_id']:
            raise InvalidTransaction("Invalid Transaction ID in dependency")

        id_state_data['digital_id'] = digital_id_byte
        id_state_data['acting_transaction_id'] = transaction_id
        id_state_data['trust_score'] = trust_score

        addresses = context.set_state({id_creation_address: cbor.dumps(id_state_data)})

        LOGGER.debug("State-data : {}".format(id_state_data))

        if len(addresses) < 1:
            raise InternalError("State Error")
        LOGGER.debug("state updated for update operation")

        context.add_event(
            event_type='digitalid/update',
            attributes=[
                ('address', str(id_creation_address)),
                ('signer_public_key', str(signer_pub_key_hex)),  # why send with event?
                ('transaction_id', str(transaction_id)),
                ('send_to', str(cls.primary_certifier_address))
            ]
        )

    @classmethod
    def _recover_id(cls, context, to_address_list, from_address_list, transaction_id, digital_id_byte,
                    signer_pub_key_hex, trust_score, dependency):

        LOGGER.debug("Inside _recover_id method")

        # check if recovery state is valid
        # Verify if the requested address is valid for RECOVER operation
        signer_pub_key_hash = hashing.get_pub_key_hash(signer_pub_key_hex)
        recovery_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                         pub_key_hash=signer_pub_key_hash,
                                                         key=FAMILY_NAME_CERTIFY)
        LOGGER.debug("recovery_address : {}".format(recovery_address))
        if recovery_address not in to_address_list:
            raise InvalidTransaction("Output Address not valid")

        # get state data to validate and update
        id_state_data = chain_access_util.get_state(cls.rest_api_url, recovery_address)

        LOGGER.debug("Existing id_state_data : {}".format(id_state_data))

        # pre-requisite for recover_id operation
        if id_state_data != digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            raise InvalidTransaction("State invalid for ID recovery")

        # check if dependency is valid
        digital_id = digital_id_pb2.DigitalId()
        digital_id.ParseFromString(digital_id_byte)
        invalidated_address = hashing.get_pub_key_hash(digital_id.id_owner_public_key)
        state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                      pub_key_hash=invalidated_address,
                                                      key=FAMILY_NAME_CERTIFY)
        if recovery_address not in from_address_list:
            raise InvalidTransaction("Input Address list not valid")
        retrieved_state_data = chain_access_util.get_state(base_url=cls.rest_api_url, address=state_address)

        if retrieved_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            print("Recovery of ID not possible - ID state of learner {} not found".format(invalidated_address))
            return None

        try:
            digital_id_data = retrieved_state_data['digital_id']
        except BaseException as err:
            LOGGER.error("Error while reading state data : {}".format(err))
            raise InvalidTransaction("Digital Id of requested profile cannot be retrieved")

        if digital_id_data is None or digital_id_data is b'':
            LOGGER.error("Invalid Digital-ID state")
            raise InvalidTransaction("Digital-ID of requested profile cannot be found")
        else:
            # check status of the retrieved digital_id_data
            retrieved_digital_id = digital_id_pb2.DigitalId()
            retrieved_digital_id.ParseFromString(digital_id_data)
            # if recovered_digital_id.status != id_attribute_pb2.Status.RECOVERY_REQ:
            if retrieved_digital_id.status != id_attribute_pb2.Status.INVALID:
                LOGGER.error("Retrieved digital ID from state of {} has non-permitted status of {}",
                             invalidated_address, retrieved_digital_id.status)
                raise InvalidTransaction("Requested profile is not invalidated yet")

        if dependency != retrieved_state_data['acting_transaction_id']:
            raise InvalidTransaction("Invalid Transaction ID in dependency")

        # -------- remove the following-----------------
        # stored_id_data = id_state_data['digital_id']
        # stored_id_msg = digital_id_pb2.DigitalId()
        # stored_id_msg.ParseFromString(stored_id_data)

        # Reset previous trust_score value to UNINITIATED_ID_TRUST_SCORE
        LOGGER.debug("trust_score : {}".format(trust_score))
        if trust_score != digital_id_constants.UNINITIATED_ID_TRUST_SCORE:
            InvalidTransaction("Invalid ID owner trust score")

        # if stored_id_msg.status != id_attribute_pb2.Status.INVALID:
        #     LOGGER.error('The stored ID has status {}'.format(stored_id_msg.status))
        #     raise InvalidTransaction("Operation not permitted. Stored ID is not invalidated.")

        id_state_data = {
            'digital_id': digital_id_byte,
            'acting_transaction_id': transaction_id,
            'trust_score': trust_score
        }

        addresses = context.set_state({recovery_address: cbor.dumps(id_state_data)})

        LOGGER.debug("State-data : {}".format(id_state_data))

        if len(addresses) < 1:
            raise InternalError("State Error")
        LOGGER.debug("state updated for recovery operation")

        context.add_event(
            event_type='digitalid/recovery',
            attributes=[
                ('address', str(recovery_address)),
                ('signer_public_key', str(signer_pub_key_hex)),  # why send with event?
                ('transaction_id', str(transaction_id)),
                ('send_to', str(cls.primary_certifier_address))
            ]
        )

    @classmethod
    def _confirm_id(cls, context, to_address_list, transaction_id, digital_id_byte,  # owner_sig_str,
                    signer_pub_key_hex, trust_score, dependent_txn, peer_response_list):

        # Verify _update_ack if the requested address is valid for confirm action
        signer_pub_key_hash = hashing.get_pub_key_hash(signer_pub_key_hex)
        request_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                        pub_key_hash=signer_pub_key_hash,
                                                        key=FAMILY_NAME_CERTIFY)
        owner_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                      pub_key_hash=signer_pub_key_hash,
                                                      key='self')
        if request_address not in to_address_list or owner_address not in to_address_list:
            raise InvalidTransaction("Output Address not valid")

        # verify validity of dependent transaction
        id_state_data = chain_access_util.get_state(cls.rest_api_url, request_address)
        LOGGER.debug("Existing ID state_data : {}".format(id_state_data))

        if id_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            LOGGER.debug("ID data does not exist at address {}".format(request_address))
            raise InvalidTransaction("ID data does not exist")

        if id_state_data['acting_transaction_id'] != dependent_txn:
            LOGGER.debug("expected dependency : {}".format(id_state_data['acting_transaction_id']))
            raise InvalidTransaction("Invalid dependency given")

        # check validity of confirmation action and the digital-id in current transaction
        prev_id = digital_id_pb2.DigitalId()
        prev_id.ParseFromString(id_state_data['digital_id'])

        cur_id = digital_id_pb2.DigitalId()
        cur_id.ParseFromString(digital_id_byte)
        # TODO
        if prev_id.status != id_attribute_pb2.Status.ON_VERIFICATION:
            LOGGER.debug("Previous ID status is {}. Confirm ID operation not allowed".format(prev_id.status))
            raise InvalidTransaction(
                "Previous ID status is {}. Confirm ID operation not allowed".format(prev_id.status))

        # verify peer responses
        quorum_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_PEER_VERIFY,
                                                       pub_key_hash=signer_pub_key_hash,
                                                       key=FAMILY_NAME_DIGITALID)
        LOGGER.debug("quorum_address : {}".format(quorum_address))

        # get quorum_state data, then update the quorums
        quorum_state_data = chain_access_util.get_state(cls.rest_api_url, quorum_address)

        LOGGER.debug("Existing quorum_state_data : {}".format(quorum_state_data))

        if quorum_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            raise InvalidTransaction("Quorum State invalid")
        # TODO
        if dependent_txn != quorum_state_data['dependency']:
            LOGGER.debug("Quorum state dependency {} not matching".format(quorum_state_data['dependency']))
            raise InvalidTransaction("Peer verification State invalid")

        if quorum_state_data['id_quorum_reached'] is not True:
            LOGGER.debug("id_quorum_reached {}".format(quorum_state_data['id_quorum_reached']))
            raise InvalidTransaction("Required quorum is not reached")
        # TODO can we check for disjoint property for peer_response_txn_ids?
        if set(quorum_state_data['peer_response_txn_ids']) != set(peer_response_list):
            LOGGER.debug("peer_response_txn_ids {}".format(quorum_state_data['peer_response_txn_ids']))
            LOGGER.debug("peer_response_list sent in transaction {}".format(peer_response_list))
            raise InvalidTransaction("peer_verification_txns list is not valid")

        quorum_map = quorum_state_data['attribute_quorum']
        verification_dict_frm_state = quorum_state_data['verification_detail']
        # verify digital-ID structure with the stored ID in state
        _verify_digital_id(prev_id=prev_id, cur_id=cur_id, verification_dict=verification_dict_frm_state,
                           quorum_map=quorum_map, operation_type='confirm_id')

        LOGGER.debug("trust_score : {}".format(trust_score))
        if trust_score != digital_id_constants.CONFIRMED_ID_TRUST_SCORE:
            InvalidTransaction("Invalid ID owner trust score")
        state_data = cbor.dumps({
            'digital_id': digital_id_byte,
            'acting_transaction_id': transaction_id,
            'trust_score': trust_score,
            'user_confirmation_txn': transaction_id  # Apr 9, 2020: added user_confirmation_txn
        })
        # initializing self-state data
        self_state_data = cbor.dumps({
            'digital_id': digital_id_byte,
            'ack_number': None,
            'trust_score': trust_score,
            'user_confirmation_txn': transaction_id  # Apr 9, 2020: added user_confirmation_txn
        })
        addresses = context.set_state({request_address: state_data,
                                       owner_address: self_state_data
                                       })

        if len(addresses) < 1:
            raise InternalError("State Error")

        context.add_event(
            event_type='digitalid/confirm',
            attributes=[
                ('address', str(request_address)),
                ('signer_public_key', str(signer_pub_key_hex)),  # why send with event?
                ('transaction_id', str(transaction_id)),
                ('send_to', str(cls.primary_certifier_address))

            ]
            # data=owner_sig_str.encode('utf-8')
        )

    # _invalidate_id method same as _update_id method, only events are different

    @classmethod
    def _invalidate_id(cls, context, to_address_list, transaction_id, digital_id_byte,
                       signer_pub_key_hex, dependency, receiver_grp):

        LOGGER.debug("Inside _invalidate_id method")

        # Verify if the requested address is valid for the operation
        signer_pub_key_hash = hashing.get_pub_key_hash(signer_pub_key_hex)
        id_creation_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                            pub_key_hash=signer_pub_key_hash,
                                                            key=FAMILY_NAME_CERTIFY)
        LOGGER.debug("id_creation_address : {}".format(id_creation_address))
        if id_creation_address not in to_address_list:
            raise InvalidTransaction("Output Address not valid")

        # get state data to validate and update
        id_state_data = chain_access_util.get_state(cls.rest_api_url, id_creation_address)

        LOGGER.debug("Existing id_state_data : {}".format(id_state_data))

        # TODO check this : if not needed we can just update the state
        if id_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            raise InvalidTransaction("ID creation state invalid")

        if dependency != id_state_data['acting_transaction_id']:
            raise InvalidTransaction("Invalid Transaction ID in dependency")

        # TODO check if id_state_data is not None?
        # TODO ADD extra fields as well
        receiver_grp.append(cls.primary_certifier_address)
        # req_info = {
        #     'invalidation_req': digital_id_byte,
        #     'pending_acks': []
        # }
        id_state_data['invalidation_req'] = digital_id_byte
        id_state_data['pending_acks'] = []
        id_state_data['pending_acks'].extend(receiver_grp)
        # updated_state_data = {
        #     'digital_id': id_state_data['digital_id'],
        #     'acting_transaction_id': id_state_data[transaction_id,
        #     'trust_score': trust_score,
        #     'invalidation_req': digital_id_byte,
        #     'pending_acks': []
        # }
        LOGGER.debug('id_state_data {}'.format(id_state_data))
        serialized_data = cbor.dumps(id_state_data)
        addresses = context.set_state({id_creation_address: serialized_data})

        LOGGER.debug("State-data : {}".format(id_state_data))

        if len(addresses) < 1:
            raise InternalError("State Error")
        LOGGER.debug("state updated for ID invalidation operation")

        context.add_event(
            event_type='digitalid/invalidate',
            attributes=[
                ('address', str(id_creation_address)),
                ('signer_public_key', str(signer_pub_key_hex)),  # why send with event?
                ('transaction_id', str(transaction_id)),
                ('send_to', str(receiver_grp)),  # TODO
                ('sent_from', str(signer_pub_key_hash))  # TODO
            ]
        )

    @classmethod
    def _invalidate_acks(cls, context, to_address_list, transaction_id,
                         signer_pub_key_hex, dependency):

        LOGGER.debug("Inside _invalidate_acks method")

        # Fetch header data from requesting_txn_id
        txn_response = chain_access_util.get_transaction(base_url=cls.rest_api_url, requesting_txn_id=dependency)
        txn_header = txn_response['header']
        id_owner_pub_key = txn_header['signer_public_key']
        id_owner_pub_key_hash = hashing.get_pub_key_hash(id_owner_pub_key)

        to_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                   pub_key_hash=id_owner_pub_key_hash,
                                                   key=FAMILY_NAME_CERTIFY)
        if to_address not in to_address_list:
            raise InvalidTransaction("Requested Output Address not valid")
        # verify validity of dependent transaction with state information
        id_state_data = chain_access_util.get_state(cls.rest_api_url, to_address)
        LOGGER.debug("Existing ID state_data : {}".format(id_state_data))

        if id_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            raise InvalidTransaction("ID creation state invalid")
        try:
            if id_state_data['invalidation_req'] is None or \
                    id_state_data['pending_acks'] is None:
                LOGGER.debug("expected dependency : {}".format(id_state_data['acting_transaction_id']))
                raise InvalidTransaction("Invalid state condition for invalidate operation")
        except KeyError:
            raise InvalidTransaction("Invalid state condition for ID-invalidate operation")

        # pending_acks = id_state_data['pending_acks']
        # LOGGER.debug("pending_acks list in state {}".format(pending_acks))
        signer_pub_key_hash = hashing.get_pub_key_hash(signer_pub_key_hex)
        if signer_pub_key_hash not in id_state_data['pending_acks']:
            LOGGER.debug("Signer : {} not a valid responder".format(signer_pub_key_hash))
            raise InvalidTransaction("Invalid transaction signer for INVALID_ACK")

        # remove signer_pub_key_hash from 'pending_acks' in id_state_data
        id_state_data['pending_acks'].remove(signer_pub_key_hash)
        LOGGER.debug("Modified pending_acks {}".format(id_state_data['pending_acks']))
        context.add_event(
            event_type='digitalid/invalidate_ack',
            attributes=[
                ('address', str(to_address)),
                ('signer_public_key', str(signer_pub_key_hex)),  # why send with event?
                ('transaction_id', str(transaction_id)),
                ('send_to', str(id_owner_pub_key_hash)),
                ('sent_from', str(signer_pub_key_hash))
            ]
        )

        if len(id_state_data['pending_acks']) == 0:  # all pending acknowledgement received
            id_state_data['digital_id'] = id_state_data['invalidation_req']
            id_state_data['acting_transaction_id'] = dependency
            id_state_data.pop('invalidation_req')
            id_state_data.pop('pending_acks')
            if id_state_data.get("user_confirmation_txn") is not None:
                id_state_data.pop('user_confirmation_txn')

            # Apr 11, 2020: delete self-state
            owner_self_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                               pub_key_hash=id_owner_pub_key_hash,
                                                               key='self')
            if owner_self_address not in to_address_list:
                raise InvalidTransaction("Requested address {} not valid output address".format(owner_self_address))

            addresses = context.delete_state([owner_self_address])
            if len(addresses) < 1:
                LOGGER.debug("Self state data could not be deleted")
                raise InternalError("State Deletion Error")

            context.add_event(
                event_type='digitalid/invalidation_success',
                attributes=[
                    ('address', str(to_address)),
                    ('signer_public_key', str(signer_pub_key_hex)),  # why send with event?
                    ('transaction_id', str(transaction_id)),
                    ('send_to', str(id_owner_pub_key_hash))
                ]
            )

        addresses = context.set_state({to_address: cbor.dumps(id_state_data)})

        LOGGER.debug("State-data : {}".format(id_state_data))

        if len(addresses) < 1:
            raise InternalError("State Error")
        LOGGER.debug("state updated for ID invalidation ack operation")

    @classmethod
    def _update_id_verifier(cls, context, to_address_list, transaction_id, digital_id_byte, signer_pub_key_hex,
                            client_trust_score, dependent_txn, peer_response_txns):

        signer_pub_key_hash = hashing.get_pub_key_hash(signer_pub_key_hex)
        id_creation_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                            pub_key_hash=signer_pub_key_hash,
                                                            key=FAMILY_NAME_CERTIFY)
        self_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                           pub_key_hash=signer_pub_key_hash,
                                                           key='self')
        if id_creation_address not in to_address_list or self_state_address not in to_address_list:
            raise InvalidTransaction("Output Address not valid")

        # verify validity of dependent transaction
        id_state_data = chain_access_util.get_state(cls.rest_api_url, id_creation_address)
        LOGGER.debug("Existing ID state_data : {}".format(id_state_data))

        if id_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            LOGGER.debug("ID data does not exist at address {}".format(id_creation_address))
            raise InvalidTransaction("ID data does not exist")

        if id_state_data['user_confirmation_txn'] != dependent_txn:
            LOGGER.debug("expected dependency : {}".format(id_state_data['user_confirmation_txn']))
            raise InvalidTransaction("Invalid transaction dependency given")

        # check validity of verifier update action and the digital-id in current transaction
        prev_id = digital_id_pb2.DigitalId()
        prev_id.ParseFromString(id_state_data['digital_id'])

        cur_id = digital_id_pb2.DigitalId()
        cur_id.ParseFromString(digital_id_byte)
        # previous ID status has to be confirmed.
        # Requested id status in current transaction may be on_verification or confirmed
        # depending on the updated ID trust-score

        if prev_id.status != id_attribute_pb2.Status.CONFIRMED:
            LOGGER.debug(
                "Previous ID status is {}. UPDATE_VERIFIER operation not allowed on the ID".format(prev_id.status))
            raise InvalidTransaction(
                "Previous ID status is {}. UPDATE_VERIFIER ID operation not allowed".format(prev_id.status))

        if cur_id.status != id_attribute_pb2.Status.CONFIRMED and \
                cur_id.status != id_attribute_pb2.Status.ON_VERIFICATION:
            LOGGER.debug("digital_id.status {}".format(cur_id.status))
            raise InvalidTransaction("The digital id status is not valid for the transaction status VERIFIER_UPDATE")

        # check if the cur_id.status valid for the owner's trust score
        if cur_id.status == id_attribute_pb2.Status.ON_VERIFICATION and \
                client_trust_score != digital_id_constants.PRIMARY_CERTIFIED_TRUST_SCORE:
            LOGGER.debug("client_trust_score {}".format(client_trust_score))
            raise InvalidTransaction("Unexpected client_trust_score")

        if cur_id.status == id_attribute_pb2.Status.CONFIRMED and \
                client_trust_score != digital_id_constants.CONFIRMED_ID_TRUST_SCORE:
            LOGGER.debug("client_trust_score {}".format(client_trust_score))
            raise InvalidTransaction("Unexpected client_trust_score")

        # check if new peer verification transactions are to be added by comparing with dependent_txn
        txn_response = chain_access_util.get_transaction(base_url=cls.rest_api_url, requesting_txn_id=dependent_txn)
        try:
            txn_payload = txn_response['payload']
            digital_id_transaction = digital_id_transaction_pb2.DigitalIdTransaction()
            digital_id_transaction.ParseFromString(base64.b64decode(txn_payload))
            prev_peer_txns = digital_id_transaction.peer_verification_txns
            LOGGER.debug("peer_verification_txns in dependency transaction: {}".format(prev_peer_txns))
        except BaseException as err:
            LOGGER.error("Error while reading transaction data {}".format(err))
            raise InvalidTransaction("Error while reading dependency transaction data")
        verification_dict_frm_state = None
        # new peer_verification_txns are present in the current transaction

        if len(set(peer_response_txns).difference(set(prev_peer_txns))) > 0:
            LOGGER.debug("Current transaction contains new peer_verification_txn")
            # verify peer responses
            quorum_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_PEER_VERIFY,
                                                           pub_key_hash=signer_pub_key_hash,
                                                           key=FAMILY_NAME_DIGITALID)
            LOGGER.debug("quorum_address : {}".format(quorum_address))

            # get quorum_state data, then update the quorums
            quorum_state_data = chain_access_util.get_state(cls.rest_api_url, quorum_address)

            LOGGER.debug("Existing quorum_state_data : {}".format(quorum_state_data))

            if quorum_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
                raise InvalidTransaction("Quorum State invalid")

            if dependent_txn != quorum_state_data['dependency']:
                LOGGER.debug("Quorum state dependency {} not matching".format(quorum_state_data['dependency']))
                raise InvalidTransaction("Peer verification State invalid")

            # verifying the peer_verification_txns sent in the transaction with quorum_state_data[
            # 'peer_response_txn_ids']
            if not set(peer_response_txns).issubset(set(quorum_state_data['peer_response_txn_ids'])):
                LOGGER.debug("peer_response_txn_ids {}".format(quorum_state_data['peer_response_txn_ids']))
                LOGGER.debug("peer_response_list sent in transaction {}".format(peer_response_txns))
                raise InvalidTransaction("peer_verification_txns list in transaction is not valid")

            verification_dict_frm_state = quorum_state_data['verification_detail']
        elif set(peer_response_txns) == set(prev_peer_txns):
            LOGGER.debug("Current transaction does not update peer_verification_txns")
            verification_dict_frm_state = None
        # else:
        #     LOGGER.debug("Current transaction does not contain txn {}".format(
        #         set(prev_peer_txns).difference(set(peer_response_txns))))
        #     raise InvalidTransaction("peer_verification_txns list in transaction does not contain all "
        #                              "peer_verification_txns of its dependency transaction")

        # verify digital-ID structure with the stored ID in state
        if cur_id.status == id_attribute_pb2.Status.ON_VERIFICATION:
            operation_type = 'demote_id'
        else:
            operation_type = 'confirm_id'

        _verify_digital_id(prev_id=prev_id, cur_id=cur_id, verification_dict=verification_dict_frm_state,
                           operation_type=operation_type)

        # user_confirmation_txn would contain a valid transaction id as long as there is a valid confirmed ID in the
        # self-state to share and use for authentication. In case the ID is demoted or invalidated, the
        # user_confirmation_txn field would be reset to have an empty string to indicate the owner has
        # no valid confirmed ID for use.

        if operation_type == 'confirm_id':
            # Apr 9, 2020: added user_confirmation_txn
            id_state_data['digital_id'] = digital_id_byte
            id_state_data['acting_transaction_id'] = transaction_id
            id_state_data['trust_score'] = client_trust_score
            id_state_data['user_confirmation_txn'] = transaction_id  #This is working fine
            # TODO comment id_state_data['user_confirmation_txn'] = transaction_id ?

            # initializing self-state data
            self_state_data = cbor.dumps({
                'digital_id': digital_id_byte,
                'ack_number': None,
                'trust_score': client_trust_score,
                'user_confirmation_txn': transaction_id  # Apr 9, 2020: added user_confirmation_txn
            })
            addresses = context.set_state({id_creation_address: cbor.dumps(id_state_data),
                                           self_state_address: self_state_data
                                           })

            if len(addresses) < 1:
                raise InternalError("State Error")

            context.add_event(
                event_type='digitalid/confirm',
                attributes=[
                    ('address', str(id_creation_address)),
                    ('signer_public_key', str(signer_pub_key_hex)),  # why send with event?
                    ('transaction_id', str(transaction_id)),
                    ('send_to', str(cls.primary_certifier_address))

                ]
            )
        elif operation_type == 'demote_id':  # the learner no longer has a valid ID to share
            # Apr 11, 2020: added user_confirmation_txn.
            id_state_data['digital_id'] = digital_id_byte
            id_state_data['acting_transaction_id'] = transaction_id
            id_state_data['trust_score'] = client_trust_score
            if id_state_data.get("user_confirmation_txn") is not None:
                id_state_data.pop('user_confirmation_txn')
            state_data = cbor.dumps(id_state_data)
            addresses = context.set_state({id_creation_address: state_data
                                           })
            if len(addresses) < 1:
                raise InternalError("ID Creation State Update Error")

            # Apr 11, 2020: delete self-state
            addresses = context.delete_state([self_state_address])
            if len(addresses) < 1:
                LOGGER.debug("Self state data could not be deleted")
                raise InternalError("State Deletion Error")

            context.add_event(
                event_type='digitalid/demoted',
                attributes=[
                    ('address', str(id_creation_address)),
                    ('signer_public_key', str(signer_pub_key_hex)),  # why send with event?
                    ('transaction_id', str(transaction_id))
                ]
            )


def create_parser(prog_name):
    """Create the command line argument parser for the digital-ID event listener for learner."""
    parser = argparse.ArgumentParser(prog=prog_name, add_help=False)
    parser.add_argument('-C', '--connect', dest='validator_url', type=str, help="Url to connect to validator")
    parser.add_argument('-l', '--url', dest='rest_api_url', type=str, help="Rest-API URL")
    parser.add_argument('-v', '--verbosity1', action='store_const', const=1, default=0, dest='verbosity',
                        help='sets verbosity level to 1')
    parser.add_argument('-vv', '--verbosity2', action='store_const', const=2, dest='verbosity',
                        help='sets verbosity level to 2')
    parser.add_argument('-vvv', '--verbosity3', action='store_const', const=3, dest='verbosity',
                        help='sets verbosity level to 3')
    return parser


def main(prog_name=os.path.basename(sys.argv[0]), args=None):
    # Setup logging for this class.
    # logging.basicConfig()
    # logging.getLogger().setLevel(logging.DEBUG)
    # setup_loggers(verbose_level=0)
    # pwd = os.path.expanduser(".")
    # config_dir = os.path.join(pwd, "tfprocessor")
    # config_file = '{}/{}.txt'.format(config_dir, digital_id_constants.CERTIFIER_CONFIG_FILE)
    #
    # try:
    #     with open(config_file) as fd:
    #         for line in fd:
    #             line = line.strip()
    #             if line.startswith('#') or line == '':
    #                 continue
    #             (key, value) = line.split(': ')
    #             certifier_dict[key] = value.strip()
    # except OSError as err:
    #     raise Exception('Failed to read certifier config file {}: {}'.format(config_file, str(err)))
    # if certifier_dict.get('primary_certifier_pubkey') is None:
    #     raise Exception("Invalid certifier configuration: 'primary_certifier_pubkey' not set")
    # LOGGER.debug("primary_certifier_pubkey : {}".format(certifier_dict.get('primary_certifier_pubkey')))
    # TODO test this block
    try:
        # key_file_name = sys.argv[1]
        if args is None:
            args = sys.argv[1:]
        parser = create_parser(prog_name)
        results = parser.parse_args(args)
        verbose_level = results.verbosity
        setup_loggers(verbose_level=verbose_level)
        LOGGER.debug("results: %s", results)
        LOGGER.critical("verbose_level: %s", verbose_level)
        validator_url = results.validator_url
        api_url = results.rest_api_url
        if validator_url is None:
            validator_url = DEFAULT_VALIDATOR_URL

        if api_url is None:
            api_url = DEFAULT_REST_API_URL
        LOGGER.debug("Validator URL: %s", validator_url)
        LOGGER.debug("REST API URL: %s", api_url)
        # TODO adding code to parse cmd arguments
        tp_processor = TransactionProcessor(url=validator_url)
        id_generation_namespace = hashing.hash512(FAMILY_NAME_DIGITALID.encode('utf-8'))[0:6] + \
                                  hashing.hash512(FAMILY_NAME_CERTIFY.encode('utf-8'))[0:24]
        app_namespace = hashing.hash512(FAMILY_NAME_DIGITALID.encode('utf-8'))[0:6]
        client_app_namespace = hashing.hash512(FAMILY_NAME_DIGITALID_CLIENT.encode('utf-8'))[0:6]
        # creating Handler classes
        id_app_handler = DigitalIdTransactionHandler([app_namespace, id_generation_namespace])
        client_app_handler = DigitalIdClientTransactionHandler([app_namespace, client_app_namespace])
        # Setting field rest_api_url
        DigitalIdTransactionHandler.rest_api_url = api_url
        DigitalIdClientTransactionHandler.rest_api_url = api_url
        tp_processor.add_handler(id_app_handler)
        tp_processor.add_handler(client_app_handler)
        tp_processor.start()
    except KeyboardInterrupt:
        pass
    except SystemExit as err:
        raise err
    except BaseException as err:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
