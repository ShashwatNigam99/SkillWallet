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

# path.append('/home/suchira/digital-id/learner')
# home = os.path.expanduser("~")
# proj_dir = os.path.join(home, "digital-id")
# path.append(proj_dir)

path.append(os.getcwd())

from protobuf import peer_verification_pb2, digital_id_pb2, id_attribute_pb2, digital_id_transaction_pb2
from util import hashing, chain_access_util
from constants import digital_id_constants
from constants.digital_id_constants import MAX_CLIENT_TRUST_SCORE, MIN_PEER_COUNT, MAX_PEER_COUNT, \
    PEER_VERIFICATION_REQUEST

# path.append('/home/suchira/digital-id/util')
#
# path.append('/home/suchira/digital-id/protobuf')

DEFAULT_VALIDATOR_URL = 'tcp://localhost:4004'
DEFAULT_REST_API_URL = 'http://localhost:8008'

LOGGER = logging.getLogger('peer_verification_tp')

FAMILY_NAME_PEER_VERIFY = "peer_verification"
FAMILY_NAME_DIGITALID = 'digitalid'  # 2122d3
FAMILY_NAME_CERTIFY = "digitalid_certifier"


# MAX_PEER_QUORUM = 2 * MAX_AVG_TRUST_SCORE -- not needed
# MIN_PEER_QUORUM = MIN_PEER_COUNT * MAX_AVG_TRUST_SCORE


def _verify_peer_verification_txn(peer_verification_request):
    LOGGER.debug("Inside _verify_peer_verification_txn")
    flag = True
    attribute_fields = peer_verification_request.ListFields()
    for attr in attribute_fields:
        print('Field name : {}'.format(attr[0].name))
        print('value : {}'.format(attr[1]))
    try:
        if peer_verification_request.payload is b'':
            flag = False
            LOGGER.error("peer_verification_txn.payload is empty")

        if peer_verification_request.action is "":
            flag = False
            LOGGER.error("peer_verification_txn.action is empty")

        if flag is False:
            LOGGER.error("Invalid peer_verification_txn")
            raise InvalidTransaction("Invalid peer_verification_txn")
    except AttributeError:
        raise InvalidTransaction("Invalid message structure for PeerVerificationTransaction")


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
    return clog


def create_file_handler():
    # configure logger
    file_handler = logging.FileHandler('peer_verification_tp.log')
    file_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    return file_handler


def setup_loggers(verbose_level):
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


def is_quorum_fulfilled(total_quorum, target_peer_quorum):
    # check to see if the target is reached for total_quorum
    # if total_quorum < max(MIN_PEER_QUORUM, target_peer_quorum):
    if total_quorum < target_peer_quorum:
        return False
    else:
        return True


def initialize_quorum_dict(digital_id):
    attribute_quorum_dict = {}
    attribute_set_msg = digital_id.attribute_set
    attribute_fields = attribute_set_msg.ListFields()
    for attribute_field in attribute_fields:
        if attribute_field[0].name != 'others':
            field_name = attribute_field[0].name
            attribute_quorum_dict[field_name] = 0
        elif attribute_field[0].name == 'others':
            attr_map = attribute_field[1]
            for field_name in attr_map:
                attribute_quorum_dict[field_name] = 0

    return attribute_quorum_dict


def calculate_target_quorum(total_peer_count):
    LOGGER.debug("Inside calculate_target_quorum()")

    # calculate the min quorum needed for each attribute to confirm the digital ID
    # N = total_peer + count({digitalid_certifier, learner})
    # removed: N = total_peer_count + 2
    N = total_peer_count + 1
    # removed: super_majority_num = math.floor(2 * (total_peer + 1) / 3)
    # removed: super_majority_num = math.floor(2 * N / 3) + 1
    # super_majority_num = math.floor(2 * (N - 1) / 3) + 1
    super_majority_num = 2 * math.floor((N - 1) / 3) + 1
    LOGGER.debug("super_majority_num {}".format(super_majority_num))

    # subtract the {primary digitalid_certifier + the learner} vote from the super_majority_num
    # for calculating target quorum from peers
    # the target quorum is the minimum value to be achieved through up vote

    # removed: target_peer_quorum = (super_majority_num - 2) * MAX_AVG_TRUST_SCORE
    # target_peer_quorum = (super_majority_num - 1) * MAX_CLIENT_TRUST_SCORE
    target_peer_quorum = super_majority_num * MAX_CLIENT_TRUST_SCORE
    LOGGER.debug("Target quorum {}".format(target_peer_quorum))
    return target_peer_quorum


def process_attribute_response(field_name, field_value, field_in_req_value,
                               signer_pub_key, client_info,
                               operation_type, quorum_state_data):
    LOGGER.debug("Inside process_attribute_response for attribute {}".format(field_name))
    attribute_quorum_dict = quorum_state_data['attribute_quorum']
    request_count_dict = quorum_state_data['request_count']
    verification_detail_dict = quorum_state_data['verification_detail']
    if attribute_quorum_dict.get(field_name) is None:
        total_quorum = 0
    else:
        total_quorum = attribute_quorum_dict.get(field_name)

    if field_value.status == id_attribute_pb2.Status.CONFIRMED and \
            field_in_req_value.status == id_attribute_pb2.Status.REQUESTED:
        # verify if the field_value was requested

        # verify certificate
        LOGGER.debug("{} status confirmed".format(field_name))
        is_verified = _verify_message_signature(field_value.attribute_data_enc,
                                                field_value.certificate,
                                                signer_pub_key)
        if is_verified is True:
            try:
                verification_detail_dict[field_name].extend([client_info.SerializeToString()])
            except KeyError:
                # TODO test this
                verification_detail_dict[field_name] = []
                verification_detail_dict[field_name].extend([client_info.SerializeToString()])

            if operation_type == digital_id_constants.TYPE_ID_CREATE:
                total_quorum = total_quorum + field_value.credibility_strength
                attribute_quorum_dict[field_name] = total_quorum
                LOGGER.debug("updated total_quorum : {}".format(attribute_quorum_dict[field_name]))
        else:
            raise InvalidTransaction("{} Attribute certificate is invalid".format(field_name))

    if operation_type == digital_id_constants.TYPE_ID_CREATE:
        total_peer_count = request_count_dict.get(field_name)

        if total_peer_count is None:
            raise InternalError(
                "Invalid quorum-state update: request count for {} does not exist".
                    format(field_name))

        elif total_peer_count < MIN_PEER_COUNT:
            raise InvalidTransaction(
                "Minimum peer count of {} has not reached for all attributes".format(
                    MIN_PEER_COUNT))

        target_peer_quorum = calculate_target_quorum(total_peer_count)
        quorum_fulfilled = is_quorum_fulfilled(total_quorum, target_peer_quorum)
        LOGGER.debug("quorum_fulfilled {}".format(quorum_fulfilled))
        return quorum_fulfilled
    else:
        return None


class PeerVerificationHandler(TransactionHandler):
    """
    Transaction Processor class for the DigitalID Transaction Family.

    This TP communicates with the Validator using the accept/get/set functions.

    """
    batch_transactions = []
    dependency_txn = None
    request_count_dict = {}
    txn_timestamp = None
    rest_api_url = None

    def __init__(self, namespace_prefix):
        """Initialize the transaction handler class.
           This is setting the "digitalid" TF namespace prefix.
        """
        self._namespace_prefix = namespace_prefix

    @property
    def family_name(self):
        """Return Transaction Family name string."""
        return FAMILY_NAME_PEER_VERIFY

    @property
    def family_versions(self):
        """Return Transaction Family version string."""
        return ['1.0']

    @property
    def namespaces(self):
        """Return Transaction Family namespace 6-character prefix."""
        return [self._namespace_prefix]

    def apply(self, transaction, context):
        """This implements the apply function for the TransactionHandler class.

           The apply function does most of the work for this class by
           processing a transaction for the peer_verification transaction family.
        """

        # Get the payload
        # extract the digital id-specific information
        # verify the structure of digital-id transaction message
        header = transaction.header
        # removing the following logic. Derive the to_address based on the information available
        # we add a verification if the derived address belongs to header.outputs or not
        to_address_list = header.outputs
        LOGGER.debug("to-address: {}".format(to_address_list))

        transaction_id = transaction.signature
        LOGGER.debug("transaction id: {}".format(transaction_id))

        # Get the signer's public key, sent in the header from the _client.
        signer_pub_key_hex = header.signer_public_key
        LOGGER.debug("signer_pub_key {}".format(signer_pub_key_hex))
        dependency_list = header.dependencies
        if dependency_list is None or len(dependency_list) != 1:
            raise InvalidTransaction("Invalid transaction dependency")
        payload = transaction.payload

        try:
            peer_verification_txn = peer_verification_pb2.PeerVerificationTransaction()
            peer_verification_txn.ParseFromString(payload)
        except BaseException as err:
            raise Exception(err)
        _verify_peer_verification_txn(peer_verification_txn)
        peer_verification_payload = peer_verification_txn.payload
        peer_verification_req_type = peer_verification_txn.type

        # if total_peers < MIN_PEER_COUNT:
        #     raise InvalidTransaction("Total peer number should be at least {}".format(MIN_PEER_COUNT))
        #
        # if total_peers > MAX_PEER_COUNT:
        #     raise InvalidTransaction("Maximum permissible number of total peers is 4 {}".format(MAX_PEER_COUNT))

        if peer_verification_txn.action == digital_id_constants.PEER_VERIFICATION_REQUEST:
            total_peers = peer_verification_txn.total_peer_request_count
            LOGGER.debug("total_peers {}".format(total_peers))

            self._peer_request(context, to_address_list, transaction_id,
                               peer_verification_payload, signer_pub_key_hex,
                               dependency_list[0], total_peers, peer_verification_req_type)

        elif peer_verification_txn.action == digital_id_constants.PEER_VERIFICATION_RESPONSE:
            self._peer_response(context, to_address_list, transaction_id, peer_verification_payload,
                                signer_pub_key_hex, dependency_list[0], peer_verification_req_type)
        else:
            LOGGER.debug("Unhandled action. Action should be peer_verify_request or peer_verify_response")
            raise InvalidTransaction('Unhandled action: {}'.format(peer_verification_txn.action))

    @classmethod
    def _peer_request(cls, context, to_address_list, transaction_id, peer_verification_payload,
                      signer_pub_key_hex, dependency, total_peer, request_type):
        LOGGER.debug("Inside _peer_request")
        try:
            peer_verification_request = peer_verification_pb2.PeerVerificationRequest()
            peer_verification_request.ParseFromString(peer_verification_payload)
        except BaseException as err:
            raise Exception(err)

        update_flag = False

        if request_type == digital_id_constants.TYPE_ID_CREATE:
            # This block handles batch of multiple trasactions
            update_flag = True

            if cls.dependency_txn != dependency \
                    or cls.txn_timestamp != peer_verification_request.create_timestamp:
                LOGGER.debug("resetting class state variables")
                # reset the class state variables
                cls.batch_transactions = []
                cls.dependency_txn = None
                cls.request_count_dict = {}
                cls.txn_timestamp = None

            if cls.txn_timestamp is None:
                cls.txn_timestamp = peer_verification_request.create_timestamp

            if cls.dependency_txn is None:
                cls.dependency_txn = dependency

            if cls.dependency_txn == dependency \
                    and cls.txn_timestamp == peer_verification_request.create_timestamp:

                if transaction_id not in cls.batch_transactions:
                    cls.batch_transactions.append(transaction_id)
                    LOGGER.debug(cls.request_count_dict)
                else:
                    update_flag = False
                    # cls.request_count_dict would be updated in cls._verify_digital_id
            # else:
            #     LOGGER.debug("resetting class state variables")
            #     # reset the class state variables
            #     cls.batch_transactions = []
            #     cls.dependency_txn = None
            #     cls.request_count_dict = {}
            #     cls.txn_timestamp = None

            LOGGER.debug("cls.batch_transactions = {}".format(cls.batch_transactions))
            LOGGER.debug("cls.dependency_txn = {}".format(cls.dependency_txn))
            LOGGER.debug("cls.request_count_dict = {}".format(cls.request_count_dict))
            LOGGER.debug("cls.txn_timestamp = {}".format(cls.txn_timestamp))
            LOGGER.debug("update_flag = {}".format(update_flag))

            if len(cls.batch_transactions) > total_peer:
                raise InvalidTransaction("Total number of requests received exceeds total peers")

        # _verify_peer_verification_request(peer_verification_request)

        digital_id_byte = peer_verification_request.digital_id
        LOGGER.debug("digital_id_byte = %s.", digital_id_byte)

        try:
            digital_id = digital_id_pb2.DigitalId()
            # TODO de-compress digital_id_bytes
            digital_id.ParseFromString(digital_id_byte)

        except BaseException as err:
            raise Exception(err)

        # verify the digital id signature
        owner_sig_str = peer_verification_request.owner_signature
        LOGGER.debug("owner_sig_str = %s.", owner_sig_str)

        peer_address = peer_verification_request.peer_address
        LOGGER.debug("peer_address = %s.", peer_address)

        is_verified = _verify_message_signature(digital_id_byte, owner_sig_str, signer_pub_key_hex)
        if is_verified == 0:
            LOGGER.error('DigitalIdTransaction.owner_signature invalid')
            raise InvalidTransaction('DigitalIdTransaction.owner_signature invalid')
        else:
            # Verify if the requested address is valid for REQUEST action
            signer_pub_key_hash = hashing.get_pub_key_hash(signer_pub_key_hex)

            # verify validity of dependent transaction
            owner_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                          pub_key_hash=signer_pub_key_hash,
                                                          key=FAMILY_NAME_CERTIFY)
            id_state_data = chain_access_util.get_state(cls.rest_api_url, owner_address)
            LOGGER.debug("Existing ID state_data : {}".format(id_state_data))
            if id_state_data != digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
                if request_type == digital_id_constants.TYPE_ID_CREATE:
                    if id_state_data['acting_transaction_id'] != dependency:
                        LOGGER.debug("expected dependency : {}".format(id_state_data['acting_transaction_id']))
                        raise InvalidTransaction("Invalid dependency given")
                elif request_type == digital_id_constants.TYPE_CREDIBILITY_INC:
                    if id_state_data['user_confirmation_txn'] != dependency:
                        LOGGER.debug("expected dependency : {}".format(id_state_data['user_confirmation_txn']))
                        raise InvalidTransaction("Invalid dependency given")

            else:
                raise InvalidTransaction("Requested ID details not available")

            # TODO Apr 9: check ID in dependency transaction and its status
            # ---- start change ------------------
            dependent_txn_response = chain_access_util.get_transaction(base_url=cls.rest_api_url,
                                                                       requesting_txn_id=dependency)
            LOGGER.debug("dependent_txn_response {}".format(dependent_txn_response))
            try:
                txn_payload = dependent_txn_response['payload']
                digitalid_transaction = digital_id_transaction_pb2.DigitalIdTransaction()
                digitalid_transaction.ParseFromString(base64.b64decode(txn_payload))
            except BaseException as err:
                LOGGER.error("Error while reading transaction data {}".format(err))
                raise Exception("Error while reading transaction data")

            if request_type == digital_id_constants.TYPE_ID_CREATE:
                if digitalid_transaction.status != id_attribute_pb2.ON_VERIFICATION and \
                        digitalid_transaction.status != id_attribute_pb2.VERIFIER_UPDATE:
                    raise InvalidTransaction("Unexpected dependency transaction status of {}".
                                             format(digitalid_transaction.status))
            elif request_type == digital_id_constants.TYPE_CREDIBILITY_INC:
                if digitalid_transaction.status != id_attribute_pb2.CONFIRMED and \
                        digitalid_transaction.status != id_attribute_pb2.VERIFIER_UPDATE:
                    raise InvalidTransaction("Unexpected dependency transaction status of {}".
                                             format(digitalid_transaction.status))

            # --------------ends------------
            stored_id = digital_id_pb2.DigitalId()
            stored_id.ParseFromString(id_state_data['digital_id'])

            # verify digital_id data sent in request is matches with stored_id
            # also updates cls.request_count_dict
            cls._verify_digital_id(stored_id=stored_id, cur_id=digital_id,
                                   total_peer_count=total_peer, update_count=update_flag)

            # Verify if the quorum address is valid for REQUEST action
            quorum_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_PEER_VERIFY,
                                                           pub_key_hash=signer_pub_key_hash,
                                                           key=FAMILY_NAME_DIGITALID)
            LOGGER.debug("quorum_address : {}".format(quorum_address))

            if quorum_address not in to_address_list:
                raise InvalidTransaction("Output Quorum Address not valid")

            # TODO else part never executes as peer requests are submitted as a batch
            # so, quorum_state is not updated until the batch is committed.
            # Class variables are introduced to keep track of the requests within the same batch
            quorum_state_data_loaded = chain_access_util.get_state(cls.rest_api_url, quorum_address)

            if quorum_state_data_loaded == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
                # This block is executed only for TYPE_ID_CREATE
                LOGGER.debug("{} State not initialized".format(quorum_address))
                # Initialize state
                # attribute_quorum_dict = initialize_quorum_dict(digital_id)
                quorum_state_data = cbor.dumps({'attribute_quorum': {},
                                                'peer_request_txn_ids': cls.batch_transactions,
                                                'dependency': dependency,
                                                'id_quorum_reached': False,
                                                'peer_response_txn_ids': [],
                                                'request_count': cls.request_count_dict,
                                                'operation_type': request_type,
                                                'verification_detail': {}
                                                })
                # LOGGER.debug("attribute_quorum : {}".format(attribute_quorum_dict))
                LOGGER.debug("attribute_quorum : '{}'")
                LOGGER.debug("peer_request_txn_ids : {}".format(cls.batch_transactions))
                LOGGER.debug("dependency : {}".format(dependency))
                LOGGER.debug("peer_response_txn_ids : {}".format([]))
                LOGGER.debug("id_quorum_reached : {}".format(False))
                LOGGER.debug("request_count : {}".format(cls.request_count_dict))
                LOGGER.debug("operation_type : {}".format(request_type))
                LOGGER.debug("verification_detail : '{}'")
            else:
                dependent_txn_id = quorum_state_data_loaded['dependency']
                if dependent_txn_id != dependency:
                    if request_type == digital_id_constants.TYPE_ID_CREATE:
                        # ID peer verification is re-initiated TODO how to handle ID-update case? attribute_quorum
                        #  keeps the list of attributes requested for verification; related to dependency txn
                        quorum_state_data_loaded['attribute_quorum'] = {}
                        quorum_state_data_loaded['dependency'] = dependency
                        quorum_state_data_loaded['id_quorum_reached'] = False  # depends on the dependency
                        quorum_state_data_loaded['peer_request_txn_ids'] = cls.batch_transactions  # [transaction_id]
                        quorum_state_data_loaded['peer_response_txn_ids'] = []
                        quorum_state_data_loaded['request_count'] = cls.request_count_dict
                        quorum_state_data_loaded['operation_type'] = request_type
                        quorum_state_data_loaded['verification_detail'] = {}
                    elif request_type == digital_id_constants.TYPE_CREDIBILITY_INC:
                        # quorum state is being used for TYPE_CREDIBILITY_INC
                        # for TYPE_CREDIBILITY_INC type of operation, dependency is a txn confirming the ID
                        # if the dependency changes, the existing peer_requests become invalid and so those are removed
                        quorum_state_data_loaded['dependency'] = dependency
                        quorum_state_data_loaded['peer_request_txn_ids'] = [transaction_id]
                        quorum_state_data_loaded['peer_response_txn_ids'] = []
                        quorum_state_data_loaded['verification_detail'] = {}

                        if quorum_state_data_loaded['operation_type'] != request_type:
                            quorum_state_data_loaded['attribute_quorum'] = {}
                            quorum_state_data_loaded['id_quorum_reached'] = False  # depends on the dependency
                            quorum_state_data_loaded['request_count'] = {}
                            quorum_state_data_loaded['operation_type'] = request_type
                else:
                    # this block may be entered if peer-request is resent after timer expiry for type TYPE_ID_CREATE
                    # TODO test peer_request_txn_ids
                    LOGGER.debug("in else block")
                    # re-initialize
                    if request_type == digital_id_constants.TYPE_ID_CREATE:
                        quorum_state_data_loaded = {'attribute_quorum': {},
                                                    'peer_request_txn_ids': cls.batch_transactions,
                                                    'dependency': dependency,
                                                    'id_quorum_reached': False,
                                                    'peer_response_txn_ids': [],
                                                    'request_count': cls.request_count_dict,
                                                    'verification_detail': {}
                                                    }
                    else:
                        if quorum_state_data_loaded['operation_type'] == request_type:
                            if quorum_state_data_loaded.get('peer_request_txn_ids') is None:
                                quorum_state_data_loaded['peer_request_txn_ids'] = []
                            quorum_state_data_loaded['peer_request_txn_ids'].append(transaction_id)
                            quorum_state_data_loaded['peer_response_txn_ids'] = []
                        else:
                            # transaction is invalid for operation type TYPE_CREDIBILITY_INC
                            LOGGER.debug("Existing operation type for dependency {} is {}".
                                         format(dependent_txn_id, quorum_state_data_loaded['operation_type']))
                            raise InvalidTransaction("Invalid dependency for operation type: {}".format(request_type))

                    # quorum_state_data_loaded['peer_request_txn_ids'].append(transaction_id)
                    # LOGGER.debug("peer_request_txn_ids : {}".format(quorum_state_data_loaded['peer_request_txn_ids']))
                    # LOGGER.debug("Total number of requests received {}".format(
                    #     len(quorum_state_data_loaded['peer_request_txn_ids'])))
                    # LOGGER.debug("Total expected peers {}".format(total_peer))
                    #
                    # if len(quorum_state_data_loaded['peer_request_txn_ids']) > total_peer:
                    #     raise InvalidTransaction("Total number of requests received exceeds total peers")
                    #
                    # # update quorum_state_data_loaded['request_count']
                    # request_count = quorum_state_data_loaded['request_count']
                    # for k in cls.request_count_dict.keys():
                    #     if request_count.get(k) is None:
                    #         request_count[k] = cls.request_count_dict[k]
                    #     else:
                    #         request_count[k] += cls.request_count_dict[k]
                    # quorum_state_data_loaded['request_count'] = request_count

                LOGGER.debug("attribute_quorum : {}".format(quorum_state_data_loaded['attribute_quorum']))
                LOGGER.debug("id_quorum_reached : {}".format(quorum_state_data_loaded['id_quorum_reached']))
                LOGGER.debug("peer_response_txn_ids : {}".format(quorum_state_data_loaded['peer_response_txn_ids']))
                LOGGER.debug("dependent transaction id : {}".format(quorum_state_data_loaded['dependency']))
                LOGGER.debug("peer_request_txn_ids : {}".format(quorum_state_data_loaded['peer_request_txn_ids']))
                LOGGER.debug("request_count : {}".format(quorum_state_data_loaded['request_count']))

                quorum_state_data = cbor.dumps(quorum_state_data_loaded)

            if quorum_state_data is not None:
                addresses = context.set_state({  # request_address: state_data,
                    quorum_address: quorum_state_data
                })

                if len(addresses) < 1:
                    raise InternalError("State Error")

                context.add_event(
                    event_type='peer_verification/request',
                    attributes=[
                        ('address', str(quorum_address)),
                        ('signer_public_key', str(signer_pub_key_hex)),  # why send with event?
                        ('transaction_id', str(transaction_id)),
                        ('send_to', str(peer_address)),  # request sent to peer
                        ('sent_from', str(signer_pub_key_hash))  # ID owner address
                    ]
                    # data=owner_sig_str.encode('utf-8')
                )
            else:
                LOGGER.debug("No update for Quorum state")
                LOGGER.debug("resetting class state variables")
                # reset the class state variables
                cls.batch_transactions = []
                cls.dependency_txn = None
                cls.request_count_dict = {}
                cls.txn_timestamp = None

    @classmethod
    def _peer_response(cls, context, to_address_list, transaction_id, peer_verification_payload,
                       signer_pub_key_hex, dependency, operation_type):

        LOGGER.debug("Inside _peer_response")
        # check response is from valid address based on its dependency

        dependent_txn_response = chain_access_util.get_transaction(base_url=cls.rest_api_url,
                                                                   requesting_txn_id=dependency)
        LOGGER.debug("dependent_txn_response {}".format(dependent_txn_response))
        try:
            txn_payload = dependent_txn_response['payload']
            peer_transaction = peer_verification_pb2.PeerVerificationTransaction()
            peer_transaction.ParseFromString(base64.b64decode(txn_payload))
        except BaseException as err:
            LOGGER.error("Error while reading transaction data {}".format(err))
            raise Exception("Error while reading transaction data")

        if peer_transaction.action != PEER_VERIFICATION_REQUEST:
            raise InvalidTransaction("Dependency transaction action type is not PEER_VERIFICATION_REQUEST")

        if peer_transaction.type != operation_type:
            raise InvalidTransaction("Dependency transaction request type is not {}".format(operation_type))

        peer_request_payload = peer_transaction.payload
        peer_request = peer_verification_pb2.PeerVerificationRequest()
        peer_request.ParseFromString(peer_request_payload)
        requested_peer_address = peer_request.peer_address
        LOGGER.debug("requested_peer_address {}".format(requested_peer_address))
        peer_request_id = digital_id_pb2.DigitalId()
        peer_request_id.ParseFromString(peer_request.digital_id)
        LOGGER.debug("Digital id in peer request {}".format(peer_request_id))

        responding_address = hashing.get_pub_key_hash(signer_pub_key_hex)
        LOGGER.debug("responding_address {}".format(responding_address))
        if requested_peer_address != responding_address:
            raise InvalidTransaction("Invalid signer of PeerVerificationResponse")
        try:
            peer_verification_response = peer_verification_pb2.PeerVerificationResponse()
            peer_verification_response.ParseFromString(peer_verification_payload)
        except BaseException as err:
            raise Exception(err)

        # TODO verify response with peer response
        # TODO _verify_peer_verification_response(peer_verification_request)

        digital_id_byte = peer_verification_response.digital_id
        LOGGER.debug("digital_id_byte = %s.", digital_id_byte)

        # TODO add code for verify digital_id_byte information
        try:
            digital_id = digital_id_pb2.DigitalId()
            # TODO de-compress digital_id_bytes
            digital_id.ParseFromString(digital_id_byte)

        except BaseException as err:
            raise Exception(err)

        # TODO _verify_digital_id(digital_id)

        # retrieve peer_info
        client_info = peer_verification_response.peer_info
        if client_info.trust_score < digital_id_constants.CONFIRMED_ID_TRUST_SCORE:
            LOGGER.error('Client trust score of less than 20 not eligible')
            LOGGER.debug('client_trust_score {}'.format(client_info.trust_score))
            raise InvalidTransaction('Client trust score of less than 20 not eligible')
        else:
            client_trust_score = client_info.trust_score
            client_family = client_info.family_name
            LOGGER.debug("client_family {}".format(client_family))
            LOGGER.debug('client_trust_score {}'.format(client_trust_score))

            # construct peer state address
            peer_state_address = hashing.get_digitalid_address(family_name=client_family,
                                                               pub_key_hash=requested_peer_address,
                                                               key='self')
            id_state_data = chain_access_util.get_state(cls.rest_api_url, peer_state_address)
            LOGGER.debug("Existing ID state_data : {}".format(id_state_data))

            if id_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
                LOGGER.debug("Expected ID state does not exist")
                raise InvalidTransaction("Expected ID state does not exist")

            if id_state_data['trust_score'] != client_trust_score:
                LOGGER.debug("Expected trust score: {}".format(id_state_data['trust_score']))
                raise InvalidTransaction("Invalid trust score provided")
            # TODO change trust_score in the verifier namespace
            # TODO if invalid transaction penalize?
            # if peer_verification_response.verification_reward != digital_id_constants.PEER_VERIFICATION_REWARD:
            #     raise InvalidTransaction('Invalid peer verification reward')

        # verify the digital id signature done by peer sending response using the transaction signer's public key
        peer_sig_str = peer_verification_response.peer_signature
        LOGGER.debug("peer_sig_str = %s.", peer_sig_str)

        # signer_pub_key is the transaction signer's public key
        is_verified = _verify_message_signature(digital_id_byte, peer_sig_str, signer_pub_key_hex)
        if is_verified == 0:
            LOGGER.error('PeerVerificationResponse.peer_signature invalid')
            raise InvalidTransaction('PeerVerificationResponse.peer_signature invalid')
        else:

            # Verify if the requested address is valid by regenerating the same
            # signer_pub_key_hash = hashing.get_pub_key_hash(signer_pub_key)

            owner_pub_key_hash = hashing.get_pub_key_hash(digital_id.id_owner_public_key)

            quorum_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_PEER_VERIFY,
                                                           pub_key_hash=owner_pub_key_hash,
                                                           key=FAMILY_NAME_DIGITALID)
            LOGGER.debug("quorum_address : {}".format(quorum_address))

            if quorum_address not in to_address_list:
                raise InvalidTransaction("Quorum Output Address not valid")

            # verify trust score of each attribute on the basis of its state saved data
            # get quorum_state data, then update the quorums
            quorum_state_data = chain_access_util.get_state(cls.rest_api_url, quorum_address)

            if quorum_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
                raise InvalidTransaction("Quorum State invalid")

            LOGGER.debug("Existing quorum_state_data : {}".format(quorum_state_data))
            # if operation_type == digital_id_constants.TYPE_ID_CREATE:
            attribute_quorum_dict = quorum_state_data['attribute_quorum']
            # request_count_dict = quorum_state_data['request_count']

            txn_ids = quorum_state_data['peer_request_txn_ids']
            LOGGER.debug("peer request dependency {}".format(dependency))
            if dependency in txn_ids:
                LOGGER.debug("dependency {} present".format(dependency))
                txn_ids.remove(dependency)
                quorum_state_data['peer_request_txn_ids'] = txn_ids
            else:
                raise InvalidTransaction("Request by transaction {} already fulfilled".format(dependency))

            verification_detail_dict = {}
            try:
                verification_detail_dict = quorum_state_data['verification_detail']
            except KeyError:
                quorum_state_data['verification_detail'] = verification_detail_dict

            # saving trust_score in state
            attribute_set_msg = digital_id.attribute_set
            attribute_fields = attribute_set_msg.ListFields()
            attribute_fields_in_req = peer_request_id.attribute_set.ListFields()
            id_quorum_fulfilled = True
            for attribute_field in attribute_fields:
                field_in_req_value = [x[1] for x in attribute_fields_in_req if x[0] == attribute_field[0]][0]
                if attribute_field[0].name != 'others':
                    field_name = attribute_field[0].name
                    result = process_attribute_response(field_name=field_name, field_value=attribute_field[1],
                                                        field_in_req_value=field_in_req_value,
                                                        signer_pub_key=signer_pub_key_hex, client_info=client_info,
                                                        operation_type=operation_type,
                                                        quorum_state_data=quorum_state_data)
                    if result is False:
                        id_quorum_fulfilled = False

                    # LOGGER.debug("Validating field {}".format(field_name))
                    # id_attribute = attribute_field[1]
                    # if id_attribute.status == id_attribute_pb2.Status.CONFIRMED and \
                    #         field_in_req_value.status == id_attribute_pb2.Status.REQUESTED:
                    #     # verify if the id_attribute was requested
                    #
                    #     # verify certificate
                    #     LOGGER.debug("{} status confirmed".format(field_name))
                    #     is_verified = _verify_message_signature(id_attribute.attribute_data_enc,
                    #                                             id_attribute.certificate,
                    #                                             signer_pub_key_hex)
                    #     if is_verified is True:
                    #         try:
                    #             # verification_detail_dict[field_name].extend(client_info)
                    #             verification_detail_dict[field_name].extend([client_info.SerializeToString()])
                    #         except KeyError:
                    #             # TODO test this
                    #             verification_detail_dict[field_name] = []
                    #             verification_detail_dict[field_name].extend([client_info.SerializeToString()])
                    #
                    #         if operation_type == digital_id_constants.TYPE_ID_CREATE:
                    #             try:
                    #                 # total_quorum = attribute_quorum_dict[field_name] +
                    #                 # id_attribute.verification_quorum
                    #                 total_quorum = attribute_quorum_dict[field_name] + id_attribute.credibility_strength
                    #             except KeyError:
                    #                 # total_quorum = id_attribute.verification_quorum
                    #                 total_quorum = id_attribute.credibility_strength
                    #             # try:
                    #             #     verification_detail_dict[field_name].extend([client_info.SerializeToString()])
                    #             #     # verification_detail_dict[field_name].extend(responding_address)
                    #             # except KeyError:
                    #             #     # TODO test this
                    #             #     verification_detail_dict[field_name] = []
                    #             #     verification_detail_dict[field_name].extend([client_info.SerializeToString()])
                    #
                    #             attribute_quorum_dict[field_name] = total_quorum
                    #             LOGGER.debug("updated total_quorum : {}".format(attribute_quorum_dict[field_name]))
                    #             # total_peer_count = request_count_dict.get(field_name)
                    #             #
                    #             # if total_peer_count is None:
                    #             #     raise InternalError(
                    #             #         "Invalid quorum-state update: request count for {} does not exist".
                    #             #         format(field_name))
                    #             #
                    #             # elif total_peer_count < MIN_PEER_COUNT:
                    #             #     raise InvalidTransaction(
                    #             #         "Minimum peer count of {} has not reached for all attributes".format(
                    #             #             MIN_PEER_COUNT))
                    #             #
                    #             # target_peer_quorum = calculate_target_quorum(total_peer_count)
                    #             #
                    #             # if is_quorum_fulfilled(total_quorum, target_peer_quorum) is False:
                    #             #     id_quorum_fulfilled = False
                    #     else:
                    #         raise InvalidTransaction("{} Attribute certificate is invalid".format(field_name))
                    #
                    # total_peer_count = request_count_dict.get(field_name)
                    #
                    # if total_peer_count is None:
                    #     raise InternalError(
                    #         "Invalid quorum-state update: request count for {} does not exist".
                    #             format(field_name))
                    #
                    # elif total_peer_count < MIN_PEER_COUNT:
                    #     raise InvalidTransaction(
                    #         "Minimum peer count of {} has not reached for all attributes".format(
                    #             MIN_PEER_COUNT))
                    #
                    # target_peer_quorum = calculate_target_quorum(total_peer_count)
                    #
                    # if is_quorum_fulfilled(total_quorum, target_peer_quorum) is False:
                    #     id_quorum_fulfilled = False

                elif attribute_field[0].name == 'others':
                    attr_map = attribute_field[1]
                    for field_name in attr_map:
                        # id_attribute = attribute_field[1]
                        LOGGER.debug("Validating field {}".format(field_name))
                        # id_attribute = attr_map[field_name]
                        id_attribute_in_req = field_in_req_value.get(field_name)

                        result = process_attribute_response(field_name=field_name, field_value=attr_map[field_name],
                                                            field_in_req_value=id_attribute_in_req,
                                                            signer_pub_key=signer_pub_key_hex, client_info=client_info,
                                                            operation_type=operation_type,
                                                            quorum_state_data=quorum_state_data)
                        if result is False:
                            id_quorum_fulfilled = False
                        # if id_attribute.status == id_attribute_pb2.Status.CONFIRMED and \
                        #         id_attribute_in_req.status == id_attribute_pb2.Status.REQUESTED:
                        #     # verify attribute certificate
                        #     is_verified = _verify_message_signature(id_attribute.attribute_data_enc,
                        #                                             id_attribute.certificate,
                        #                                             signer_pub_key_hex)
                        #     if is_verified is True:
                        #
                        #         try:
                        #             # verification_detail_dict[field_name].extend(client_info)
                        #             verification_detail_dict[field_name].extend([client_info.SerializeToString()])
                        #         except KeyError:
                        #             # TODO test this
                        #             verification_detail_dict[field_name] = []
                        #             verification_detail_dict[field_name].extend([client_info.SerializeToString()])
                        #
                        #         if operation_type == digital_id_constants.TYPE_ID_CREATE:
                        #             try:
                        #                 total_quorum = attribute_quorum_dict[field_name] + \
                        #                                id_attribute.credibility_strength
                        #                 # id_attribute.verification_quorum
                        #             except KeyError:
                        #                 # total_quorum = id_attribute.verification_quorum
                        #                 total_quorum = id_attribute.credibility_strength
                        #
                        #             attribute_quorum_dict[field_name] = total_quorum
                        #             # total_peer_count = request_count_dict[field_name]
                        #             # if total_peer_count is None:
                        #             #     raise InternalError("Invalid quorum-state update: request count for {} does "
                        #             #                         "not exist".format(field_name))
                        #             # elif total_peer_count < MIN_PEER_COUNT:
                        #             #     raise InvalidTransaction(
                        #             #         "Minimum peer count of {} has not reached for all attributes".format(
                        #             #             MIN_PEER_COUNT))
                        #             #
                        #             # target_peer_quorum = calculate_target_quorum(total_peer_count)
                        #             # if is_quorum_fulfilled(total_quorum, target_peer_quorum) is False:
                        #             #     id_quorum_fulfilled = False
                        #     else:
                        #         raise InvalidTransaction("{} Attribute certificate is invalid".format(field_name))
                        #
                        # total_peer_count = request_count_dict[field_name]
                        # if total_peer_count is None:
                        #     raise InternalError("Invalid quorum-state update: request count for {} does "
                        #                         "not exist".format(field_name))
                        # elif total_peer_count < MIN_PEER_COUNT:
                        #     raise InvalidTransaction(
                        #         "Minimum peer count of {} has not reached for all attributes".format(
                        #             MIN_PEER_COUNT))
                        #
                        # target_peer_quorum = calculate_target_quorum(total_peer_count)
                        # if is_quorum_fulfilled(total_quorum, target_peer_quorum) is False:
                        #     id_quorum_fulfilled = False

            if operation_type == digital_id_constants.TYPE_ID_CREATE:
                quorum_state_data['attribute_quorum'] = attribute_quorum_dict
                quorum_state_data['id_quorum_reached'] = id_quorum_fulfilled
                LOGGER.debug("attribute_quorum : {}".format(quorum_state_data['attribute_quorum']))
                LOGGER.debug("id_quorum_reached : {}".format(quorum_state_data['id_quorum_reached']))

            quorum_state_data['peer_response_txn_ids'].append(transaction_id)
            # TODO added
            quorum_state_data['verification_detail'] = verification_detail_dict

            LOGGER.debug("dependency : {}".format(quorum_state_data['dependency']))
            LOGGER.debug("peer_response_txn_ids : {}".format(quorum_state_data['peer_response_txn_ids']))
            LOGGER.debug("peer_request_txn_ids : {}".format(quorum_state_data['peer_request_txn_ids']))

            quorum_state = cbor.dumps(quorum_state_data)

            addresses = context.set_state({  # request_address: state_data,
                quorum_address: quorum_state})

            if len(addresses) < 1:
                raise InternalError("State Error")
            # request_address = ""
            context.add_event(
                event_type='peer_verification/response',
                attributes=[
                    ('address', str(quorum_address)),  # FAMILY_NAME + SEND_FROM
                    ('signer_public_key', str(signer_pub_key_hex)),  # why send with event?
                    ('transaction_id', str(transaction_id)),
                    ('send_to', str(owner_pub_key_hash)),
                    ('sent_from', str(responding_address))
                ]
                # data=owner_sig_str.encode('utf-8')
            )

    @classmethod
    def _verify_digital_id(cls, stored_id, cur_id, total_peer_count, update_count):

        """Verifies digital id in peer request and
        updates cls.request_count_dict with attribute wise request count"""

        flag = True
        min_peer_req = True
        if update_count is True:
            request_count_cpy = dict.copy(cls.request_count_dict)
        else:
            request_count_cpy = None
        LOGGER.debug("cur_id: {}".format(cur_id))
        if stored_id.id_owner_public_key != cur_id.id_owner_public_key:
            LOGGER.debug("id_owner_public_key in transaction does not match with stored id_owner_public_key")
            LOGGER.debug("prev_id.id_owner_public_key {}".format(stored_id.id_owner_public_key))
            LOGGER.debug("cur_id.id_owner_public_key {}".format(cur_id.id_owner_public_key))
            flag = False
        if stored_id.validity_in_years != cur_id.validity_in_years:
            LOGGER.debug("validity_in_years in transaction does not match with stored validity_in_years")
            flag = False
        stored_attribute_fields = stored_id.attribute_set.ListFields()
        cur_attribute_fields = cur_id.attribute_set.ListFields()
        # stored_field_names = [x[0].name for x in stored_attribute_fields]
        # cur_field_names = [x[0].name for x in cur_attribute_fields]
        # LOGGER.debug("stored_field_names {}".format(stored_field_names))
        # LOGGER.debug("cur_field_names {}".format(cur_field_names))
        for attribute_field in cur_attribute_fields:
            field_name = attribute_field[0].name
            try:
                stored_field_value = [x[1] for x in stored_attribute_fields if x[0] == attribute_field[0]][0]
            except IndexError:
                LOGGER.debug("{} is not present in the stored ID".format(field_name))
                flag = False
                break

            if field_name != 'others':
                LOGGER.debug("Checking field in attribute_set: %s", field_name)
                if stored_field_value.certificate != attribute_field[1].certificate:
                    LOGGER.debug("certificate in transaction does not match with stored certificate")
                    flag = False
                    break
                if stored_field_value.attribute_data_enc != attribute_field[1].attribute_data_enc:
                    LOGGER.debug("attribute_data_enc in transaction does not match with stored attribute_data_enc")
                    flag = False
                    break
                if attribute_field[1].status == id_attribute_pb2.Status.REQUESTED and request_count_cpy is not None:
                    count = request_count_cpy.get(field_name)
                    if count is None:
                        request_count_cpy[field_name] = 1
                    else:
                        request_count_cpy[field_name] = count + 1

                    LOGGER.debug("Attribute {} has request count {}".format(field_name, request_count_cpy[field_name]))

                    if request_count_cpy[field_name] < MIN_PEER_COUNT:
                        min_peer_req = False
                    else:
                        min_peer_req = True

                    if request_count_cpy[field_name] > MAX_PEER_COUNT:
                        raise InvalidTransaction(
                            "Maximum permissible number of total peers is 4 {}".format(MAX_PEER_COUNT))

            elif field_name == 'others':
                attr_map = attribute_field[1]
                for key_name in attr_map:
                    field_value = attr_map[key_name]
                    LOGGER.debug("Checking field in dictionary 'others': %s", key_name)
                    stored_value = stored_field_value.get(key_name)

                    if stored_value.certificate != field_value.certificate:
                        LOGGER.debug("certificate in transaction does not match with stored certificate")
                        flag = False
                        break
                    if stored_value.attribute_data_enc != field_value.attribute_data_enc:
                        LOGGER.debug(
                            "attribute_data_enc in transaction does not match with stored attribute_data_enc")
                        flag = False
                        break
                    if field_value.status == id_attribute_pb2.Status.REQUESTED and request_count_cpy is not None:
                        count = request_count_cpy.get(key_name)
                        if count is None:
                            request_count_cpy[key_name] = 1
                        else:
                            request_count_cpy[key_name] = count + 1

                        LOGGER.debug(
                            "Attribute {} has request count {}".format(key_name, request_count_cpy[key_name]))

                        if request_count_cpy[key_name] < MIN_PEER_COUNT:
                            min_peer_req = False
                        else:
                            min_peer_req = True

                        if request_count_cpy[key_name] > MAX_PEER_COUNT:
                            raise InvalidTransaction(
                                "Maximum permissible number of total peers is {}".format(MAX_PEER_COUNT))

                    # if field_value.status != id_attribute_pb2.Status.CONFIRMED:
                    #     LOGGER.debug(
                    #         "id_owner_public_key in transaction does not match with stored id_owner_public_key")
                    #     flag = False
                    #     LOGGER.debug("Attribute {} is not confirmed".format(key_name))

        if flag is False:
            raise InvalidTransaction("Invalid Digital ID in transaction")
        else:
            if len(cls.batch_transactions) == total_peer_count and min_peer_req is False:
                raise InvalidTransaction("Minimum peer count of {} has not reached for all attributes".
                                         format(MIN_PEER_COUNT))
            if update_count is True:
                dict.update(cls.request_count_dict, request_count_cpy)
            LOGGER.debug("cls.request_count_dict {}".format(cls.request_count_dict))


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
    try:
        if args is None:
            args = sys.argv[1:]
        parser = create_parser(prog_name)
        results = parser.parse_args(args)
        verbose_level = results.verbosity
        # initialize the logger
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
        tp_processor = TransactionProcessor(url=validator_url)
        app_namespace = hashing.get_tf_prefix(FAMILY_NAME_PEER_VERIFY)
        tp_handler = PeerVerificationHandler(app_namespace)
        PeerVerificationHandler.rest_api_url = api_url
        tp_processor.add_handler(tp_handler)
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
