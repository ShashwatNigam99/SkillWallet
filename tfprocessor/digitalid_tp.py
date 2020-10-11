#!/usr/bin/env python3

"""
DigitalIdTransactionHandler class interfaces for digitalid Transaction Family.

"""
import argparse
import logging
import os
import sys
import traceback
from sys import path

import cbor
from colorlog import ColoredFormatter
from sawtooth_sdk.processor.core import TransactionProcessor
from sawtooth_sdk.processor.exceptions import InternalError
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_signing import create_context
from sawtooth_signing.secp256k1 import Secp256k1PublicKey

path.append(os.getcwd())
from protobuf import digital_id_transaction_pb2, digital_id_pb2, id_attribute_pb2
from util import chain_access_util, hashing

DEFAULT_VALIDATOR_URL = 'tcp://localhost:4004'
DEFAULT_REST_API_URL = 'http://localhost:8008'

LOGGER = logging.getLogger('digitalid_tp')
LOGGER.setLevel(logging.INFO)  # Default log level if setup_logger not used

FAMILY_NAME_LEARNER = 'learner'
FAMILY_NAME_CERTIFY = "certifier"
FAMILY_NAME_CLIENT = 'client_info'


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


# class DigitalIdClientTransactionHandler(TransactionHandler):
#     rest_api_url = None
#     LOGGER.debug("rest_api_url {}".format(rest_api_url))
#
#     def __init__(self, namespace_prefix):
#         self._namespace_prefix = namespace_prefix
#
#     @property
#     def family_name(self):
#         """Return Transaction Family name string."""
#         return FAMILY_NAME_CLIENT
#
#     @property
#     def family_versions(self):
#         """Return Transaction Family version string."""
#         return ['1.0']
#
#     @property
#     def namespaces(self):
#         """Return Transaction Family namespace 6-character prefix."""
#         return self._namespace_prefix
#
#     def apply(self, transaction, context):
#         LOGGER.debug("Inside apply()")
#         header = transaction.header
#
#         if len(header.outputs) == 0:
#             raise InvalidTransaction("Invalid transaction output list")
#
#         if len(header.inputs) == 0:
#             raise InvalidTransaction("Invalid transaction input list")
#
#         signer_pub_key_hex = header.signer_public_key
#         public_address = hashing.get_pub_key_hash(signer_pub_key_hex)
#         payload = transaction.payload
#
#         try:
#             state_update_transaction = client_pb2.StateUpdateTransaction()
#             state_update_transaction.ParseFromString(payload)
#             action = state_update_transaction.action
#             # if state_update_transaction.HasField('data'):
#             txn_data = state_update_transaction.data
#
#         except BaseException as err:
#             raise Exception(err)
#
#         if action == digital_id_constants.UPDATE_STATE_ACK:
#
#             # to_address = header.outputs[0]
#             # if len(header.outputs) == 2:
#             #     quorum_address = header.outputs[1]
#             # LOGGER.debug("quorum_address {}".format(quorum_address))
#             from_address = header.inputs[0]
#             if len(header.dependencies) != 1:
#                 raise InvalidTransaction("Invalid transaction dependency list")
#             dependency = header.dependencies[0]
#             self._update_ack(context, header.outputs, from_address, public_address, dependency, txn_data)
#         else:
#             raise InvalidTransaction("Operation not allowed")
#
#     @classmethod
#     def _update_ack(cls, context, to_addresses, from_address, public_address, dependency, txn_data):
#         LOGGER.debug("Inside _update_ack")
#
#         # verify the self state address
#         self_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_LEARNER,
#                                                            key='self',
#                                                            pub_key_hash=public_address)
#
#         LOGGER.debug("Self State address {}".format(self_state_address))
#         id_creation_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_LEARNER,
#                                                             key=FAMILY_NAME_CERTIFY,
#                                                             pub_key_hash=public_address)
#         if id_creation_address != from_address:
#             LOGGER.debug("Expected id_creation_address {}".format(id_creation_address))
#             raise InvalidTransaction("Invalid transaction input address")
#
#         # if self_state_address != to_address:
#         if self_state_address not in to_addresses:
#             LOGGER.debug("Expected self_state_address {}".format(self_state_address))
#             raise InvalidTransaction("Invalid transaction output address")
#
#         data_dict = cbor.loads(txn_data)
#
#         if data_dict['address'] != id_creation_address:
#             raise InvalidTransaction("Invalid operation - invalid state address in data")
#
#         # get quorum_state data, then update the quorums
#         id_state_data = chain_access_util.get_state(cls.rest_api_url, id_creation_address)
#
#         LOGGER.debug("Existing id_state_data : {}".format(id_state_data))
#
#         if id_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
#             raise InvalidTransaction("ID creation state invalid")
#
#         self_state_data = chain_access_util.get_state(cls.rest_api_url, self_state_address)
#
#         LOGGER.debug("Existing self_state_data : {}".format(self_state_data))
#
#         if self_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
#             raise InvalidTransaction("Invalid operation - self state not initiated")
#
#         # Added changes Apr 11
#         digital_id_byte = self_state_data['digital_id']
#         if digital_id_byte is None or digital_id_byte == b'':
#             raise InvalidTransaction("digital_id in self_state is not set")
#
#         if dependency != id_state_data['acting_transaction_id']:
#             raise InvalidTransaction("Invalid Transaction ID in dependency")
#
#         if data_dict['transaction_id'] != id_state_data['acting_transaction_id']:
#             raise InvalidTransaction("Invalid acknowledgement number in data")
#
#         #  checking if user_confirmation_txn are same in both id_creation_state and self_state
#
#         if self_state_data['user_confirmation_txn'] != id_state_data['user_confirmation_txn']:
#             raise InvalidTransaction("Self state is not updated with the latest confirmed ID")
#
#         txn_response = chain_access_util.get_transaction(base_url=cls.rest_api_url, requesting_txn_id=dependency)
#         txn_header = txn_response['header']
#         transactor_pub_key = txn_header['signer_public_key']
#         LOGGER.debug("transactor_pub_key: {}".format(transactor_pub_key))
#
#         if transactor_pub_key != cls.primary_certifier_pubkey:
#             raise InvalidTransaction("The dependency transaction is not signed by primary certifier")
#
#         LOGGER.debug("Dependency of acknowledgement transaction: {}".format(txn_header['dependencies']))
#         LOGGER.debug("user_confirmation_txn: {}".format(self_state_data['user_confirmation_txn']))
#         if self_state_data['user_confirmation_txn'] != txn_header['dependencies'][0]:
#             raise InvalidTransaction("The acknowledgement transaction does not have a valid dependency confirmation")
#         try:
#             txn_payload = txn_response['payload']
#             digital_id_transaction = digital_id_transaction_pb2.DigitalIdTransaction()
#             digital_id_transaction.ParseFromString(base64.b64decode(txn_payload))
#             _verify_digital_id_txn(digital_id_transaction)
#             transaction_status = digital_id_transaction.status
#             certifier_signature = digital_id_transaction.certifier_signature
#
#             # verify if the dependency txn status ACK_CONFIRMED
#             if transaction_status != id_attribute_pb2.ACK_CONFIRMED:
#                 raise InvalidTransaction("The dependency transaction is not a valid ID confirmation acknowledgement")
#
#             # checking if certifier-signature can be verified with the stored data
#             is_verified = _verify_message_signature(digital_id_byte, certifier_signature, transactor_pub_key)
#             if is_verified == 0:
#                 LOGGER.error('DigitalIdTransaction.certifier_signature invalid')
#                 raise InvalidTransaction('DigitalIdTransaction.certifier_signature invalid')
#         except BaseException as err:
#             LOGGER.error("Error while reading transaction data {}".format(err))
#             raise InvalidTransaction("Error while reading dependency transaction data")
#
#         self_state_data['ack_number'] = id_state_data['acting_transaction_id']
#
#         addresses = context.set_state({self_state_address: cbor.dumps(self_state_data)})
#
#         if len(addresses) < 1:
#             raise InternalError("State Error")
#         LOGGER.debug("state updated")

class DigitalIdTransactionHandler(TransactionHandler):
    """
    Transaction Processor class for the DigitalID Transaction Family.

    This TP communicates with the Validator using the accept/get/set functions.

    """
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
        return FAMILY_NAME_LEARNER

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
           processing a transaction for the 'learner' transaction family.
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
        status = digital_id_transaction.status
        digital_id = None
        # verify the digital_id status and owner's public key with the transaction level information
        try:
            if status == id_attribute_pb2.PII_REGISTERED:
                digital_id = digital_id_pb2.PII_credential()
            elif status == id_attribute_pb2.SKILL_REGISTERED:
                digital_id = digital_id_pb2.learning_credential()

            digital_id.ParseFromString(digital_id_byte)

            if signer_pub_key_hex != digital_id.id_owner_public_key:
                raise InvalidTransaction("ID owner's public key not matching with transaction signer's")
        except BaseException as err:
            raise Exception(err)

        owner_sig_str = digital_id_transaction.owner_signature
        LOGGER.debug("owner_sig_str = %s.", owner_sig_str)

        is_verified = _verify_message_signature(digital_id_byte, owner_sig_str, signer_pub_key_hex)
        if is_verified == 0:
            LOGGER.error('DigitalIdTransaction.owner_signature invalid')
            raise InvalidTransaction('DigitalIdTransaction.owner_signature invalid')

        if status == id_attribute_pb2.PII_REGISTERED:
            self._register_pii(context, to_address_list, transaction_id,
                               digital_id_byte,  # owner_sig_str,
                               signer_pub_key_hex)

        elif status == id_attribute_pb2.SKILL_REGISTERED:
            certifier_address = digital_id_transaction.receiver_address

            self._register_skill(context, to_address_list, transaction_id,
                                 digital_id_byte, signer_pub_key_hex, certifier_address)

    @classmethod
    def _register_pii(cls, context, to_address_list, transaction_id, digital_id_byte,
                      signer_pub_key_hex):

        LOGGER.debug("Inside _register_id method")

        # Verify if the output state address is valid for PII_REGISTER action

        signer_pub_key_hash = hashing.get_pub_key_hash(signer_pub_key_hex)
        self_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_LEARNER,
                                                           pub_key_hash=signer_pub_key_hash,
                                                           key='self')
        LOGGER.debug("self_state_address : {}".format(self_state_address))
        if self_state_address not in to_address_list:
            raise InvalidTransaction("Output Address not valid")

        state_data = cbor.dumps({
            'pii_credential': digital_id_byte,
            'acting_transaction_id': transaction_id
        })
        LOGGER.debug("State-data : {}".format(state_data))
        addresses = context.set_state({self_state_address: state_data})

        if len(addresses) < 1:
            raise InternalError("State Error")
        LOGGER.debug("state updated")

        context.add_event(
            event_type='learner/pii_register',
            attributes=[
                ('address', str(self_state_address)),
                ('transaction_id', str(transaction_id)),
                ('send_to', str(signer_pub_key_hash))
            ]
        )

    @classmethod
    def _register_skill(cls, context, to_address_list, transaction_id, digital_id_byte,
                        signer_pub_key_hex, certifier_address):

        LOGGER.debug("Inside _register_id method")

        # TODO verify if the certifier_address is authorized using global registry

        # Verify if the output state address is valid for this action
        signer_pub_key_hash = hashing.get_pub_key_hash(signer_pub_key_hex)
        output_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_LEARNER,
                                                             pub_key_hash=signer_pub_key_hash,
                                                             key=certifier_address)
        LOGGER.debug("request_address : {}".format(output_state_address))
        if output_state_address not in to_address_list:
            raise InvalidTransaction("Output Address not valid")
        id_state_data = chain_access_util.get_state(cls.rest_api_url, output_state_address)
        LOGGER.debug("Existing ID state_data : {}".format(id_state_data))
        id_state_data['skill_credential'] = digital_id_byte
        id_state_data['acting_transaction_id'] = transaction_id
        state_data = cbor.dumps(id_state_data)
        LOGGER.debug("State-data : {}".format(state_data))
        addresses = context.set_state({output_state_address: state_data})

        if len(addresses) < 1:
            raise InternalError("State Error")
        LOGGER.debug("state updated")

        context.add_event(
            event_type='learner/skill_register',
            attributes=[
                ('address', str(output_state_address)),
                ('sent_from', str(signer_pub_key_hash)),
                ('transaction_id', str(transaction_id)),
                ('send_to', str(certifier_address))
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
        tp_processor = TransactionProcessor(url=validator_url)
        app_namespace = hashing.hash512(FAMILY_NAME_LEARNER.encode('utf-8'))[0:6]
        # creating Handler classes
        id_app_handler = DigitalIdTransactionHandler([app_namespace])
        # Setting field rest_api_url
        DigitalIdTransactionHandler.rest_api_url = api_url
        tp_processor.add_handler(id_app_handler)
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
