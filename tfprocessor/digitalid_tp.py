#!/usr/bin/env python3

"""
DigitalIdTransactionHandler class interfaces for learner Transaction Family.

"""
import argparse
import base64
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
from constants import digital_id_constants

DEFAULT_VALIDATOR_URL = 'tcp://localhost:4004'
DEFAULT_REST_API_URL = 'http://localhost:8008'

LOGGER = logging.getLogger('digitalid_tp')
LOGGER.setLevel(logging.INFO)  # Default log level if setup_logger not used

FAMILY_NAME_LEARNER = 'learner'


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


class DigitalIdTransactionHandler(TransactionHandler):
    """
    Transaction Processor class for the LEARNER Transaction Family.

    This TP communicates with the Validator using the accept/get/set functions.

    """
    rest_api_url = None
    LOGGER.debug("rest-api-url : {}", rest_api_url)

    def __init__(self, namespace_prefix):
        """Initialize the transaction handler class.
           This is setting the "learner" TF namespace prefix.
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
        digital_sig_str = None
        # verify the digital_id status and owner's public key with the transaction level information
        try:
            if status == id_attribute_pb2.PII_REGISTERED:
                if digital_id_transaction.owner_signature == '':
                    LOGGER.error('DigitalIdTransaction.owner_signature invalid')
                    raise InvalidTransaction('DigitalIdTransaction.owner_signature invalid')
                digital_id = digital_id_pb2.PII_credential()
                digital_sig_str = digital_id_transaction.owner_signature
            elif status == id_attribute_pb2.SKILL_REGISTERED:
                if digital_id_transaction.owner_signature == '':
                    LOGGER.error('DigitalIdTransaction.owner_signature invalid')
                    raise InvalidTransaction('DigitalIdTransaction.owner_signature invalid')
                digital_id = digital_id_pb2.learning_credential()
                digital_sig_str = digital_id_transaction.owner_signature
            elif status == id_attribute_pb2.SKILL_ATTESTED:
                if digital_id_transaction.certifier_signature == '':
                    LOGGER.error('DigitalIdTransaction.certifier_signature invalid')
                    raise InvalidTransaction('DigitalIdTransaction.certifier_signature invalid')
                digital_sig_str = digital_id_transaction.certifier_signature
                digital_id = digital_id_pb2.learning_credential()

            digital_id.ParseFromString(digital_id_byte)

            if status != id_attribute_pb2.SKILL_ATTESTED:
                if signer_pub_key_hex != digital_id.id_owner_public_key:
                    raise InvalidTransaction("ID owner's public key not matching with transaction signer's")
        except BaseException as err:
            raise Exception(err)

        LOGGER.debug("digital_sig_str = %s.", digital_sig_str)

        is_verified = _verify_message_signature(digital_id_byte, digital_sig_str, signer_pub_key_hex)
        if is_verified == 0:
            LOGGER.error('DigitalIdTransaction.owner_signature invalid')
            raise InvalidTransaction('DigitalIdTransaction.owner_signature invalid')

        if status == id_attribute_pb2.PII_REGISTERED:
            self._register_pii(context, to_address_list, transaction_id,
                               digital_id_byte, signer_pub_key_hex)

        elif status == id_attribute_pb2.SKILL_REGISTERED:
            certifier_address = digital_id_transaction.receiver_address

            self._register_skill(context, to_address_list, transaction_id,
                                 digital_id_byte, signer_pub_key_hex, certifier_address)
        elif status == id_attribute_pb2.SKILL_ATTESTED:
            dependency_list = header.dependencies
            LOGGER.debug("header.dependencies: {}".format(dependency_list))

            self._attest_skill(context, digital_id_byte, to_address_list,
                               transaction_id, signer_pub_key_hex, dependency_list)

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

        LOGGER.debug("Inside _register_skill method")

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
        state_data = cbor.dumps({
            'skill_credential': digital_id_byte,
            'acting_transaction_id': transaction_id
        })
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

    @classmethod
    def _attest_skill(cls, context, digital_id_byte, to_address_list,
                      transaction_id, signer_pub_key_hex, dependency_list):

        LOGGER.debug("Inside _attest_skill method")

        # TODO verify if the certifier_address is authorized using global registry

        if len(dependency_list) > 0:
            requesting_txn_id = dependency_list[0]
        else:
            LOGGER.error("Dependency of transaction {} is empty".format(transaction_id))
            raise InvalidTransaction("Transaction dependency cannot be empty")

        # Fetch header data from requesting_txn_id
        txn_response = chain_access_util.get_transaction(base_url=cls.rest_api_url, requesting_txn_id=requesting_txn_id)
        txn_header = txn_response['header']
        id_owner_pub_key = txn_header['signer_public_key']
        id_owner_pub_key_hash = hashing.get_pub_key_hash(id_owner_pub_key)

        # Verify if the output state address is valid for this action
        signer_pub_key_hash = hashing.get_pub_key_hash(signer_pub_key_hex)
        output_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_LEARNER,
                                                             pub_key_hash=id_owner_pub_key_hash,
                                                             key=signer_pub_key_hash)
        LOGGER.debug("output_state_address : {}".format(output_state_address))
        if output_state_address not in to_address_list:
            raise InvalidTransaction("Output Address not valid")

        # verify validity of dependent transaction with state information
        id_state_data = chain_access_util.get_state(cls.rest_api_url, output_state_address)
        LOGGER.debug("Existing ID state_data : {}".format(id_state_data))

        if id_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE or \
                id_state_data['acting_transaction_id'] != requesting_txn_id:
            LOGGER.debug("expected dependency : {}".format(id_state_data['acting_transaction_id']))
            raise InvalidTransaction("Invalid dependency given")
        txn_payload = txn_response['payload']
        dependency_transaction = digital_id_transaction_pb2.DigitalIdTransaction()
        dependency_transaction.ParseFromString(base64.b64decode(txn_payload))
        if dependency_transaction.status != id_attribute_pb2.SKILL_REGISTERED:
            LOGGER.debug(
                "Dependency transaction status is {}. Skill Attest operation is not allowed".format(
                    dependency_transaction.status))
            raise InvalidTransaction(
                "Dependency transaction status is {}. Skill Attest operation is not allowed".format(
                    dependency_transaction.status))

        id_state_data['skill_credential'] = digital_id_byte
        id_state_data['acting_transaction_id'] = transaction_id
        state_data = cbor.dumps(id_state_data)
        LOGGER.debug("State-data : {}".format(state_data))

        # update owner's self-state data

        # owner_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_LEARNER,
        #                                                     pub_key_hash='self',
        #                                                     key=id_owner_pub_key_hash)
        # LOGGER.debug("output_state_address : {}".format(owner_state_address))
        # if owner_state_address not in to_address_list:
        #     LOGGER.debug('owner state cannot be updated')
        # else:
        #     id_state_data = chain_access_util.get_state(cls.rest_api_url, output_state_address)
        #     LOGGER.debug("Existing ID state_data : {}".format(id_state_data))

        addresses = context.set_state({output_state_address: state_data})

        if len(addresses) < 1:
            raise InternalError("State Error")
        LOGGER.debug("state updated")

        context.add_event(
            event_type='learner/skill_attest',
            attributes=[
                ('address', str(output_state_address)),
                ('sent_from', str(signer_pub_key_hash)),
                ('transaction_id', str(transaction_id)),
                ('send_to', str(id_owner_pub_key_hash))
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
