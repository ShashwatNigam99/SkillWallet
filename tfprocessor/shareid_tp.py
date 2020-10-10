#!/usr/bin/env python3

"""Transaction Handle class for shared_id transaction family"""

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
from sawtooth_sdk.processor.exceptions import InvalidTransaction, InternalError
from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_signing import create_context
from sawtooth_signing.secp256k1 import Secp256k1PublicKey

path.append(os.getcwd())
from constants import digital_id_constants
from protobuf import shared_id_pb2
from protobuf.digital_id_transaction_pb2 import DigitalIdTransaction
from util import hashing, chain_access_util

DEFAULT_VALIDATOR_URL = 'tcp://localhost:4004'
DEFAULT_REST_API_URL = 'http://localhost:8008'

LOGGER = logging.getLogger('shareid_tp')

FAMILY_CERTIFY = "digitalid_certifier"
FAMILY_DIGITAL_ID = "digitalid"
FAMILY_SHARED_ID = "shared_id"
FAMILY_CERTIFIER_CLIENT = 'certifier_client_info'


def _verify_message_signature(digital_id_hash, owner_sig_str, signer_pub_key_hex):
    LOGGER.debug("Inside _verify_message_signature")
    signer_pub_key = Secp256k1PublicKey.from_hex(signer_pub_key_hex)
    context_obj = create_context('secp256k1')
    # digital_id_hash = hashing.get_hash_from_bytes(digital_id_byte)
    result = context_obj.verify(owner_sig_str, digital_id_hash, signer_pub_key)
    return result


def create_file_handler():
    # configure logger
    file_handler = logging.FileHandler('shareid_tp.log')
    file_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    return file_handler


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


def setup_loggers(verbose_level):
    """Setup logging."""
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
    LOGGER.addHandler(create_file_handler())


class ShareIdTransactionHandler(TransactionHandler):
    """
    Transaction Processor class for the SharedID Transaction Family.
    This TP communicates with the Validator using the accept/get/set functions.
    """
    rest_api_url = DEFAULT_REST_API_URL

    def __init__(self, namespace_prefix):
        """Initialize the transaction handler class.
           This is setting the "digitalid" TF namespace prefix.
        """
        self._namespace_prefix = namespace_prefix

    @property
    def family_name(self):
        """Return Transaction Family name string."""
        return FAMILY_SHARED_ID

    @property
    def family_versions(self):
        """Return Transaction Family version string."""
        return ['1.0']

    @property
    def namespaces(self):
        """Return Transaction Family namespace 6-character prefix."""
        return self._namespace_prefix

    def apply(self, transaction, context):
        header = transaction.header
        if len(header.outputs) != 1:
            raise InvalidTransaction("Invalid transaction output list")

        to_address = header.outputs[0]
        signer_pub_key_hex = header.signer_public_key
        public_address = hashing.get_pub_key_hash(signer_pub_key_hex)
        payload = transaction.payload
        transaction_id = transaction.signature
        LOGGER.debug("transaction id: {}".format(transaction_id))
        try:
            share_id_transaction = shared_id_pb2.ShareIDTransaction()
            share_id_transaction.ParseFromString(payload)
            share_id_payload = share_id_transaction.payload
            action = share_id_transaction.action
            if action == digital_id_constants.SHARE_ID_REQUEST:
                shared_ID_request = shared_id_pb2.ShareIdRequest()
                shared_ID_request.ParseFromString(share_id_payload)
                self._share_request(context, public_address, shared_ID_request, to_address, transaction_id, signer_pub_key_hex)

            elif action == digital_id_constants.SHARE_ID_RESPONSE:
                shared_ID_response = shared_id_pb2.ShareIdResponse()
                shared_ID_response.ParseFromString(share_id_payload)
                self._share_response(context, signer_pub_key_hex, shared_ID_response,
                                     to_address, header.inputs, transaction_id)
        except BaseException as err:
            raise Exception(err)

    @classmethod
    def _share_request(cls, context, transactor, shared_id_request, to_address, transaction_id, signer_pub_key_hex):
        LOGGER.debug("Inside _share_request")
        recv_from = shared_id_request.recv_id_from_address
        # verify the self state address
        # TODO have to directly use the ouput address when recv_id_from_address not present
        state_address = hashing.get_digitalid_address(family_name=FAMILY_SHARED_ID,
                                                      key=transactor,
                                                      pub_key_hash=recv_from)
        if state_address != to_address:
            LOGGER.debug("Expected self_state_address {}".format(state_address))
            raise InvalidTransaction("Invalid transaction output address")

        data_require_flag = shared_id_request.ID_data_requested
        LOGGER.debug("data_require_flag {}".format(data_require_flag))
        if data_require_flag:
            contract_bytes = shared_id_request.contract_detail
            LOGGER.debug("contract_bytes {}".format(contract_bytes))
            if contract_bytes is None or contract_bytes == b'':
                raise InvalidTransaction("shared_id_request.contract_detail can not be empty if data requested")
            contract_sig = shared_id_request.contract_signature
            if contract_sig is None or contract_sig == b'':
                raise InvalidTransaction("shared_id_request.contract_signature can not be empty if data requested")

            is_verified = _verify_message_signature(hashing.get_hash_from_bytes(contract_bytes),
                                                    contract_sig,
                                                    signer_pub_key_hex)
            if is_verified == 0:
                LOGGER.error('shared_id_request.contract_signature could not be verified')
                raise InvalidTransaction('shared_id_request.contract_signature failed verification')
        # TODO filter events based on ouput address instead of recv_id_from_address
        context.add_event(
            event_type='shareid/request',
            attributes=[
                ('to_address', str(recv_from)),
                ('received_from', str(transactor)),
                ('transaction_id', str(transaction_id))
            ],
            # data=hash_only.encode('utf-8')
        )

    @classmethod
    def _share_response(cls, context, signer_pub_key_hex, shared_id_response, to_address, input_address_list,
                        transaction_id):
        LOGGER.debug("Inside _share_response")
        send_to = shared_id_response.send_to_address
        owner_address = hashing.get_pub_key_hash(signer_pub_key_hex)
        # verify the self state address
        # TODO may use alternative way to verify the output address is derived from the signer_pub_key
        share_state_address = hashing.get_digitalid_address(family_name=FAMILY_SHARED_ID,
                                                            key=send_to,
                                                            pub_key_hash=owner_address)
        if share_state_address != to_address:
            LOGGER.debug("Expected self_state_address {}".format(share_state_address))
            LOGGER.debug("not in to_address {}".format(to_address))
            raise InvalidTransaction("Invalid transaction output address")

        # TODO remove digital_id_hash verification
        # is_verified = _verify_message_signature(shared_id_response.digital_id_hash,
        #                                         shared_id_response.digital_signature,
        #                                         signer_pub_key)

        # TODO remove id_info, take the required info directly from the saved_state
        # save the info in the shared state space
        # id_info = shared_id_pb2.Id_info()
        # id_info.ParseFromString(shared_id_response.Id_info)
        # conf_txn = id_info.id_confirmation_txn
        # creating_pub_key = id_info.id_creating_pub_key

        # if creating_pub_key != signer_pub_key:
        #     LOGGER.debug("Expected public key {}".format(creating_pub_key))
        #     raise InvalidTransaction("Invalid owner {}".format(signer_pub_key))

        # fetch self-state of the ID owner
        self_state_address = hashing.get_digitalid_address(family_name=FAMILY_DIGITAL_ID,
                                                           pub_key_hash=owner_address,
                                                           key='self')
        if self_state_address not in input_address_list:
            raise InvalidTransaction("Self State input Address not valid")

        id_response = chain_access_util.get_state(base_url=DEFAULT_REST_API_URL, address=self_state_address)
        LOGGER.debug("Existing ID state_data : {}".format(id_response))

        if id_response == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
            LOGGER.debug("ID data does not exist at address {}".format(self_state_address))
            raise InvalidTransaction("ID data does not exist")

        # if id_response['ack_number'] != conf_txn:
        #     LOGGER.debug("expected acknowledgement : {}".format(id_response['ack_number']))
        #     raise InvalidTransaction("Invalid dependency given")

        stored_id = id_response['digital_id']
        # stored_id_hash = hashing.get_hash_from_bytes(id_response['digital_id'])

        # match the id hashes
        # if stored_id_hash != shared_id_response.digital_id_hash:
        #     LOGGER.debug("expected hash : {}".format(stored_id_hash))
        #     raise InvalidTransaction("Invalid digital id hash")

        conf_txn = id_response['ack_number']
        # Checking validity of the self-state data
        txn_response = chain_access_util.get_transaction(base_url=DEFAULT_REST_API_URL, requesting_txn_id=conf_txn)
        try:
            # txn_header = txn_response['header']
            # certifier_pub_key_hex = txn_header['signer_public_key']
            txn_payload = txn_response['payload']
            digital_id_transaction = DigitalIdTransaction()
            digital_id_transaction.ParseFromString(base64.b64decode(txn_payload))
            owner_signature = digital_id_transaction.owner_signature
            # certifier_signature = digital_id_transaction.certifier_signature
            # This check may fail
            # if stored_id != digital_id_transaction.digital_id:
            #     LOGGER.error("id data not same in state and transaction")
            #     raise Exception("Invalid digital ID or transaction for ID request")

            # txn_id_hash = hashing.get_hash_from_bytes(digital_id_transaction.digital_id)
            # if txn_id_hash != shared_id_response.digital_id_hash:
            #     LOGGER.debug("expected hash : {}".format(txn_id_hash))
            #     raise InvalidTransaction("Invalid digital id hash")

            is_verified = _verify_message_signature(hashing.get_hash_from_bytes(stored_id),
                                                    shared_id_response.digital_signature,
                                                    signer_pub_key_hex)
            if is_verified == 0:
                LOGGER.error('shared_id_response.digital_signature could not be verified')
                raise InvalidTransaction('shared_id_response.digital_signature')

            # is_verified = _verify_message_signature(hashing.get_hash_from_bytes(digital_id_transaction.digital_id),
            #                                         certifier_signature,
            #                                         certifier_pub_key_hex)
            # if is_verified == 0:
            #     LOGGER.error('digital_id_transaction.certifier_signature')
            #     raise InvalidTransaction('digital_id_transaction.owner_signature')
            id_info = {"id_confirmation_txn": conf_txn}
            shared_data = cbor.dumps(id_info)
            addresses = context.set_state({share_state_address: shared_data
                                           })

            if len(addresses) < 1:
                raise InternalError("State Error")

        except BaseException as err:
            LOGGER.error("Error while reading transaction data {}".format(err))
            raise InvalidTransaction("Error while reading transaction data")

        context.add_event(
            event_type='shareid/response',
            attributes=[
                ('to_address', str(send_to)),
                ('received_from', str(owner_address)),
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
    # setup_loggers()
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
        tp_processor = TransactionProcessor(url=DEFAULT_VALIDATOR_URL)
        app_namespace = hashing.hash512(FAMILY_SHARED_ID.encode('utf-8'))[0:6]
        tp_handler = ShareIdTransactionHandler([app_namespace])
        ShareIdTransactionHandler.rest_api_url = api_url
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
