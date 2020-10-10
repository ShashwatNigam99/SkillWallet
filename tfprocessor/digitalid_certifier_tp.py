#!/usr/bin/env python3
import argparse
import hashlib
import logging
import os
import sys
import traceback
from sys import path

from cbor import cbor
from colorlog import ColoredFormatter
from sawtooth_sdk.processor.core import TransactionProcessor
from sawtooth_sdk.processor.exceptions import InternalError, InvalidTransaction
from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_signing import create_context
from sawtooth_signing.secp256k1 import Secp256k1PublicKey

# path.append('/home/suchira/digital-id')
# home = os.path.expanduser("~")
# proj_dir = os.path.join(home, "digital-id")

path.append(os.getcwd())
from util import chain_access_util, hashing
from protobuf import digital_id_pb2, digital_id_transaction_pb2, id_attribute_pb2, client_pb2
from constants import digital_id_constants

# import digital_id_transaction_pb2
# import id_attribute_pb2

DEFAULT_VALIDATOR_URL = 'tcp://localhost:4004'
DEFAULT_REST_API_URL = 'http://localhost:8008'

LOGGER = logging.getLogger('digitalid_certifier_tp')

FAMILY_CERTIFY = "digitalid_certifier"
FAMILY_DIGITAL_ID = "digitalid"
FAMILY_CERTIFIER_CLIENT = 'certifier_client_info'


def _get_public_key_file(key_file_name):
    """Get the private key from key_file_name."""
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")
    return '{}/{}.pub'.format(key_dir, key_file_name)


def _get_certifier_config():
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


def _hash(data):
    """Compute the SHA-512 hash and return the result as hex characters."""
    return hashlib.sha512(data).hexdigest()


def _hash_bytes(data_bytes):
    hash_obj = hashlib.sha512()
    hash_obj.update(data_bytes)
    return hash_obj.hexdigest().encode('utf-8')


def _get_pub_key_hash(public_key):
    """Generates hex string from double hash of public key"""
    sha_hash = hashlib.sha512(public_key.encode('utf-8')).digest()
    ripemd_hash = hashlib.new('ripemd160', sha_hash)
    return ripemd_hash.hexdigest()


def _get_digitalid_address(pub_key_hash=None):
    """Generates hexadecimal address as FAMILY_NAMESPACE.key.pub_key_hash"""
    if pub_key_hash is None:
        return _hash(FAMILY_DIGITAL_ID.encode('utf-8'))[0:6] + _hash(FAMILY_CERTIFY.encode('utf-8'))[0:64]
    else:
        return _hash(FAMILY_DIGITAL_ID.encode('utf-8'))[0:6] + \
               _hash(FAMILY_CERTIFY.encode('utf-8'))[0:24] + pub_key_hash


def _verify_digital_id_txn(digital_id_transaction):
    LOGGER.debug("Inside _verify_digital_id_txn")
    flag = True
    try:
        if digital_id_transaction.digital_id is 0:
            flag = False
            LOGGER.error("digital_id_transaction.digital_id is 0")

        if digital_id_transaction.owner_signature is "":
            flag = False
            LOGGER.error("digital_id_transaction.owner_signature is empty")

        if digital_id_transaction.certifier_signature is "":
            flag = False

        if digital_id_transaction.status is 0:
            flag = False
            LOGGER.error("digital_id_transaction.status is empty")
        LOGGER.debug("Flag value {}".format(flag))
        if flag is False:
            LOGGER.error("Invalid digital_id_transaction")
            raise InvalidTransaction("Invalid digital_id_transaction")
    except AttributeError:
        raise InvalidTransaction("Invalid message structure for DigitalIdTransaction")


def _verify_message_signature(digital_id_byte, owner_sig_str, signer_pub_key_hex):
    LOGGER.debug("Inside _verify_message_signature")
    signer_pub_key = Secp256k1PublicKey.from_hex(signer_pub_key_hex)
    context_obj = create_context('secp256k1')
    digital_id_hash = _hash_bytes(digital_id_byte)
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
    file_handler = logging.FileHandler('digitalid_certifier_tp.log')
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


class CertifierClientTransactionHandler(TransactionHandler):
    def __init__(self, namespace_prefix):
        self._namespace_prefix = namespace_prefix

    @property
    def family_name(self):
        """Return Transaction Family name string."""
        return FAMILY_CERTIFIER_CLIENT

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
        public_address = _get_pub_key_hash(signer_pub_key_hex)
        payload = transaction.payload
        try:
            client_info_transaction = client_pb2.ClientInfoSetupTransaction()
            client_info_transaction.ParseFromString(payload)
            trust_score = client_info_transaction.client_info.trust_score
        except BaseException as err:
            raise Exception(err)

        if trust_score != 0:
            # verify the self state address
            self_state_address = hashing.get_digitalid_address(family_name=FAMILY_CERTIFY,
                                                               key='self',
                                                               pub_key_hash=public_address)
            if self_state_address != to_address:
                LOGGER.debug("Expected self_state_address {}".format(self_state_address))
                raise InvalidTransaction("Invalid transaction output address")
            # state data is a dictionary
            state_data = cbor.dumps({
                'trust_score': trust_score
            })
            addresses = context.set_state({to_address: state_data})

            if len(addresses) < 1:
                raise InternalError("State Error")
            LOGGER.debug("state updated")


class CertifyTransactionHandler(TransactionHandler):
    certifier_dict = _get_certifier_config()
    primary_certifier_pubkey = certifier_dict.get('primary_certifier_pubkey')
    LOGGER.debug("primary_certifier_pubkey : {}".format(primary_certifier_pubkey))
    primary_certifier_address = hashing.get_pub_key_hash(primary_certifier_pubkey)
    LOGGER.debug("primary_certifier_address: {}".format(primary_certifier_address))
    rest_api_url = None
    LOGGER.debug("rest-api-url : {}", rest_api_url)

    def __init__(self, namespace_prefix):
        self._namespace_prefix = namespace_prefix

    @property
    def family_name(self):
        """Return Transaction Family name string."""
        return FAMILY_CERTIFY

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
            The apply function processes a transaction for the digitalid_certifier transaction family.
        """

        # Get the payload and extract the digital id-specific information.

        header = transaction.header
        if len(header.inputs) == 0:
            raise InvalidTransaction("Invalid transaction input list")

        if len(header.outputs) == 0:
            raise InvalidTransaction("Invalid transaction output list")

        to_address_list = header.outputs
        signer_pub_key_hex = header.signer_public_key
        # TODO
        if CertifyTransactionHandler.primary_certifier_pubkey != signer_pub_key_hex:
            raise InvalidTransaction("Invalid transaction signer for primary certifier")

        # remove the following logic. Derive the to_address based on the information available
        # we add a verification if the derived address belongs to header.outputs or not
        transaction_id = transaction.signature
        payload = transaction.payload
        try:
            digital_id_transaction = digital_id_transaction_pb2.DigitalIdTransaction()
            digital_id_transaction.ParseFromString(payload)
        except BaseException as err:
            raise Exception(err)

        _verify_digital_id_txn(digital_id_transaction)

        try:
            digital_id_byte = digital_id_transaction.digital_id
            LOGGER.debug("digital_id_byte = %s.", digital_id_byte)

            # verify the digital_id status and owner's public key with the transaction level information
            try:
                digital_id = digital_id_pb2.DigitalId()
                # TODO de-compress digital_id_bytes
                digital_id.ParseFromString(digital_id_byte)
                # TODO remove if signer_pub_key != digital_id.id_owner_public_key:
                #     raise InvalidTransaction("ID owner's public key not matching with transaction signer's")

            except BaseException as err:
                raise Exception(err)
        except BaseException as err:
            raise Exception(err)

        # verify certifier's signature
        certifier_sig_str = digital_id_transaction.certifier_signature
        LOGGER.debug("certifier_sig_str = %s.", certifier_sig_str)

        # TODO added new method _verify_message_signature
        is_verified = _verify_message_signature(digital_id_byte, certifier_sig_str, signer_pub_key_hex)
        if is_verified == 0:
            LOGGER.error('DigitalIdTransaction.certifier_signature invalid')
            raise InvalidTransaction('DigitalIdTransaction.certifier_signature invalid')

        dependency_list = header.dependencies
        LOGGER.debug("header.dependencies: {}".format(dependency_list))

        # TODO get trust score from owner_info
        client_info = digital_id_transaction.owner_info
        client_trust_score = client_info.trust_score
        LOGGER.debug('client_trust_score {}'.format(client_trust_score))

        # call this only when status is VERIFIED
        status = digital_id_transaction.status
        if status == id_attribute_pb2.Status.ON_VERIFICATION:

            if digital_id_transaction.status != digital_id.status:
                raise InvalidTransaction("The digital id status is not valid for the transaction status")

            self._issue_certificate(context, digital_id_byte, to_address_list,
                                    transaction_id, signer_pub_key_hex, dependency_list, client_trust_score)
        if status == id_attribute_pb2.Status.ACK_CONFIRMED:
            self._send_ack(context, to_address_list,
                           transaction_id, signer_pub_key_hex, dependency_list, client_trust_score)

        # TODO not using this blockThe digital id status is not valid for the transaction status
        # if status == id_attribute_pb2.Status.INVALID_ACK:
        #     if len(header.dependencies) != 1:
        #         raise InvalidTransaction("Invalid transaction dependency list")
        #
        #     dependent_txn = header.dependencies[0]
        #
        #     self._invalidate_acks(context, to_address_list, transaction_id,
        #                           signer_pub_key, dependent_txn)

    @classmethod
    def _issue_certificate(cls, context, digital_id_byte, to_address_list,
                           transaction_id, signer_pub_key, dependency_list, client_trust_score):
        LOGGER.debug("Inside _issue_certificate()")
        # TODO Verify if the requested address is valid for REQUEST action
        # add code to get owner public key from previous transaction
        if len(dependency_list) > 0:
            requesting_txn_id = dependency_list[0]
        else:
            LOGGER.error("Dependency of transaction {} is empty".format(transaction_id))
            raise InvalidTransaction("Transaction dependency cannot be empty")

        # Fetch header data from requesting_txn_id
        txn_response = chain_access_util.get_transaction(base_url=cls.rest_api_url, requesting_txn_id=requesting_txn_id)
        txn_header = txn_response['header']
        id_owner_pub_key = txn_header['signer_public_key']
        id_owner_pub_key_hash = _get_pub_key_hash(id_owner_pub_key)
        to_address = _get_digitalid_address(id_owner_pub_key_hash)
        if to_address not in to_address_list:
            raise InvalidTransaction("Requested Output Address not valid")
        # verify validity of dependent transaction with state information
        id_state_data = chain_access_util.get_state(cls.rest_api_url, to_address)
        LOGGER.debug("Existing ID state_data : {}".format(id_state_data))

        if id_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE or \
                id_state_data['acting_transaction_id'] != requesting_txn_id:
            LOGGER.debug("expected dependency : {}".format(id_state_data['acting_transaction_id']))
            raise InvalidTransaction("Invalid dependency given")

        # check validity of confirmation action and the digital-id in current transaction
        prev_id = digital_id_pb2.DigitalId()
        prev_id.ParseFromString(id_state_data['digital_id'])

        if prev_id.status not in (id_attribute_pb2.Status.REQUESTED, id_attribute_pb2.Status.ON_UPDATE,
                                  id_attribute_pb2.Status.RECOVERY_REQ):
            LOGGER.debug("Previous ID status is {}. Issue Certificate operation is not allowed".format(prev_id.status))
            raise InvalidTransaction(
                "Previous ID status is {}. Issue Certificate operation is not allowed".format(prev_id.status))

        if prev_id.status in (id_attribute_pb2.Status.REQUESTED, id_attribute_pb2.Status.RECOVERY_REQ) and \
                client_trust_score != digital_id_constants.PRIMARY_CERTIFIED_TRUST_SCORE:
            InvalidTransaction("Invalid ID owner trust score")
        # state data is a dictionary
        state_data = cbor.dumps({
            'digital_id': digital_id_byte,
            'acting_transaction_id': transaction_id,
            'trust_score': client_trust_score
        })
        addresses = context.set_state({to_address: state_data})

        if len(addresses) < 1:
            raise InternalError("State Error")
        LOGGER.debug("state updated")

        if prev_id.status == id_attribute_pb2.Status.RECOVERY_REQ:
            recovery_address = hashing.get_pub_key_hash(prev_id.id_owner_public_key)
            prev_state_address = _get_digitalid_address(recovery_address)
            addresses = context.delete_state([prev_state_address])
            if len(addresses) < 1:
                LOGGER.debug("Previous state data could not be deleted")
                raise InternalError("State Deletion Error")

        context.add_event(
            event_type='digitalid_certifier/verified',
            attributes=[
                ('address', str(to_address)),
                ('signer_public_key', str(signer_pub_key)),
                ('transaction_id', str(transaction_id)),
                ('send_to', str(id_owner_pub_key_hash))
            ]
        )

    @classmethod
    def _send_ack(cls, context, to_address_list,
                  transaction_id, signer_pub_key, dependency_list, client_trust_score):
        LOGGER.debug("Inside _issue_certificate()")
        # TODO Verify if the requested address is valid for REQUEST action
        # add code to get owner public key from previous transaction
        if len(dependency_list) > 0:
            requesting_txn_id = dependency_list[0]
        else:
            LOGGER.error("Dependency of transaction {} is empty".format(transaction_id))
            raise InvalidTransaction("Transaction dependency cannot be empty")
        # Fetch header data from requesting_txn_id
        txn_response = chain_access_util.get_transaction(base_url=cls.rest_api_url, requesting_txn_id=requesting_txn_id)
        txn_header = txn_response['header']
        id_owner_pub_key = txn_header['signer_public_key']
        id_owner_pub_key_hash = _get_pub_key_hash(id_owner_pub_key)
        to_address = _get_digitalid_address(id_owner_pub_key_hash)
        if to_address not in to_address_list:
            raise InvalidTransaction("Requested Output Address not valid")

        # verify validity of dependent transaction with state information
        id_state_data = chain_access_util.get_state(cls.rest_api_url, to_address)
        LOGGER.debug("Existing ID state_data : {}".format(id_state_data))

        if id_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE or \
                id_state_data['acting_transaction_id'] != requesting_txn_id:
            LOGGER.debug("expected dependency : {}".format(id_state_data['acting_transaction_id']))
            raise InvalidTransaction("Invalid dependency given")

        # check validity of confirmation action and the digital-id in current transaction
        prev_id = digital_id_pb2.DigitalId()
        prev_id.ParseFromString(id_state_data['digital_id'])

        if prev_id.status != id_attribute_pb2.Status.CONFIRMED:
            LOGGER.debug(
                "Previous ID status is {}. Confirmation operation is not allowed".format(prev_id.status))
            raise InvalidTransaction(
                "Previous ID status is {}. Confirmation operation is not allowed".format(prev_id.status))

        if client_trust_score != digital_id_constants.CONFIRMED_ID_TRUST_SCORE:
            InvalidTransaction("Invalid ID owner trust score")

        # save acknowledgement id to state
        id_state_data['acting_transaction_id'] = transaction_id

        state_data = cbor.dumps(id_state_data)
        addresses = context.set_state({to_address: state_data})

        if len(addresses) < 1:
            raise InternalError("State Error")
        LOGGER.debug("state updated")

        context.add_event(
            event_type='digitalid_certifier/acknowledged',
            attributes=[
                ('address', str(to_address)),
                ('signer_public_key', str(signer_pub_key)),
                ('transaction_id', str(transaction_id)),
                ('send_to', str(id_owner_pub_key_hash))
            ]
        )

    # @classmethod TODO not using this
    # def _invalidate_acks(cls, context, to_address_list, transaction_id,
    #                      signer_pub_key, dependency):
    #
    #     LOGGER.debug("Inside _invalidate_acks method")
    #
    #     # Fetch header data from requesting_txn_id
    #     txn_response = chain_access_util.get_transaction(base_url=cls.rest_api_url, requesting_txn_id=dependency)
    #     txn_header = txn_response['header']
    #     id_owner_pub_key = txn_header['signer_public_key']
    #     id_owner_pub_key_hash = hashing.get_pub_key_hash(id_owner_pub_key)
    #
    #     to_address = hashing.get_digitalid_address(family_name=FAMILY_DIGITAL_ID,
    #                                                pub_key_hash=id_owner_pub_key_hash,
    #                                                key=FAMILY_CERTIFY)
    #     if to_address not in to_address_list:
    #         raise InvalidTransaction("Requested Output Address not valid")
    #     # verify validity of dependent transaction with state information
    #     id_state_data = chain_access_util.get_state(cls.rest_api_url, to_address)
    #     LOGGER.debug("Existing ID state_data : {}".format(id_state_data))
    #
    #     if id_state_data == digital_id_constants.SAWTOOTH_STATE_NOT_FOUND_CODE:
    #         raise InvalidTransaction("ID creation state invalid")
    #     try:
    #         if id_state_data['invalidation_req'] is None or \
    #                 id_state_data['pending_acks'] is None:
    #             LOGGER.debug("expected dependency : {}".format(id_state_data['acting_transaction_id']))
    #             raise InvalidTransaction("Invalid state condition for invalidate operation")
    #     except KeyError:
    #         raise InvalidTransaction("Invalid state condition for ID-invalidate operation")
    #
    #     # pending_acks = id_state_data['pending_acks']
    #     # LOGGER.debug("pending_acks list in state {}".format(pending_acks))
    #     signer_pub_key_hash = hashing.get_pub_key_hash(signer_pub_key)
    #     if signer_pub_key_hash not in id_state_data['pending_acks']:
    #         LOGGER.debug("Signer : {} not a valid responder".format(signer_pub_key_hash))
    #         raise InvalidTransaction("Invalid transaction signer for INVALID_ACK")
    #
    #     # remove signer_pub_key_hash from 'pending_acks' in id_state_data
    #     id_state_data['pending_acks'].remove(signer_pub_key_hash)
    #     LOGGER.debug("Modified pending_acks {}".format(id_state_data['pending_acks']))
    #     context.add_event(
    #         event_type='digitalid/invalidate_ack',
    #         attributes=[
    #             ('address', str(to_address)),
    #             ('signer_public_key', str(signer_pub_key)),  # why send with event?
    #             ('transaction_id', str(transaction_id)),
    #             ('send_to', str(id_owner_pub_key_hash)),
    #             ('sent_from', str(signer_pub_key_hash))
    #         ]
    #     )
    #
    #     if len(id_state_data['pending_acks']) == 0:  # all pending acknowledgement received
    #         id_state_data['digital_id'] = id_state_data['invalidation_req']
    #         id_state_data['acting_transaction_id'] = dependency
    #         id_state_data.pop('invalidation_req')
    #         id_state_data.pop('pending_acks')
    #         context.add_event(
    #             event_type='digitalid/invalidation_success',
    #             attributes=[
    #                 ('address', str(to_address)),
    #                 ('signer_public_key', str(signer_pub_key)),  # why send with event?
    #                 ('transaction_id', str(transaction_id)),
    #                 ('send_to', str(id_owner_pub_key_hash))
    #             ]
    #         )
    #
    #     addresses = context.set_state({to_address: cbor.dumps(id_state_data)})
    #
    #     LOGGER.debug("State-data : {}".format(id_state_data))
    #
    #     if len(addresses) < 1:
    #         raise InternalError("State Error")
    #     LOGGER.debug("state updated for ID invalidation ack operation")


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
    # initialize the logger
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
        processor = TransactionProcessor(url=validator_url)
        app_namespace = _hash(FAMILY_CERTIFY.encode('utf-8'))[0:6]
        id_generation_namespace = _hash(FAMILY_DIGITAL_ID.encode('utf-8'))[0:6] + _hash(FAMILY_CERTIFY.encode('utf-8'))[
                                                                                  0:24]
        client_app_namespace = _hash(FAMILY_CERTIFIER_CLIENT.encode('utf-8'))[0:6]
        handler = CertifyTransactionHandler([app_namespace, id_generation_namespace])
        client_handler = CertifierClientTransactionHandler([client_app_namespace, app_namespace])
        # Setting field rest_api_url
        CertifyTransactionHandler.rest_api_url = api_url
        CertifyTransactionHandler.rest_api_url = api_url
        processor.add_handler(handler)
        processor.add_handler(client_handler)
        processor.start()

    except KeyboardInterrupt:
        pass
    except SystemExit as err:
        raise err
    except BaseException as err:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
