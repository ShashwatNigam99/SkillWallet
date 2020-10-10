#! /usr/bin/env python3
import argparse
import hashlib
import logging
import multiprocessing
import sys
import os
import traceback

from bsddb3 import db
from cbor import cbor
from colorlog import ColoredFormatter
from sawtooth_sdk.messaging.stream import Stream
from sawtooth_sdk.protobuf import events_pb2, client_event_pb2
from sawtooth_sdk.protobuf.validator_pb2 import Message
from sawtooth_signing import CryptoFactory, create_context
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey
from sawtooth_signing import ParseError

sys.path.append(os.getcwd())
from learner.userwallet_client import UserWalletClient
from util import hashing

# sys.path.append('/home/suchira/digital-id/learner')
# from userwallet_client import UserWalletClient

DEFAULT_VALIDATOR_URL = 'tcp://localhost:4004'
DEFAULT_API_URL = 'http://localhost:8008'
FAMILY_NAME_DIGITALID = "digitalid"
FAMILY_NAME_CERTIFY = "digitalid_certifier"
FAMILY_NAME_PEER_VERIFY = "peer_verification"

DEFAULT_KEY_FILE_NAME = 'digitalid'
# LOGGER = logging.getLogger(__name__)
LOGGER = logging.getLogger("learner-events-cli")

EVENTS_DB_FILE = 'user_events_db'


# TODO create a class level list or, db to put received events
# TODO access them in the client class when needed


def create_file_handler():
    # configure logger
    file_handler = logging.FileHandler('learner-events.log')
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
            'DEBUG': 'cyan',  # verbosity=3
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


def setup_loggers(verbose_level):
    """Setup logging."""
    # logger = logging.getLogger()
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


def _hash(data):
    """Compute the SHA-512 hash and return the result as hex characters."""
    return hashlib.sha512(data).hexdigest()


def _hash_bytes(data_bytes):
    hash_obj = hashlib.sha512()
    hash_obj.update(data_bytes)
    return hash_obj.hexdigest().encode('utf-8')


def _get_certification_address_prefix():
    """
    Return the address of a digital id object from the digitalid TF.

    The address is the first 6 hex characters from the hash SHA-512(TF name),
    plus the FAMILY_NAME_CERTIFY.
    """
    return str(_hash(FAMILY_NAME_DIGITALID.encode('utf-8'))[0:6] + _hash(FAMILY_NAME_CERTIFY.encode('utf-8'))[0:24])


def _get_peer_verification_address_prefix():
    """
    Return the address of a digital id object from the digitalid TF.

    The address is the first 6 hex characters from the hash SHA-512(TF name),
    plus the FAMILY_NAME_CERTIFY.
    """
    return str(_hash(FAMILY_NAME_PEER_VERIFY.encode('utf-8'))[0:6])


def _get_private_key_file(key_file_name):
    """Get the private key from key_file_name."""
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")
    return '{}/{}.priv'.format(key_dir, key_file_name)


def _get_private_key(key_file_name):
    private_key_file = _get_private_key_file(key_file_name)
    try:
        with open(private_key_file) as fd:
            private_key_str = fd.read().strip()
    except OSError as err:
        raise Exception('Failed to read private key {}: {}'.format(private_key_file, str(err)))
    try:
        private_key = Secp256k1PrivateKey.from_hex(private_key_str)
    except ParseError as err:
        raise Exception('Failed to load private key:{}'.format(str(err)))
    return private_key


class UserEventsClient(object):

    def __init__(self, filter_dict=None, user_name=None, validator=DEFAULT_VALIDATOR_URL, rest_api_url=DEFAULT_API_URL):
        self._filters = filter_dict
        self.user_name = user_name
        # self._msg_stream = Stream(DEFAULT_VALIDATOR_URL)
        self.validator_url = validator
        self.rest_api_url = rest_api_url
        self._msg_stream = Stream(self.validator_url)
        user_dir = os.path.join(os.getcwd(), user_name)
        if os.path.isdir(user_dir) is False:
            os.mkdir(user_name)
        self.events_db_file = os.path.join(user_dir, EVENTS_DB_FILE)

    def _accept_receipt(self):
        LOGGER.debug("Inside _accept_receipt()")
        print("\nSaving acknowledgement in state.")
        user_client = UserWalletClient(base_url=self.rest_api_url,  # DEFAULT_API_URL,
                                       command='save_ack_receipt',
                                       key_file_name=self.user_name)
        user_client.save_ack_receipt()

    def listen_events(self):
        # subscribe to events

        # state_delta_subscription = events_pb2.EventSubscription(
        #     event_type="sawtooth/state-delta",
        #     filters=self._filters
        # )

        verified_id_subscription = events_pb2.EventSubscription(
            event_type="digitalid_certifier/verified",
            filters=self._filters['certification_filters']
        )
        peer_verification_request_subscription = events_pb2.EventSubscription(
            event_type="peer_verification/request",
            filters=self._filters['peer_filters']
        )
        peer_verification_response_subscription = events_pb2.EventSubscription(
            event_type="peer_verification/response",
            filters=self._filters['peer_filters']
        )
        certifier_acknowledgement_subscription = events_pb2.EventSubscription(
            event_type="digitalid_certifier/acknowledged",
            filters=self._filters['certification_filters']
        )
        share_id_request_subscription = events_pb2.EventSubscription(
            event_type="shareid/request",
            filters=self._filters['share_filters']
        )
        share_id_response_subscription = events_pb2.EventSubscription(
            event_type="shareid/response",
            filters=self._filters['share_filters']
        )
        invalidation_request_subscription = events_pb2.EventSubscription(
            event_type="digitalid/invalidate",
            filters=self._filters['invalidation_filters']
        )
        invalidation_ack_subscription = events_pb2.EventSubscription(
            event_type="digitalid/invalidate_ack",
            filters=self._filters['invalidation_ack_filters']
        )
        invalidation_success_subscription = events_pb2.EventSubscription(
            event_type="digitalid/invalidation_success",
            filters=self._filters['invalidation_ack_filters']
        )
        id_demotion_subscription = events_pb2.EventSubscription(
            event_type="digitalid/demoted",
            filters=self._filters['id_demotion_filters']
        )
        subscription_req = client_event_pb2.ClientEventsSubscribeRequest(
            subscriptions=[verified_id_subscription,
                           peer_verification_request_subscription,
                           peer_verification_response_subscription,
                           certifier_acknowledgement_subscription,
                           share_id_request_subscription,
                           share_id_response_subscription,
                           invalidation_request_subscription,
                           invalidation_ack_subscription,
                           invalidation_success_subscription,
                           id_demotion_subscription]
        )

        # Send the subscription request
        msg = self._msg_stream.send(message_type=Message.CLIENT_EVENTS_SUBSCRIBE_REQUEST,
                                    content=subscription_req.SerializeToString()).result()

        assert msg.message_type == Message.CLIENT_EVENTS_SUBSCRIBE_RESPONSE

        if msg.message_type == Message.CLIENT_EVENTS_SUBSCRIBE_RESPONSE:
            # Parse the subscription response
            subscription_response = client_event_pb2.ClientEventsSubscribeResponse()
            subscription_response.ParseFromString(msg.content)
            assert subscription_response.status == client_event_pb2.ClientEventsSubscribeResponse.OK

        # Listen for events continuously
        LOGGER.debug("Listening to events.")
        print("\nListening to events.")
        while True:
            msg = self._msg_stream.receive().result()
            assert msg.message_type == Message.CLIENT_EVENTS

            # Parse the response
            event_list = events_pb2.EventList()
            event_list.ParseFromString(msg.content)
            LOGGER.debug("Received the following events: ----------")
            print("\nReceived the following events: ----------")
            for event in event_list.events:
                LOGGER.debug(event)

                if event.event_type == "digitalid_certifier/verified":

                    LOGGER.debug("digitalid_certifier/verified")
                    print("digitalid_certifier/verified")
                    # creating database with hash access method
                    events_db = db.DB()
                    # events_db.open(EVENTS_DB_FILE, None, db.DB_HASH, db.DB_CREATE)
                    events_db.open(self.events_db_file, None, db.DB_HASH, db.DB_CREATE)
                    event_attr = {}
                    LOGGER.debug("event of type {} received".format(event.event_type))
                    attribute_list = event.attributes
                    for event_attribute in attribute_list:

                        if event_attribute.key == 'address':
                            address = event_attribute.value
                            LOGGER.debug("event attribute address: {}".format(address))
                            event_attr['address'] = address

                        elif event_attribute.key == 'signer_public_key':
                            signer_public_key = event_attribute.value
                            LOGGER.debug("event attribute signer_public_key: {}".format(signer_public_key))
                            event_attr['signer_public_key'] = signer_public_key

                        elif event_attribute.key == 'transaction_id':
                            transaction_id = event_attribute.value
                            LOGGER.debug("event attribute transaction_id: {}".format(transaction_id))
                            event_attr['transaction_id'] = transaction_id

                    # TODO Key format: event_type+'/transaction_id'.encode()
                    # db_key = '{}/{}'.format(event.event_type, transaction_id)
                    db_key = event.event_type
                    events_db.put(db_key.encode(), cbor.dumps(event_attr))
                    # TODO send command for peer verfication
                    events_db.close()
                    print("Digital ID successfully registered. Please peer verify.")

                    # transaction_id = event_attribute.value
                    # user_client = UserWalletClient(base_url=DEFAULT_API_URL)
                    # TODO change the value of enable_confirm to true
                    # user_client.get_id(event.event_type, address, transaction_id)
                    # if self._user_client is None:
                    #     user_client = UserWalletClient(base_url=DEFAULT_API_URL)
                    #     user_client.change_id_status()
                    continue

                if event.event_type == "peer_verification/request" or \
                        event.event_type == "digitalid/invalidate":

                    LOGGER.debug(event.event_type)
                    print(event.event_type)
                    events_db = db.DB()
                    events_db.open(self.events_db_file, None, db.DB_HASH, db.DB_CREATE)
                    # we don't need dictionary here, just storing transaction ID instead
                    # event_attr = {}
                    transaction_id = None
                    sent_from = None
                    LOGGER.debug("event of type {} received".format(event.event_type))
                    attribute_list = event.attributes
                    for event_attribute in attribute_list:

                        if event_attribute.key == 'transaction_id':
                            transaction_id = event_attribute.value
                            LOGGER.debug("event attribute transaction_id: {}".format(transaction_id))
                        elif event_attribute.key == 'sent_from':
                            sent_from = event_attribute.value
                            LOGGER.debug("event attribute sent_from: {}".format(sent_from))

                        # if event_attribute.key == 'address':
                        #     address = event_attribute.value
                        #     event_attr['address'] = address
                        #     LOGGER.debug("event attribute address: {}".format(address))
                        # elif event_attribute.key == 'signer_public_key':
                        #     signer_public_key = event_attribute.value
                        #     event_attr['signer_public_key'] = signer_public_key
                        #     LOGGER.debug("event attribute signer_public_key: {}".format(signer_public_key))
                        # elif event_attribute.key == 'transaction_id':
                        #     transaction_id = event_attribute.value
                        #     event_attr['transaction_id'] = transaction_id
                        #     LOGGER.debug("event attribute transaction_id: {}".format(transaction_id))
                        # elif event_attribute.key == 'send_to':
                        #     send_to = event_attribute.value
                        #     event_attr['send_to'] = send_to
                        #     LOGGER.debug("event attribute send_to: {}".format(send_to))
                        # elif event_attribute.key == 'sent_from':
                        #     sent_from = event_attribute.value
                        #     event_attr['sent_from'] = sent_from
                        #     LOGGER.debug("event attribute sent_from: {}".format(sent_from))

                    db_key = event.event_type
                    value = events_db.get(db_key.encode())
                    if value is None:
                        request_list = []
                    else:
                        request_list = cbor.loads(value)
                        if request_list is None:
                            request_list = []

                    # request_list.append(event_attr)
                    if transaction_id not in request_list:
                        request_list.append(transaction_id)

                    LOGGER.debug(request_list)
                    events_db.put(db_key.encode(), cbor.dumps(request_list))
                    events_db.close()
                    # TODO execute command for peer verification for ID state at 'address'
                    # command that calls verify_peer_data(self, peer_address)
                    # print("Peer verification request received for ID at {}".format(address))
                    if event.event_type == "peer_verification/request":
                        # print("ID attestation request received from address {} in transaction {}".format(
                        #     event_attr['sent_from'],
                        #     event_attr['transaction_id']))

                        print("ID attestation request received from address {} in transaction {}".format(
                            sent_from,
                            transaction_id))

                    elif event.event_type == "digitalid/invalidate":
                        print("ID invalidation request received from address {} in transaction {}".format(
                            sent_from,
                            transaction_id))
                    continue

                if event.event_type == "peer_verification/response" or \
                        event.event_type == "digitalid/invalidate_ack" or \
                        event.event_type == "digitalid/invalidation_success":

                    LOGGER.debug(event.event_type)
                    print(event.event_type)
                    address = None
                    transaction_id = None
                    sent_from = None
                    # signer_public_key = None
                    # send_to = None
                    # event_attr = {}

                    LOGGER.debug("event of type {} received".format(event.event_type))
                    attribute_list = event.attributes
                    for event_attribute in attribute_list:

                        if event_attribute.key == 'address':
                            address = event_attribute.value
                            # event_attr['address'] = address
                            LOGGER.debug("event attribute address: {}".format(address))
                        elif event_attribute.key == 'signer_public_key':
                            signer_public_key = event_attribute.value
                            # event_attr['signer_public_key'] = signer_public_key
                            LOGGER.debug("event attribute signer_public_key: {}".format(signer_public_key))
                        elif event_attribute.key == 'transaction_id':
                            transaction_id = event_attribute.value
                            # event_attr['transaction_id'] = transaction_id
                            LOGGER.debug("event attribute transaction_id: {}".format(transaction_id))
                        elif event_attribute.key == 'send_to':
                            send_to = event_attribute.value
                            # event_attr['send_to'] = send_to
                            LOGGER.debug("event attribute send_to: {}".format(send_to))
                        elif event_attribute.key == 'sent_from':
                            sent_from = event_attribute.value
                            LOGGER.debug("event attribute sent_from: {}".format(sent_from))

                    # Key format: event_type+'/transaction_id'.encode()
                    # db_key = '{}/{}'.format(event.event_type, transaction_id)
                    # events_db.put(db_key.encode(), cbor.dumps(event_attr))
                    if event.event_type == "peer_verification/response":
                        print("Peer verification response received for ID at {} from transaction {}".format(address,
                                                                                                            transaction_id))
                    elif event.event_type == "digitalid/invalidate_ack":
                        print(
                            "Digital ID invalidation request is acknowledged by {}, transaction ID {}".format(sent_from,
                                                                                                              transaction_id))
                    elif event.event_type == "digitalid/invalidation_success":
                        print("Digital ID is successfully invalidated at {}".format(address))

                    continue

                if event.event_type == "digitalid_certifier/acknowledged":

                    LOGGER.debug("digitalid_certifier/acknowledged")
                    print("digitalid_certifier/acknowledged")
                    events_db = db.DB()
                    events_db.open(self.events_db_file, None, db.DB_HASH, db.DB_CREATE)
                    address = None
                    event_attr = {}
                    LOGGER.debug("event of type {} received".format(event.event_type))
                    attribute_list = event.attributes
                    for event_attribute in attribute_list:

                        if event_attribute.key == 'address':
                            address = event_attribute.value
                            event_attr['address'] = address
                            LOGGER.debug("event attribute address: {}".format(address))

                        elif event_attribute.key == 'signer_public_key':
                            signer_public_key = event_attribute.value
                            event_attr['signer_public_key'] = signer_public_key
                            LOGGER.debug("event attribute signer_public_key: {}".format(signer_public_key))

                        elif event_attribute.key == 'transaction_id':
                            transaction_id = event_attribute.value
                            event_attr['transaction_id'] = transaction_id
                            LOGGER.debug("event attribute transaction_id: {}".format(transaction_id))

                        elif event_attribute.key == 'send_to':
                            send_to = event_attribute.value
                            event_attr['send_to'] = send_to
                            LOGGER.debug("event attribute send_to: {}".format(send_to))

                    # Key format: event_type+'/transaction_id'.encode()
                    # db_key = '{}/{}'.format(event.event_type, transaction_id)
                    db_key = event.event_type
                    events_db.put(db_key.encode(), cbor.dumps(event_attr))
                    events_db.close()
                    print("\nPrimary certifier's acknowledgement received for ID at {}".format(address))
                    process_client = multiprocessing.Process(target=self._accept_receipt())
                    process_client.daemon = True
                    process_client.start()
                    LOGGER.debug("userwallet_client is_alive {}".format(process_client.is_alive()))
                    process_client.join()
                    LOGGER.debug("Process for accepting receipt finished operation")
                    print("Process for accepting receipt finished operation")
                    LOGGER.debug("userwallet_client is_alive {}".format(process_client.is_alive()))
                    if process_client.is_alive():
                        process_client.terminate()
                    continue

                if event.event_type == "shareid/request":

                    LOGGER.debug("shareid/request")
                    to_address = None
                    received_from = None
                    transaction_id = None

                    LOGGER.debug("event of type {} received".format(event.event_type))
                    attribute_list = event.attributes
                    for event_attribute in attribute_list:

                        if event_attribute.key == 'to_address':
                            to_address = event_attribute.value
                            # event_attr['address'] = address
                            LOGGER.debug("event attribute to_address: {}".format(to_address))
                        elif event_attribute.key == 'received_from':
                            received_from = event_attribute.value
                            # event_attr['signer_public_key'] = signer_public_key
                            LOGGER.debug("event attribute received_from: {}".format(received_from))
                        elif event_attribute.key == 'transaction_id':
                            transaction_id = event_attribute.value
                            # event_attr['transaction_id'] = transaction_id
                            LOGGER.debug("event attribute transaction_id: {}".format(transaction_id))

                    # Key format: event_type+'/transaction_id'.encode()
                    # db_key = '{}/{}'.format(event.event_type, transaction_id)
                    # events_db.put(db_key.encode(), cbor.dumps(event_attr))

                    print("ID share request received from {} in transaction {}".format(received_from, transaction_id))
                    continue

                if event.event_type == "shareid/response":

                    LOGGER.debug("shareid/response")
                    received_from = None
                    transaction_id = None

                    LOGGER.debug("event of type {} received".format(event.event_type))
                    attribute_list = event.attributes
                    for event_attribute in attribute_list:

                        if event_attribute.key == 'to_address':
                            to_address = event_attribute.value
                            # event_attr['address'] = address
                            LOGGER.debug("event attribute to_address: {}".format(to_address))
                        elif event_attribute.key == 'received_from':
                            received_from = event_attribute.value
                            # event_attr['signer_public_key'] = signer_public_key
                            LOGGER.debug("event attribute received_from: {}".format(received_from))
                        elif event_attribute.key == 'transaction_id':
                            transaction_id = event_attribute.value
                            # event_attr['transaction_id'] = transaction_id
                            LOGGER.debug("event attribute transaction_id: {}".format(transaction_id))

                    # Key format: event_type+'/transaction_id'.encode()
                    # db_key = '{}/{}'.format(event.event_type, transaction_id)
                    # events_db.put(db_key.encode(), cbor.dumps(event_attr))

                    print("ID share response received from {} in transaction {}".format(received_from, transaction_id))
                    continue

    def disconnect(self):
        # Unsubscribe from events
        LOGGER.debug("inside UserEventsCli.disconnect")

        subscription_req = client_event_pb2.ClientEventsUnsubscribeRequest()
        msg = self._msg_stream.send(Message.CLIENT_EVENTS_UNSUBSCRIBE_REQUEST,
                                    subscription_req.SerializeToString()).result()
        assert msg.message_type == Message.CLIENT_EVENTS_UNSUBSCRIBE_RESPONSE

        # Parse the unsubscribe response
        subscription_response = client_event_pb2.ClientEventsUnsubscribeResponse()
        subscription_response.ParseFromString(msg.content)
        assert subscription_response.status == \
               client_event_pb2.ClientEventsUnsubscribeResponse.OK

        return


def create_parser(prog_name):
    """Create the command line argument parser for the digital-ID event listener for learner."""
    parser = argparse.ArgumentParser(prog=prog_name, add_help=False)
    parser.add_argument('-C', '--connect', dest='validator_url', type=str, help="Url to connect to validator")
    parser.add_argument('-l', '--url', dest='rest_api_url', type=str, help="Rest-API URL")
    parser.add_argument('-u', '--learner', dest='learner', type=str, help='learner name')
    parser.add_argument('-v', '--verbosity1', action='store_const', const=1, default=0, dest='verbosity',
                        help='sets verbosity level to 1')
    parser.add_argument('-vv', '--verbosity2', action='store_const', const=2, dest='verbosity',
                        help='sets verbosity level to 2')
    parser.add_argument('-vvv', '--verbosity3', action='store_const', const=3, dest='verbosity',
                        help='sets verbosity level to 3')
    return parser


def main(prog_name=os.path.basename(sys.argv[0]), args=None):
    """Entry point function for the event _client"""

    # Set up logger
    # logging.basicConfig()
    # logging.getLogger().setLevel(logging.DEBUG)
    key_file_name = None
    validator_url = None
    api_url = None
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
        key_file_name = results.user
        validator_url = results.validator_url
        if validator_url is None:
            validator_url = DEFAULT_VALIDATOR_URL
        api_url = results.rest_api_url
        if api_url is None:
            api_url = DEFAULT_API_URL
        LOGGER.debug("User name: %s", key_file_name)
        LOGGER.debug("Validator URL: %s", validator_url)
        LOGGER.debug("REST API URL: %s", api_url)
    except BaseException:
        traceback.print_exc(file=sys.stderr)

    private_key = _get_private_key(key_file_name)
    _signer = CryptoFactory(create_context('secp256k1')).new_signer(private_key)
    public_key = _signer.get_public_key().as_hex()
    public_address = hashing.get_pub_key_hash(public_key)

    filter_dict = {}
    # crypto_obj = CryptoKeyManager(DEFAULT_KEY_FILE_NAME)
    # if key_file_name is None:
    #     crypto_obj = CryptoKeyManager(DEFAULT_KEY_FILE_NAME)
    # else:
    #     crypto_obj = CryptoKeyManager(key_file_name)
    id_creation_state = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                      key=FAMILY_NAME_CERTIFY,
                                                      pub_key_hash=public_address)
    # pub_key_hash=crypto_obj.public_key_hash)

    certification_filters = [events_pb2.EventFilter(key="address",
                                                    match_string=_get_certification_address_prefix() + '.*',
                                                    filter_type=events_pb2.EventFilter.REGEX_ANY),
                             events_pb2.EventFilter(key="send_to",
                                                    # match_string=crypto_obj.public_key_hash,
                                                    match_string=public_address,
                                                    filter_type=events_pb2.EventFilter.SIMPLE_ALL),
                             ]
    # filter_type=events_pb2.EventFilter.SIMPLE_ALL)

    peer_filters = [
        # filter to match prefix for peer_verification family
        events_pb2.EventFilter(key="address",
                               match_string=_get_peer_verification_address_prefix() + '.*',
                               filter_type=events_pb2.EventFilter.REGEX_ANY),

        # filter to receive verification requests coming to or verification responses received
        # for requests that generated from the corresponding client

        events_pb2.EventFilter(key="send_to",
                               match_string=public_address,  # get this information frm metadata
                               # match_string=crypto_obj.public_key_hash,  # get this information frm metadata
                               filter_type=events_pb2.EventFilter.SIMPLE_ALL),
    ]
    share_filters = [

        # filter to receive verification responses and requests coming to the corresponding client

        events_pb2.EventFilter(key="to_address",
                               match_string=public_address,  # get this information frm metadata
                               # match_string=crypto_obj.public_key_hash,  # get this information frm metadata
                               filter_type=events_pb2.EventFilter.SIMPLE_ALL),
    ]
    invalidation_filters = [

        # filter to receive ID invalidation requests/responses

        events_pb2.EventFilter(key="send_to",
                               match_string=".*'" + public_address + "'.*",
                               # match_string=".*'" + crypto_obj.public_key_hash + "'.*",
                               # accepts strings of from ['jakroaie34534arda','398akljdfe423']
                               filter_type=events_pb2.EventFilter.REGEX_ANY),  # use regex pattern
    ]
    invalidation_ack_filters = [

        # filter to receive ID invalidation requests/responses

        events_pb2.EventFilter(key="send_to",
                               # match_string=crypto_obj.public_key_hash,
                               match_string=public_address,
                               filter_type=events_pb2.EventFilter.SIMPLE_ALL),  # use regex pattern
    ]
    demotion_filters = [events_pb2.EventFilter(key="address",
                                               match_string=id_creation_state,
                                               filter_type=events_pb2.EventFilter.SIMPLE_ALL),
                        events_pb2.EventFilter(key="signer_public_key",
                                               match_string=public_key,
                                               # match_string=crypto_obj.public_key,
                                               filter_type=events_pb2.EventFilter.SIMPLE_ALL),
                        ]
    filter_dict['certification_filters'] = certification_filters
    filter_dict['peer_filters'] = peer_filters
    filter_dict['share_filters'] = share_filters
    filter_dict['invalidation_filters'] = invalidation_filters
    filter_dict['invalidation_ack_filters'] = invalidation_ack_filters
    filter_dict['id_demotion_filters'] = demotion_filters

    events_client = UserEventsClient(filter_dict=filter_dict, user_name=key_file_name,
                                     validator=validator_url, rest_api_url=api_url)
    try:
        # listen to events
        events_client.listen_events()
    except KeyboardInterrupt:
        events_client.disconnect()
        sys.exit(1)
    except SystemExit as err:
        raise err
    except BaseException as err:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    # finally:
    #     events_client.events_db.close()


if __name__ == '__main__':
    main()
