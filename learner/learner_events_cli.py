#! /usr/bin/env python3
import argparse
import hashlib
import logging
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
from util import hashing

# sys.path.append('/home/suchira/digital-id/learner')
# from userwallet_client import LearnerWalletClient

DEFAULT_VALIDATOR_URL = 'tcp://localhost:4004'
DEFAULT_API_URL = 'http://localhost:8008'
FAMILY_NAME_LEARNER = "learner"
FAMILY_NAME_CERTIFY = "certifier"

DEFAULT_KEY_FILE_NAME = 'skill_wallet'
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
    The address is the first 6 hex characters from the hash SHA-512(FAMILY_NAME_LEARNER),
    """
    return str(_hash(FAMILY_NAME_LEARNER.encode('utf-8'))[0:6])


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


class LearnerEventsClient(object):

    def __init__(self, filter_dict=None, user_name=None, validator=DEFAULT_VALIDATOR_URL, rest_api_url=DEFAULT_API_URL):
        self._filters = filter_dict
        self.user_name = user_name
        self.validator_url = validator
        self.rest_api_url = rest_api_url
        self._msg_stream = Stream(self.validator_url)
        user_dir = os.path.join(os.getcwd(), user_name)
        if os.path.isdir(user_dir) is False:
            os.mkdir(user_name)
        self.events_db_file = os.path.join(user_dir, EVENTS_DB_FILE)

    def listen_events(self):
        # subscribe to events

        # state_delta_subscription = events_pb2.EventSubscription(
        #     event_type="sawtooth/state-delta",
        #     filters=self._filters
        # )

        verified_id_subscription = events_pb2.EventSubscription(
            event_type="certifier/confirmed",
            filters=self._filters['certification_filters']
        )
        register_event_subscription = events_pb2.EventSubscription(
            event_type="learner/pii_register",
            filters=self._filters['certification_filters']
        )
        subscription_req = client_event_pb2.ClientEventsSubscribeRequest(
            subscriptions=[verified_id_subscription,register_event_subscription]
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
            #  msg.message_type == Message.CLIENT_EVENTS

            # Parse the response
            event_list = events_pb2.EventList()
            event_list.ParseFromString(msg.content)
            LOGGER.info("Received the following events: ----------")
            print("\nReceived the following events: ----------")
            for event in event_list.events:
                LOGGER.debug(event)

                if event.event_type == "learner/pii_register":

                    LOGGER.debug("learner/pii_register")
                    print("learner/pii_register")
                    attribute_list = event.attributes
                    for event_attribute in attribute_list:

                        if event_attribute.key == 'address':
                            address = event_attribute.value
                            LOGGER.debug("event attribute address: {}".format(address))

                        elif event_attribute.key == 'transaction_id':
                            transaction_id = event_attribute.value
                            LOGGER.debug("event attribute transaction_id: {}".format(transaction_id))

                        elif event_attribute.key == 'send_to':
                            send_to = event_attribute.value
                            LOGGER.debug("event attribute send_to: {}".format(send_to))

                    print("PII credential successfully registered.")
                    LOGGER.info("PII credential successfully registered.")

                    continue

                if event.event_type == "certifier/confirmed":

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
                    LOGGER.info("Digital ID successfully registered. Please peer verify.")

                    # transaction_id = event_attribute.value
                    # user_client = LearnerWalletClient(base_url=DEFAULT_API_URL)
                    # TODO change the value of enable_confirm to true
                    # user_client.get_id(event.event_type, address, transaction_id)
                    # if self._user_client is None:
                    #     user_client = LearnerWalletClient(base_url=DEFAULT_API_URL)
                    #     user_client.change_id_status()
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
    self_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_LEARNER,
                                                       key='self',
                                                       pub_key_hash=public_address)

    registration_filters = [events_pb2.EventFilter(key="address",
                                                   match_string=self_state_address,
                                                   filter_type=events_pb2.EventFilter.SIMPLE_ALL),
                            events_pb2.EventFilter(key="send_to",
                                                   match_string=public_address,
                                                   filter_type=events_pb2.EventFilter.SIMPLE_ALL),
                            ]

    certification_filters = [events_pb2.EventFilter(key="address",
                                                    match_string=_get_certification_address_prefix() + '.*',
                                                    filter_type=events_pb2.EventFilter.REGEX_ANY),
                             events_pb2.EventFilter(key="send_to",
                                                    # match_string=crypto_obj.public_key_hash,
                                                    match_string=public_address,
                                                    filter_type=events_pb2.EventFilter.SIMPLE_ALL),
                             ]

    share_filters = [

        # filter to receive share responses and requests coming to the corresponding client

        events_pb2.EventFilter(key="to_address",
                               match_string=public_address,  # get this information frm metadata
                               # match_string=crypto_obj.public_key_hash,  # get this information frm metadata
                               filter_type=events_pb2.EventFilter.SIMPLE_ALL),
    ]
    filter_dict['pii_registration_filter'] = registration_filters
    filter_dict['certification_filters'] = certification_filters
    filter_dict['share_filters'] = share_filters

    events_client = LearnerEventsClient(filter_dict=filter_dict, user_name=key_file_name,
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


if __name__ == '__main__':
    main()
