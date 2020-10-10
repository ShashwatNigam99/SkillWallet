#!/usr/bin/env python3

"""
Command line interface for digital ID  TF.
"""

import argparse
import logging
import os
import sys
import traceback

from colorlog import ColoredFormatter
from cmd import Cmd
from sawtooth_sdk.protobuf import events_pb2

sys.path.append(os.getcwd())
from learner.userwallet_client import UserWalletClient
from learner.user_events_cli import UserEventsClient
from util import hashing

DEFAULT_KEY_FILE_NAME = 'digitalid'

# hard-coded for simplicity (otherwise get the URL from the args in main):
DEFAULT_URL = 'http://localhost:8008'
LOGGER = logging.getLogger('userwallet')
LOGGER.setLevel(logging.INFO)  # TODO was set to logging.INFO this may be default level
# TODO OVERRIDDEN IN setup_loggers() what are different verbosity levels?
FAMILY_NAME_DIGITALID = "digitalid"
CERTIFY_FAMILY_NAME = "digitalid_certifier"
FAMILY_NAME_PEER_VERIFY = "peer_verification"


# For Docker:
# DEFAULT_URL = 'http://rest-api:8008'


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
    file_handler = logging.FileHandler('userwallet.log')
    # file_handler.setLevel(logging.DEBUG)
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


def create_parser(prog_name):
    """Create the command line argument parser for the digital-ID application for learner."""
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)
    parent_parser.add_argument('-l', '--url', dest='rest_api_url', type=str, help="Rest-API URL")
    parent_parser.add_argument('-u', '--learner', dest='learner', type=str, help='learner name')
    parent_parser.add_argument('-v', '--verbosity1', action='store_const', const=1, default=0, dest='verbosity',
                               help='sets verbosity level to 1')
    parent_parser.add_argument('-vv', '--verbosity2', action='store_const', const=2, dest='verbosity',
                               help='sets verbosity level to 2')
    parent_parser.add_argument('-vvv', '--verbosity3', action='store_const', const=3, dest='verbosity',
                               help='sets verbosity level to 3')
    parser = argparse.ArgumentParser(
        description='Provides sub-commands for managing learner wallet',
        parents=[parent_parser])

    subparsers = parser.add_subparsers(title='subcommands', dest='command')
    subparsers.required = True
    subparsers.add_parser('id_wallet', help='Start wallet in interactive mode', parents=[parent_parser])
    subparsers.add_parser('request', help='Request new digital id', parents=[parent_parser])
    subparsers.add_parser('confirm', help='Confirm verified digital id', parents=[parent_parser])
    subparsers.add_parser('display', help='Display digital id', parents=[parent_parser])
    subparsers.add_parser('peer_verify', help='Send digital id for peer verification', parents=[parent_parser])
    subparsers.add_parser('credibility_inc', help='Send additional peer verification request', parents=[parent_parser])
    subparsers.add_parser('save_ack', help='Save digital id acknowledgement to self state', parents=[parent_parser])
    subparsers.add_parser('update', help='Update attributes in digital id', parents=[parent_parser])
    subparsers.add_parser('disable', help='Invalidate digital id', parents=[parent_parser])
    ack_disable_parser = subparsers.add_parser('ack_disable_req', help='Process ID Invalidation request',
                                               parents=[parent_parser])
    ack_disable_parser.add_argument('-t', '--txn', dest='req_txn', type=str, help='transaction id '
                                                                                  'of invalidation request')
    subparsers.add_parser('request_recovery', help='Request for ID recovery', parents=[parent_parser])
    attest_peer_parser = subparsers.add_parser('attest_peer', help='Verify and attest peer data',
                                               parents=[parent_parser])
    # attest_peer_parser.add_argument('-p', '--peer', dest='peer', type=str, help='peer address', required=True)
    attest_peer_parser.add_argument('-t', '--txn', dest='req_txn', type=str, help='requesting transaction id '
                                                                                  'for verification')
    share_req_parser = subparsers.add_parser('shareid_request', help='Request Digital-ID Sharing',
                                             parents=[parent_parser])
    share_req_parser.add_argument('-r', '--receiver', dest='receiver', type=str, help='Address of intended receiver')
    share_req_parser.add_argument('-d', '--add_data', dest='data_mode', required=False, action='store_const', const=True,
                                  help='Option is True if ID attribute data is required')

    share_res_parser = subparsers.add_parser('shareid_response', help='Share Digital-ID', parents=[parent_parser])
    share_res_parser.add_argument('-r', '--receiver', dest='receiver', type=str, help='Address of sender')
    share_res_parser.add_argument('-t', '--txn', dest='req_txn', type=str,
                                  help='Transaction ID of the ID share response')

    share_disp_parser = subparsers.add_parser('display_shareid_response', help='Display Shared Digital-ID',
                                              parents=[parent_parser])
    share_disp_parser.add_argument('-r', '--receiver', dest='receiver', type=str, help='Address of sender')
    share_disp_parser.add_argument('-t', '--txn', dest='req_txn', type=str,
                                   help='Transaction ID of the ID share response')
    return parser


def _get_certification_address_prefix():
    """
    Return the address of a digital id object from the digitalid TF.

    The address is the first 6 hex characters from the hash SHA-512(TF name),
    plus the FAMILY_NAME_CERTIFY.
    """
    return str(hashing.hash512(FAMILY_NAME_DIGITALID.encode('utf-8'))[0:6] + hashing.hash512(
        CERTIFY_FAMILY_NAME.encode('utf-8'))[0:24])


def _get_peer_verification_address_prefix():
    """
    Return the address of a digital id object from the digitalid TF.

    The address is the first 6 hex characters from the hash SHA-512(TF name),
    plus the FAMILY_NAME_CERTIFY.
    """
    return str(hashing.hash512(FAMILY_NAME_PEER_VERIFY.encode('utf-8'))[0:6])


def _start_events_listener(public_key_hash):
    LOGGER.debug("inside Userwallet._start_events_listener")
    filter_dict = {}
    # crypto_obj = CryptoKeyManager(DEFAULT_KEY_FILE_NAME)
    certification_filters = [events_pb2.EventFilter(key="address",
                                                    match_string=_get_certification_address_prefix() + '.*',
                                                    filter_type=events_pb2.EventFilter.REGEX_ANY)
                             ]
    peer_filters = [
        # filter to match prefix for peer_verification family
        events_pb2.EventFilter(key="address",
                               match_string=_get_peer_verification_address_prefix() + '.*',
                               filter_type=events_pb2.EventFilter.REGEX_ANY),

        # filter to receive verification requests coming to or verification responses received
        # for requests that generated from the corresponding client

        events_pb2.EventFilter(key="send_to",
                               match_string=public_key_hash,  # get this information frm metadata
                               filter_type=events_pb2.EventFilter.SIMPLE_ALL),
    ]
    filter_dict['certification_filters'] = certification_filters
    filter_dict['peer_filters'] = peer_filters

    events_client = UserEventsClient(filter_dict=filter_dict, )
    try:
        # listen to events
        events_client.listen_events()
    except KeyboardInterrupt:
        sys.exit(1)
    except SystemExit as err:
        raise err
    except BaseException as err:
        LOGGER.error(err)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    finally:
        events_client.disconnect()


def parse_param(parser, command, inp):
    parse_line = command + " " + inp
    LOGGER.debug("parse_line {}".format(parse_line))
    parsed_args = parser.parse_args(parse_line.split(" "))
    return parsed_args


class SkillWallet(Cmd):

    def __init__(self, command, rest_api, user=None, parser=None):
        super().__init__()
        self.parser = parser
        if user is None:
            self._client = UserWalletClient(base_url=rest_api, command=command, key_file_name=DEFAULT_KEY_FILE_NAME)
        else:
            self._client = UserWalletClient(base_url=rest_api, command=command, key_file_name=user)

        # self.proc_event_listener = multiprocessing.Process(target=_start_events_listener,
        #                                                    args=(self._client.public_address,))
        # self.proc_event_listener.start()

    # def __del__(self):
    #     try:
    #         self.proc_event_listener.terminate()
    #         # pass
    #     except AttributeError as err:
    #         LOGGER.debug(err)
    #         exit(0)

    def get_client(self):
        return self._client

    def do_request(self, inp):
        """ Sub command to request ID.  Calls userwallet_client class."""
        response = self._client.request_id()
        LOGGER.debug("Request ID Response: {}".format(response))

    def do_confirm(self, inp):
        """ Sub command to request ID.  Calls userwallet_client class."""
        response = self._client.confirm_id()
        LOGGER.debug("Confirm ID Response: {}".format(response))

    def do_display(self, inp):
        """ Sub command to request ID.  Calls userwallet_client class."""
        LOGGER.debug("Display ID Response: ")
        self._client.display_id()

    def do_peer_verify(self, inp):
        """ Sub command to request ID.  Calls userwallet_client.peer_verify"""
        LOGGER.debug("Calling peer_verify()")
        self._client.peer_verify()

    def do_attest_peer(self, inp):
        """ Sub command to process attestation request.
                                 Calls userwallet_client.attest_peer"""
        if self.parser is not None:
            parsed_args = parse_param(self.parser, "attest_peer", inp)
            req_txn = parsed_args.req_txn
        else:
            req_txn = inp
        # LOGGER.debug("Peer address: {}".format(inp.peer))
        LOGGER.debug("Requesting transaction ID: {}".format(req_txn))
        # response = self._client.attest_peer(inp.peer, inp.req_txn)
        response = self._client.attest_peer(req_txn)

        LOGGER.debug("attest_peer Response: {}".format(response))

    def do_save_ack(self, inp):
        """ Sub command to request ID.  Calls userwallet_client.save_ack_receipt"""
        LOGGER.debug("Calling save_ack_receipt()")
        response = self._client.save_ack_receipt()
        LOGGER.debug("save_ack Response: {}".format(response))

    def do_shareid_request(self, inp):
        """ Sub command to request ID.  Calls userwallet_client.do_request_id_share"""
        LOGGER.debug("Calling do_shareid_request()")
        if self.parser is not None:
            parsed_args = parse_param(self.parser, "shareid_request", inp)
            receiver = parsed_args.receiver
            data_mode = parsed_args.data_mode
        else:
            receiver = inp.receiver
            data_mode = inp.data_mode
        LOGGER.debug("Receiver Address: {}".format(receiver))
        LOGGER.debug("data_mode: {}".format(data_mode))
        response = self._client.do_request_id_share(to_address=receiver, data_mode=data_mode)
        LOGGER.debug("shareid_request Response: {}".format(response))

    def do_shareid_response(self, inp):
        """ Sub command to request ID.  Calls userwallet_client.do_respond_id_share"""
        LOGGER.debug("Calling do_shareid_response()")
        if self.parser is not None:
            parsed_args = parse_param(self.parser, "shareid_response", inp)
            receiver = parsed_args.receiver
            req_txn = parsed_args.req_txn
        else:
            receiver = inp.receiver
            req_txn = inp.req_txn
        LOGGER.debug("Receiver Address: {}".format(receiver))
        LOGGER.debug("Txn ID: {}".format(req_txn))
        response = self._client.do_respond_id_share(to_address=receiver, txn_id=req_txn)
        LOGGER.debug("shareid_response Response: {}".format(response))

    def do_display_shareid_response(self, inp):
        """ Sub command to request ID.  Calls userwallet_client.show_share_response"""
        LOGGER.debug("Calling do_display_shareid_response()")
        if self.parser is not None:
            parsed_args = parse_param(self.parser, "display_shareid_response", inp)
            receiver = parsed_args.receiver
            req_txn = parsed_args.req_txn
        else:
            receiver = inp.receiver
            req_txn = inp.req_txn
        LOGGER.debug("Receiver Address: {}".format(receiver))
        LOGGER.debug("Txn ID: {}".format(req_txn))
        response = self._client.show_share_response(receiver_address=receiver, resp_txn=req_txn)
        LOGGER.debug("display_shareid_response Response: {}".format(response))

    def do_update(self, inp):
        """ Sub command to update ID.  Calls userwallet_client class."""
        response = self._client.do_update_id()
        LOGGER.debug("Update ID Response: {}".format(response))

    def do_disable(self, inp):
        """ Sub command to invalidate ID.  Calls userwallet_client class."""
        response = self._client.invalidate_id()
        LOGGER.debug("Disable ID Response: {}".format(response))

    def do_ack_disable_req(self, inp):
        """ Sub command to send acknowledgement to invalidation request of ID.
        Calls userwallet_client class."""
        if self.parser is not None:
            parsed_args = parse_param(self.parser, "ack_disable_req", inp)
            req_txn = parsed_args.req_txn
        else:
            req_txn = inp.req_txn
        LOGGER.debug("Txn ID received: {}".format(req_txn))
        response = self._client.serve_id_disable_requests(req_txn)
        LOGGER.debug("ack_disable_req Response: {}".format(response))

    def do_request_recovery(self, inp):
        """ Sub command to send ID recovery request.
        Calls userwallet_client class."""
        response = self._client.recover_id()
        LOGGER.debug("Recovery Request Response: {}".format(response))

    def do_credibility_inc(self, inp):
        """ Sub command to increment credibility of ID attributes.
        Calls userwallet_client class."""
        response = self._client.add_verifier()
        LOGGER.debug("Recovery Request Response: {}".format(response))


def main(prog_name=os.path.basename(sys.argv[0]), args=None):
    """Entry point function for the _client CLI."""

    # logging.basicConfig()
    # logging.getLogger().setLevel(logging.DEBUG)
    try:

        if args is None:
            args = sys.argv[1:]

        parser = create_parser(prog_name)
        args = parser.parse_args(args)
        verbose_level = args.verbosity
        setup_loggers(verbose_level=verbose_level)
        LOGGER.debug("args: %s", args)
        LOGGER.critical("verbose_level: %s", verbose_level)

        user_name = args.user
        # Added new argument rest_api_url
        rest_api_url = args.rest_api_url
        if rest_api_url is None:
            rest_api_url = DEFAULT_URL

        LOGGER.debug("User name: %s", user_name)
        LOGGER.debug("REST-API URL: %s", rest_api_url)

        if args.command == 'id_wallet':
            wallet = SkillWallet(command='id_wallet', rest_api=rest_api_url, user=user_name, parser=parser)
            wallet.cmdloop()
        elif args.command == 'request':
            wallet = SkillWallet('request', rest_api_url, user_name)
            wallet.do_request("")
        elif args.command == 'confirm':
            wallet = SkillWallet('confirm', rest_api_url, user_name)
            wallet.do_confirm("")
        elif args.command == 'display':
            wallet = SkillWallet('display', rest_api_url, user_name)
            wallet.do_display("")
        elif args.command == 'peer_verify':
            wallet = SkillWallet('request_peer_verification', rest_api_url, user_name)
            wallet.do_peer_verify("")
        elif args.command == 'attest_peer':
            wallet = SkillWallet('attest_peer', rest_api_url, user_name)
            req_txn = args.req_txn
            LOGGER.debug("txn id {}".format(req_txn))
            wallet.do_attest_peer(req_txn)
        elif args.command == 'save_ack':
            wallet = SkillWallet('save_ack', rest_api_url, user_name)
            wallet.do_save_ack(args)
        elif args.command == 'update':
            wallet = SkillWallet('update', rest_api_url, user_name)
            wallet.do_update(args)
        elif args.command == 'disable':
            wallet = SkillWallet('disable', rest_api_url, user_name)
            wallet.do_disable(args)
        elif args.command == 'ack_disable_req':
            wallet = SkillWallet('ack_disable_req', rest_api_url, user_name)
            wallet.do_ack_disable_req(args)
        elif args.command == 'request_recovery':
            wallet = SkillWallet('request_recovery', rest_api_url, user_name)
            wallet.do_request_recovery(args)
        elif args.command == 'credibility_inc':
            wallet = SkillWallet('credibility_inc', rest_api_url, user_name)
            wallet.do_credibility_inc(args)
        elif args.command == 'shareid_request':
            wallet = SkillWallet('shareid_request', rest_api_url, user_name)
            wallet.do_shareid_request(args)
        elif args.command == 'shareid_response':
            wallet = SkillWallet('shareid_response', rest_api_url, user_name)
            wallet.do_shareid_response(args)
        elif args.command == 'display_shareid_response':
            wallet = SkillWallet('display_shareid_response', rest_api_url, user_name)
            wallet.do_display_shareid_response(args)
        else:
            raise Exception("Invalid command: {}".format(args.command))

    except KeyboardInterrupt:
        pass
    except SystemExit as err:
        raise err
    except BaseException as err:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
