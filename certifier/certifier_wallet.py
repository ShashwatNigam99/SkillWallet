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

# sys.path.append('/home/suchira/digital-id/certifier')
# home = os.path.expanduser("~")
# proj_dir = os.path.join(home, "digital-id")
# sys.path.append(proj_dir)

sys.path.append(os.getcwd())
from certifier.certifier_client import CertifierWalletClient

KEY_FILE_NAME = 'certifier1'

# hard-coded for simplicity (otherwise get the URL from the args in main):
DEFAULT_URL = 'http://localhost:8008'
LOGGER = logging.getLogger('certifier_wallet')


# For Docker:
# DEFAULT_URL = 'http://rest-api:8008'


def create_console_handler(verbose_level):
    """Setup console logging."""
    clog = logging.StreamHandler()
    formatter = ColoredFormatter(
        "%(log_color)s[%(asctime)s %(levelname)-8s%(module)s]%(reset)s "
        "%(white)s%(message)s",
        datefmt="%H:%M:%S",
        reset=True,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red',
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
    file_handler = logging.FileHandler('certifier_wallet.log')
    file_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    return file_handler


def setup_loggers(verbose_level=0):
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


# def setup_loggers(verbose_level):
#     """Setup logging."""
#     logger = logging.getLogger()
#     logger.setLevel(logging.DEBUG)
#     logger.addHandler(create_console_handler(verbose_level))


def create_parser(prog_name):
    """Create the command line argument parser for the certifying wallet CLI."""
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)
    parent_parser.add_argument('-l', '--url', dest='rest_api_url', type=str, help="Rest-API URL")
    # parent_parser.add_argument('-a', '--address', dest='address', type=str, help="ID owner's public address")
    parent_parser.add_argument('-u', '--learner', dest='learner', type=str, help="Certifier name")
    parent_parser.add_argument('-v', '--verbosity1', action='store_const', const=1, default=0, dest='verbosity',
                               help='sets verbosity level to 1')
    parent_parser.add_argument('-vv', '--verbosity2', action='store_const', const=2, dest='verbosity',
                               help='sets verbosity level to 2')
    parent_parser.add_argument('-vvv', '--verbosity3', action='store_const', const=3, dest='verbosity',
                               help='sets verbosity level to 3')
    parser = argparse.ArgumentParser(
        description='Provides sub-commands for managing certifier wallet',
        parents=[parent_parser])

    subparsers = parser.add_subparsers(title='subcommands', dest='command')
    subparsers.required = True
    subparsers.add_parser('certifier_wallet', help="Start certifier's wallet in interactive mode",
                          parents=[parent_parser])
    fill_parser = subparsers.add_parser('fill_details', help='Take learner input for creating new ID',
                                        parents=[parent_parser])
    fill_parser.add_argument('-a', '--address', dest='address', type=str, help="ID owner's public address")
    process_request_parser = subparsers.add_parser('process_request', help='Issue new digital id',
                                                   parents=[parent_parser])
    process_request_parser.add_argument('-a', '--address', dest='address', type=str, help="ID owner's public address")

    subparsers.add_parser('process_pending_requests', help='Issue new digital id to requests in event db',
                          parents=[parent_parser])

    confirm_parser = subparsers.add_parser('confirm', help='Confirm and attest validated credentials',
                                           parents=[parent_parser])
    confirm_parser.add_argument('-a', '--address', dest='address', type=str, help="ID owner's public address")

    # send_ack = subparsers.add_parser('send_ack', help='Acknowledge confirmed ID', parents=[parent_parser])
    # send_ack.add_argument('-a', '--address', dest='address', type=str, help="ID owner's public address")

    # attest_peer_parser = subparsers.add_parser('attest_peer', help='Verify and attest peer data',
    #                                            parents=[parent_parser])
    # attest_peer_parser.add_argument('-a', '--address', dest='address', type=str, help="ID owner's public address")
    # attest_peer_parser.add_argument('-p', '--peer', dest='peer', type=str, help='peer address')
    # attest_peer_parser.add_argument('-t', '--txn', dest='req_txn', type=str, help='requesting transaction id '
    #                                                                               'for verification')

    share_req_parser = subparsers.add_parser('shareid_request', help='Request Digital-ID Sharing',
                                             parents=[parent_parser])
    share_req_parser.add_argument('-r', '--receiver', dest='receiver', type=str, help='Address of intended receiver')
    share_req_parser.add_argument('-d', '--add_data', dest='data_mode', required=False, action='store_const',
                                  const=True,
                                  help='Option is True if ID attribute data is required')
    share_disp_parser = subparsers.add_parser('display_shareid_response', help='Display Shared Digital-ID',
                                              parents=[parent_parser])
    share_disp_parser.add_argument('-r', '--receiver', dest='receiver', type=str, help='Address of sender')
    share_disp_parser.add_argument('-t', '--txn', dest='req_txn', type=str,
                                   help='Transaction ID of the ID share response')
    return parser


def _get_private_key_file(key_file_name):
    """Get the private key from key_file_name."""
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")
    return '{}/{}.priv'.format(key_dir, key_file_name)


def parse_param(parser, command, inp):
    parse_line = command + " " + inp
    LOGGER.debug("parse_line {}".format(parse_line))
    parsed_args = parser.parse_args(parse_line.split(" "))
    return parsed_args


class CertifierWallet(Cmd):

    def __init__(self, parser=None, rest_api_url=DEFAULT_URL, user=None):
        super().__init__()
        self.parser = parser
        LOGGER.debug("learner %s", user)
        if user is None:
            # replaced DEFAULT_URL with rest_api_url
            self._client = CertifierWalletClient(base_url=rest_api_url, key_file_name=KEY_FILE_NAME)
        else:
            self._client = CertifierWalletClient(base_url=rest_api_url, key_file_name=user)

    def do_send_ack(self, inp):
        """ Sub command to send ID confirmation acknowledgement.
         Calls certifier_client class.send_ack"""
        LOGGER.debug("inside do_send_ack")
        try:
            if self.parser is not None:
                parsed_args = parse_param(self.parser, "send_ack", inp)
                address = parsed_args.address
            else:
                address = inp
            LOGGER.debug("address {}".format(address))
            response = self._client.send_ack(address)
            LOGGER.debug("send_ack Response: {}".format(response))
        except BaseException as err:
            print("Exception due to {}".format(err))

    def do_process_request(self, inp):
        """ Sub command to process ID request.
                 Calls certifier_client class.process_id_request"""
        try:
            if self.parser is not None:
                parsed_args = parse_param(self.parser, "process_request", inp)
                address = parsed_args.address
            else:
                address = inp
            LOGGER.debug("address {}".format(address))
            response = self._client.process_id_request(address)
            LOGGER.debug("process_request Response: {}".format(response))
        except BaseException as err:
            print("Exception due to {}".format(err))

    def do_process_pending_requests(self, inp):
        """ Sub command to process ID request from event db.
                 Calls certifier_client class.process_pending_requests"""
        try:
            response = self._client.process_pending_requests()
            LOGGER.debug("process_pending_requests Response: {}".format(response))
        except BaseException as err:
            print("Exception due to {}".format(err))

    def do_ack_disable_req(self, inp):
        """ Sub command to process ID request from event db.
                 Calls certifier_client class.process_pending_requests"""
        try:
            if self.parser is not None:
                parsed_args = parse_param(self.parser, "ack_disable_req", inp)
                req_txn = parsed_args.req_txn
            else:
                req_txn = inp

            LOGGER.debug("Requesting transaction ID: {}".format(req_txn))
            response = self._client.serve_id_disable_requests(req_txn)
            LOGGER.debug("ack_disable_req Response: {}".format(response))
        except BaseException as err:
            print("Exception due to {}".format(err))

    def do_attest_peer(self, inp):
        """ Sub command to process attestation request.
                         Calls certifier_client class.attest_peer"""
        # LOGGER.debug("Peer address: {}".format(inp.peer))
        try:
            if self.parser is not None:
                parsed_args = parse_param(self.parser, "attest_peer", inp)
                req_txn = parsed_args.req_txn
            else:
                req_txn = inp
            LOGGER.debug("Requesting transaction ID: {}".format(req_txn))
            # response = self._client.attest_peer(inp.peer, inp.req_txn)
            response = self._client.attest_peer(req_txn)

            LOGGER.debug("attest_peer Response: {}".format(response))
        except BaseException as err:
            print("Exception due to {}".format(err))

    def do_recover_id(self, inp):
        """ Sub command to process attestation request.
                         Calls certifier_client class.attest_peer"""
        # LOGGER.debug("Peer address: {}".format(inp.peer))
        # response = self._client.attest_peer(inp.peer, inp.req_txn)
        try:
            if self.parser is not None:
                parsed_args = parse_param(self.parser, "recover_id", inp)
                req_txn = parsed_args.req_txn
            else:
                req_txn = inp
            LOGGER.debug("Requesting transaction ID: {}".format(req_txn))
            response = self._client.process_recovery_request(req_txn)
            LOGGER.debug("recover_id Response: {}".format(response))
        except BaseException as err:
            print("Exception due to {}".format(err))

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
        LOGGER.debug("hash_only_mode: {}".format(data_mode))
        response = self._client.do_request_id_share(to_address=receiver, data_mode=data_mode)
        LOGGER.debug("shareid_request Response: {}".format(response))

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

        certifier_name = args.user
        LOGGER.debug("certifier_name: %s", certifier_name)
        # Added new argument rest_api_url
        rest_api_url = args.rest_api_url
        if rest_api_url is None:
            rest_api_url = DEFAULT_URL
        LOGGER.debug("REST-API url: %s", rest_api_url)
        if args.command == 'certifier_wallet':
            wallet = CertifierWallet(parser=parser, rest_api_url=rest_api_url, user=certifier_name)
            wallet.cmdloop()
        elif args.command == 'send_ack':
            owner_address = args.address
            LOGGER.debug("Owner address: %s", owner_address)
            wallet = CertifierWallet(rest_api_url=rest_api_url, user=certifier_name)
            wallet.do_send_ack(owner_address)
        elif args.command == 'process_request':
            wallet = CertifierWallet(rest_api_url=rest_api_url, user=certifier_name)
            owner_address = args.address
            LOGGER.debug("Owner address: %s", owner_address)
            wallet.do_process_request(owner_address)
        elif args.command == 'attest_peer':
            wallet = CertifierWallet(rest_api_url=rest_api_url, user=certifier_name)
            txn = args.req_txn
            LOGGER.debug("txn id {}".format(txn))
            wallet.do_attest_peer(txn)
        elif args.command == 'process_pending_requests':
            wallet = CertifierWallet(rest_api_url=rest_api_url, user=certifier_name)
            wallet.do_process_pending_requests(args)
        elif args.command == 'ack_disable_req':
            wallet = CertifierWallet(rest_api_url=rest_api_url, user=certifier_name)
            txn = args.req_txn
            LOGGER.debug("txn id {}".format(txn))
            wallet.do_ack_disable_req(txn)
        elif args.command == 'recover_id':
            wallet = CertifierWallet(rest_api_url=rest_api_url, user=certifier_name)
            txn = args.req_txn
            LOGGER.debug("txn id {}".format(txn))
            wallet.do_recover_id(txn)
        elif args.command == 'shareid_request':
            wallet = CertifierWallet(rest_api_url=rest_api_url, user=certifier_name)
            wallet.do_shareid_request(args)
        elif args.command == 'display_shareid_response':
            wallet = CertifierWallet(rest_api_url=rest_api_url, user=certifier_name)
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
