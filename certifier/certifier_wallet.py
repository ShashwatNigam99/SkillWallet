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


def create_parser(prog_name):
    """Create the command line argument parser for the certifying wallet CLI."""
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)
    parent_parser.add_argument('-l', '--url', dest='rest_api_url', type=str, help="Rest-API URL")
    # parent_parser.add_argument('-a', '--address', dest='address', type=str, help="ID owner's public address")
    parent_parser.add_argument('-u', '--user', dest='user', type=str, help="Certifier name")
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

    attest_peer_parser = subparsers.add_parser('attest_skill', help='Verify and attest learning credential',
                                               parents=[parent_parser])
    attest_peer_parser.add_argument('-t', '--txn', dest='req_txn', type=str, help='requesting transaction id '
                                                                                  'for verification')
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

    def do_attest_skill(self, inp):
        """ Sub command to process attestation request.
                         Calls certifier_client class.attest_skill"""
        try:
            if self.parser is not None:
                parsed_args = parse_param(self.parser, "attest_skill", inp)
                req_txn = parsed_args.req_txn
            else:
                req_txn = inp
            LOGGER.debug("Requesting transaction ID: {}".format(req_txn))
            # response = self._client.attest_peer(inp.peer, inp.req_txn)
            response = self._client.attest_skill(req_txn)

            LOGGER.debug("attest_skill Response: {}".format(response))
        except BaseException as err:
            print("Exception due to {}".format(err))


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
        elif args.command == 'attest_skill':
            wallet = CertifierWallet(rest_api_url=rest_api_url, user=certifier_name)
            txn = args.req_txn
            LOGGER.debug("txn id {}".format(txn))
            wallet.do_attest_skill(txn)
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
