#!/usr/bin/env python3

"""
Command line interface for digital ID  TF.
"""

import argparse
import logging
import os
import sys
import traceback
from cmd import Cmd

from colorlog import ColoredFormatter

sys.path.append(os.getcwd())
from learner.learnerwallet_client import LearnerWalletClient

DEFAULT_KEY_FILE_NAME = 'skill_wallet'

# hard-coded for simplicity (otherwise get the URL from the args in main):
DEFAULT_URL = 'http://localhost:8008'
LOGGER = logging.getLogger('skillwallet')
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
    file_handler = logging.FileHandler('learner_wallet.log')
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
    subparsers.add_parser('skill_wallet', help='Start wallet in interactive mode', parents=[parent_parser])
    subparsers.add_parser('register', help='Register personal details to setup profile', parents=[parent_parser])
    subparsers.add_parser('request_validation', help='Send validation request for your registered personal details',
                          parents=[parent_parser])
    subparsers.add_parser('register_skill', help='Register a newly completed course',
                          parents=[parent_parser])
    subparsers.add_parser('display', help='Display digital id', parents=[parent_parser])
    subparsers.add_parser('save_ack', help='Save digital id acknowledgement to self state', parents=[parent_parser])
    subparsers.add_parser('print_code_file', help='Print contents of saved code file', parents=[parent_parser])
    gen_key_parser = subparsers.add_parser('generate_dec_key',
                                           help='generate file containing decode key for each field',
                                           parents=[parent_parser])
    gen_key_parser.add_argument('-k', '--receiver_key', dest='receiver_key', type=str,
                                help='public key of the receiver')
    gen_key_parser.add_argument('-f', '--file', dest='code_file', type=str,
                                help="File path of learner's ID code file")
    subparsers.add_parser('share_code_file', help='upload code_file in share directory of peer',
                          parents=[parent_parser])
    return parser


def parse_param(parser, command, inp):
    parse_line = command + " " + inp
    LOGGER.debug("parse_line {}".format(parse_line))
    parsed_args = parser.parse_args(parse_line.split(" "))
    return parsed_args


class LearnerWallet(Cmd):

    def __init__(self, command, rest_api, user=None, parser=None):
        super().__init__()
        self.parser = parser
        if user is None:
            self._client = LearnerWalletClient(base_url=rest_api, command=command, key_file_name=DEFAULT_KEY_FILE_NAME)
        else:
            self._client = LearnerWalletClient(base_url=rest_api, command=command, key_file_name=user)

    def get_client(self):
        return self._client

    def do_register(self, inp):
        """ Sub command to request ID.  Calls userwallet_client class."""
        response = self._client.register_pii()
        LOGGER.debug("Register Profile Response: {}".format(response))

    def do_register_skill(self, inp):
        """ Sub command to request ID.  Calls userwallet_client class."""
        response = self._client.register_skill()
        LOGGER.debug("Register Profile Response: {}".format(response))

    def do_display(self, inp):
        """ Sub command to request ID.  Calls userwallet_client class."""
        LOGGER.debug("Display ID Response: ")
        self._client.display_id()


    # def do_save_ack(self, inp):
    #     """ Sub command to request ID.  Calls userwallet_client.save_ack_receipt"""
    #     LOGGER.debug("Calling save_ack_receipt()")
    #     response = self._client.save_ack_receipt()
    #     LOGGER.debug("save_ack Response: {}".format(response))


    def do_generate_dec_key(self, inp):
        """ Sub command to generate ID data decode key files for the receiver public key.
        Calls userwallet_client.generate_dec_key"""
        LOGGER.debug("Calling do_share_response()")
        if self.parser is not None:
            parsed_args = parse_param(self.parser, "generate_dec_key", inp)
            receiver_key = parsed_args.receiver_key
            code_file = parsed_args.code_file
        else:
            receiver_key = inp.receiver_key
            code_file = inp.code_file
        LOGGER.debug("Receiver's Public Key: {}".format(receiver_key))
        LOGGER.debug("code_file path: {}".format(code_file))
        response = self._client.generate_dec_key(recvr_public_key=receiver_key, code_file_path=code_file)
        LOGGER.debug("do_generate_dec_key Response: {}".format(response))

    def do_print_code_file(self, inp):
        self._client.print_code_file()

    def do_share_code_file(self, inp):
        self._client.share_code_file()


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

        if args.command == 'skill_wallet':
            wallet = LearnerWallet(command='skill_wallet', rest_api=rest_api_url, user=user_name, parser=parser)
            wallet.cmdloop()
        elif args.command == 'register':
            wallet = LearnerWallet('register', rest_api_url, user_name)
            wallet.do_register("")
        elif args.command == 'register_skill':
            wallet = LearnerWallet('register_skill', rest_api_url, user_name)
            wallet.do_register_skill("")
        elif args.command == 'display':
            wallet = LearnerWallet('display', rest_api_url, user_name)
            wallet.do_display("")
        elif args.command == 'print_code_file':
            wallet = LearnerWallet('print_code_file', rest_api_url, user_name)
            wallet.do_print_code_file(args)
        elif args.command == 'generate_dec_key':
            wallet = LearnerWallet('generate_dec_key', rest_api_url, user_name)
            wallet.do_generate_dec_key(args)
        elif args.command == 'share_code_file':
            wallet = LearnerWallet('share_code_file', rest_api_url, user_name)
            wallet.do_share_code_file(args)
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
