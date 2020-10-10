#!/usr/bin/env python3
import os
import sys
from sawtooth_signing import ParseError, create_context, CryptoFactory
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey

sys.path.append(os.getcwd())
from util.hashing import get_pub_key_hash


def _get_private_key_file(key_file_name):
    """Get the private key from key_file_name."""
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")
    return '{}/{}.priv'.format(key_dir, key_file_name)


class CryptoKeyManager(object):

    def __init__(self, key_file_name):
        self.key_file_name = key_file_name
        _key_file = _get_private_key_file(self.key_file_name)
        try:
            with open(_key_file) as fd:
                private_key_str = fd.read().strip()
        except OSError as err:
            raise Exception('Failed to read private key {}: {}'.format(_key_file, str(err)))

        try:
            self.privateKey = Secp256k1PrivateKey.from_hex(private_key_str)
        except ParseError as err:
            raise Exception('Failed to load private key:{}'.format(str(err)))

        _signer = CryptoFactory(create_context('secp256k1')).new_signer(self.privateKey)
        self.public_key = _signer.get_public_key().as_hex()
        self.public_key_hash = get_pub_key_hash(self.public_key)



