#!/usr/bin/env python3
import hashlib
import json
import logging
import math
from random import random

from sawtooth_signing.secp256k1 import Secp256k1PublicKey

LOGGER = logging.getLogger('certifier_wallet.client')
LOGGER.setLevel(logging.DEBUG)


# renamed _hash method to hash512
def hash512(data):
    """Compute the SHA-512 hash and return the result as hex characters."""
    return hashlib.sha512(data).hexdigest()


def get_hash_from_bytes(data_bytes):
    hash_obj = hashlib.sha512()
    hash_obj.update(data_bytes)
    return hash_obj.hexdigest().encode('utf-8')


def get_pub_key_hash(public_key):
    """Generates hex string from double hash of public key"""
    sha_hash = hashlib.sha512(public_key.encode('utf-8')).digest()
    ripemd_hash = hashlib.new('ripemd160', sha_hash)
    return ripemd_hash.hexdigest()


def get_encoding(data_str, code_bytes):
    # return get_double_hash_160(data_str.encode('utf-8') + code_bytes)
    data_bytes = data_str.encode('utf-8') + code_bytes
    sha_hash = hashlib.sha512(data_bytes).digest()
    ripemd_hash = hashlib.new('ripemd160', sha_hash)
    ripemd_hex_digest = ripemd_hash.hexdigest()
    ripemd_bytes_digest = bytes.fromhex(ripemd_hex_digest)
    return ripemd_bytes_digest


def get_digitalid_address(family_name, pub_key_hash, key=''):
    """Generates hexadecimal address as FAMILY_NAMESPACE.key.pub_key_hash"""
    # TF Prefix is first 6 characters of SHA-512(family_name)
    return hash512(family_name.encode('utf-8'))[0:6] + hash512(key.encode('utf-8'))[0:24] + pub_key_hash


def get_tf_prefix(family_name):
    return hash512(family_name.encode('utf-8'))[0:6]


def get_code_from_key(symm_key, dec_key):
    symm_key_uncompressd = symm_key.serialize(False)
    LOGGER.debug("symm_key_uncompressd {} ".format(symm_key_uncompressd))
    x2 = symm_key_uncompressd[1:33]
    y2 = symm_key_uncompressd[33:65]
    x2_i = int.from_bytes(x2, 'big')
    LOGGER.debug("x2_i {}".format(x2_i))
    y2_i = int.from_bytes(y2, 'big')
    LOGGER.debug("y2_i {}".format(y2_i))
    dec_key_dict = json.loads(dec_key)
    x1 = dec_key_dict.get('x')
    y1 = dec_key_dict.get('y')
    x_comp = x1 - x2_i
    LOGGER.debug("x_comp {}".format(x_comp))
    y_comp = y1 - y2_i
    LOGGER.debug("y_comp {}".format(y_comp))
    r = math.sqrt(x_comp * x_comp + y_comp * y_comp)
    r_n = int(r)
    r_bytes = r_n.to_bytes(32, 'big')
    LOGGER.debug("code {}".format(r))
    LOGGER.debug("code {}".format(r_bytes))


def verify_data_value(data_bytes, r):
    data_str = input("Enter plain text data: ")
    enc_data = get_encoding(data_str=data_str.lower(), code_bytes=r)
    # enc_data = get_encoding(data_str=data_str, code_bytes=r)
    if enc_data == data_bytes:
        return True
    else:
        return False


def get_symmetric_key(private_key_bytes, public_key_bytes):
    public_key = Secp256k1PublicKey.from_hex(public_key_bytes)
    pub_key_instance = public_key.secp256k1_public_key
    symm_key = pub_key_instance.tweak_mul(private_key_bytes)
    return symm_key


def gen_decode_key(symm_key, code):
    ang = random.randint(0, 360)
    r_i = int.from_bytes(code, 'big')
    LOGGER.debug("r_i {}".format(r_i))
    x_comp = r_i * math.cos(ang)
    LOGGER.debug("x_comp {}".format(x_comp))
    y_comp = r_i * math.sin(ang)
    LOGGER.debug("y_comp {}".format(y_comp))
    symm_key_uncompressd = symm_key.serialize(False)
    LOGGER.debug(symm_key_uncompressd)
    x = symm_key_uncompressd[1:33]
    y = symm_key_uncompressd[33:65]

    x1_i = int.from_bytes(x, 'big')
    LOGGER.debug("x1_i {}".format(x))

    y1_i = int.from_bytes(y, 'big')
    LOGGER.debug("y1_i {}".format(y))

    x1 = x1_i + x_comp
    LOGGER.debug("x1 {}".format(x1))  # share this securely
    y1 = y1_i + y_comp
    LOGGER.debug("y1 {}".format(y1))  # share this securely
    key_dict = {
        'x': x1,
        'y': y1
    }
    encoded_key_bytes = json.dumps(key_dict)
    return encoded_key_bytes
