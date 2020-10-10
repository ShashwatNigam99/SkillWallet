#!/usr/bin/env python3
import hashlib


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


def get_digitalid_address(family_name, pub_key_hash, key=''):

    """Generates hexadecimal address as FAMILY_NAMESPACE.key.pub_key_hash"""
    # TF Prefix is first 6 characters of SHA-512(family_name)
    return hash512(family_name.encode('utf-8'))[0:6] + hash512(key.encode('utf-8'))[0:24] + pub_key_hash


def get_tf_prefix(family_name):
    return hash512(family_name.encode('utf-8'))[0:6]

