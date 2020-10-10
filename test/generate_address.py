import hashlib

from sawtooth_signing import CryptoFactory, create_context

from util import hashing
from util.crypto_keys import CryptoKeyManager

FAMILY_NAME = 'digitalid'  # 2122d3
CERTIFY_FAMILY_NAME = "digitalid_certifier"


def _hash(data):
    return hashlib.sha512(data).hexdigest()


def _hash_bytes(data_bytes):
    hash_obj = hashlib.sha512()
    hash_obj.update(data_bytes)
    return hash_obj.hexdigest().encode('utf-8')


def _get_pub_key_hash(public_key):
    """Generates hex string from double hash of public key"""
    sha_hash = hashlib.sha512(public_key.encode('utf-8')).digest()
    ripemd_hash = hashlib.new('ripemd160', sha_hash)
    shareable_address = ripemd_hash.hexdigest()
    print('shareable_address: {}'.format(shareable_address) )
    return shareable_address


def _generate_address(family_name, key='', pub_key_hash=None):
    """Generates hexadecimal address as FAMILY_NAMESPACE.key.pub_key_hash"""
    if pub_key_hash is None:
        return _hash(family_name.encode('utf-8'))[0:6] + _hash(key.encode('utf-8'))[0:64]
    else:
        return _hash(family_name.encode('utf-8'))[0:6] + _hash(key.encode('utf-8'))[0:24] + pub_key_hash


def main():

    # public_key1 = '02e1a5879572635ff106ef03f2db4d14b09158b427f8f360b3a638dfc22dc8e7a9'
    # pub_digital_id = '031a9ea8578936a1f5d2338582ec93028cb6382a95b1933e1242ea033800cce99f'
    # public_key2 = '03d35fcae5539d754cbf323901e70171caae50a8bafa40fdf16b1fb0bf373b37c6'
    # pub_certifier = '02ca91b7e24b9031c3202d1a5c8b9d434500dfddf60f1b09f31bd0ebf267eb57d6'
    # pub_certifier2 = '03b345ab9ed3d7cdee0960f57e8bb3fe078a1d13adb00d60bce2f6a9715a8314cc'
    # pub_certifier3 = '03b93cae9c1223758714ce2eb95d374555840de8020a76a5c5f995419e10d7d47f'
    # pub_user1 = '0309745d3f8a1f21538d2e9fb331269992e23bacf45da25c504b506dc61a72c638'
    # address = _generate_address(FAMILY_NAME_DIGITALID, 'self', _get_pub_key_hash(pub_digital_id))
    # user6 = '03fe529659cf495a2e94ac236ed50334769936ebc8fc42d3223eccb9a5b19399cf'
    # address = _get_pub_key_hash(user6)

    certifier_key = CryptoKeyManager(key_file_name='certifier4')
    _signer = CryptoFactory(create_context('secp256k1')).new_signer(certifier_key.privateKey)
    # public_key = _signer.get_public_key().as_hex()
    # print("certifier4".casefold())
    # print(certifier_key.public_key)
    # print(certifier_key.public_key_hash)
    digital_id_bytes = '\b001'
    _owner_signature = _signer.sign(hashing.get_hash_from_bytes(digital_id_bytes.encode("utf-8")))
    print(_owner_signature)
    # print(hashing.get_digitalid_address(FAMILY_NAME, '608f3dba2bc689b4d88038f5f8333f955fc23215', 'self'))


if __name__ == '__main__':
    main()
