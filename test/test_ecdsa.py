# ! /usr/bin/env python3
import math

import secp256k1
import hashlib
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey
from sawtooth_signing.secp256k1 import Secp256k1PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from sawtooth_signing import ParseError

from util import hashing


def main():
    priv_key_str = 'f2712ca2f2ffaf55f468ccf332686c73bf3600a77b3140b9eddd5e26f44581b8'
    pub_key = '021f36fe23cfe09e25431903a7aa3cb71a211e74d701600ed91aa0ee413dbd8ac9'
    pub_key2 = '03b345ab9ed3d7cdee0960f57e8bb3fe078a1d13adb00d60bce2f6a9715a8314cc'
    pub_key3 = '03b93cae9c1223758714ce2eb95d374555840de8020a76a5c5f995419e10d7d47f'
    priv_key_str2 = '4039f7c886a39fa8377531e8956636f3889cc5e4f01b092fa673b46eb747eda9'
    priv_key_str3 = '4ecb7acb42fb76a744355b70223f27dbcaaefb9f08ef858fcea6a4117faf4dbb'

    try:

        private_key = Secp256k1PrivateKey.from_hex(priv_key_str)
        private_key2 = Secp256k1PrivateKey.from_hex(priv_key_str2)
        private_key3 = Secp256k1PrivateKey.from_hex(priv_key_str3)
        priv_bytes_A = private_key.as_bytes()
        priv_bytes_B = private_key2.as_bytes()
        priv_bytes_C = private_key3.as_bytes()
        # priv_key_instanceA = private_key.secp256k1_private_key

        public_key = Secp256k1PublicKey.from_hex(pub_key)
        public_key2 = Secp256k1PublicKey.from_hex(pub_key2)
        public_key3 = Secp256k1PublicKey.from_hex(pub_key3)
        pub_key_instanceA = public_key.secp256k1_public_key
        pub_key_instanceB = public_key2.secp256k1_public_key
        # pub_key_instanceC = public_key3.secp256k1_public_key
        # priv_key_instance = secp256k1.PrivateKey(privkey=private_key)
        # print(priv_key_instance)
        # priv_key_instance.pubkey.serialize(compressed)
        # pub_key_instance2 = secp256k1.PublicKey(pubkey=public_key)
        # pub_bytes_A = pub_key_instanceA.serialize(False)

        # priv_key_compressed_A = priv_key_instanceA.serialize()
        # print(pub_key_instanceA)
        # print(priv_key_instanceA)
        # print(priv_key_compressed_A)
        # print(priv_bytes)

        pub_key_compressed_A = pub_key_instanceA.serialize()
        # pub_bytes_A = pub_key_compressed_A[: -1]
        # print("pub_bytes_A {}".format(pub_bytes_A))
        # print("length of pub_bytes_C {}".format(len(pub_bytes_A)))

        # pub_key_compressed_B = pub_key_instanceB.serialize()
        # pub_bytes_B = pub_key_compressed_B[: -1]
        # print("pub_bytes_B {}".format(pub_bytes_B))
        # print("length of pub_bytes_C {}".format(len(pub_bytes_B)))
        #
        # pub_key_compressed_C = pub_key_instanceC.serialize()
        # pub_bytes_C = pub_key_compressed_C[: -1]
        # print("pub_bytes_C {}".format(pub_bytes_C))
        # print("length of pub_bytes_C {}".format(len(pub_bytes_C)))

        # priv_bytes_A = bytes(bytearray.fromhex(priv_key_compressed_A))
        # print(len(priv_bytes_A))

        # ---diffie-hellman ecdsa----
        # dh_pub_key_1 = pub_key_instanceB.tweak_mul(priv_bytes_A)
        # dh_pub_key_2 = pub_key_instanceA.tweak_mul(priv_bytes_B)
        # ---------------------

        secp256k1_pubkey_A = pub_key_instanceA.deserialize(pub_key_compressed_A)
        print(secp256k1_pubkey_A)
        combined_key_AB = pub_key_instanceB.combine([secp256k1_pubkey_A])
        print("combined_key_AB {}".format(combined_key_AB))
        pub_key_AB = secp256k1.PublicKey(combined_key_AB)
        print("pub_key_AB {}".format(pub_key_AB))
        compressed_pub_key_AB = pub_key_AB.serialize()
        print("compressed_pub_key_AB {}".format(compressed_pub_key_AB))
        compressed_pub_key_AB_hex = bytes.hex(compressed_pub_key_AB)
        # B shares this to A. A knows inverse of publicKey of A but does not know publicKey B
        print("compressed_pub_key_AB_hex {}".format(compressed_pub_key_AB_hex))

        # find inverse of secp256k1_pubkey_A
        pub_key_uncompressed_A = pub_key_instanceA.serialize(False)
        print("pub_key_uncompressed_A {}".format(pub_key_uncompressed_A))
        print("pub_key_compressed_A {}".format(pub_key_compressed_A))
        print("len(pub_key_compressed_A) {}".format(len(pub_key_compressed_A)))
        print("len(pub_key_uncompressed_A) {}".format(len(pub_key_uncompressed_A)))
        x_A = pub_key_compressed_A[1:]
        pub_key_uncompressed_hex = bytes.hex(pub_key_uncompressed_A)
        x_A_1 = pub_key_uncompressed_A[1:33]
        y_A = pub_key_uncompressed_A[33:65]

        y_hex = bytes.hex(y_A)
        x_hex = bytes.hex(x_A_1)
        print("x_A {}".format(x_A))
        print("x_A_1 {}".format(x_A_1))
        print("y_A {}".format(y_A))
        print("pub_key_uncompressed_hex {}".format(pub_key_uncompressed_hex))
        print("x_hex {}".format(x_hex))
        print("y_hex {}".format(y_hex))
        xy = 0x1f36fe23cfe09e25431903a7aa3cb71a211e74d701600ed91aa0ee413dbd8ac925231e891b81038b647d9665025e5f96be0bd39750544f9343a5af0d0370ee56
        x = 0x1f36fe23cfe09e25431903a7aa3cb71a211e74d701600ed91aa0ee413dbd8ac9
        y = 0x25231e891b81038b647d9665025e5f96be0bd39750544f9343a5af0d0370ee56
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC2F
        inv_y = p-y % p
        print("inv_y {}".format(inv_y))
        uncomp_x_A_1 = pub_key_uncompressed_A[0:33]
        inv_y_bytes = inv_y.to_bytes(32, byteorder="big")
        print("inv_p_bytes {}".format(inv_y_bytes))
        print("uncomp_x_A_1 {}".format(uncomp_x_A_1))
        inv_pub_uncomp_A = uncomp_x_A_1+inv_y_bytes
        print(inv_pub_uncomp_A)
        inv_A_pub_uncomp_hex = bytes.hex(inv_pub_uncomp_A)
        print(inv_A_pub_uncomp_hex)

        # x = int.from_bytes(x_A_1, 'big')
        # y = int.from_bytes(y_A, 'big')
        res = ((y * y) - (x * x * x) - 7) % p
        print("res {}".format(res))
        # trying to find public_key of B from  public_key_instance_AB
        # public_key_sawtooth_AB = Secp256k1PublicKey.from_hex(compressed_pub_key_AB_hex)
        # print("public_key_sawtooth_AB {}".format(public_key_sawtooth_AB))
        # public_key_instance_AB = public_key_sawtooth_AB.secp256k1_public_key
        # print("public_key_instance_AB {}".format(public_key_instance_AB))
        # public_key_sawtooth_inv_A = Secp256k1PublicKey.from_hex(inv_A_pub_uncomp_hex)
        # print("public_key_sawtooth_inv_A {}".format(public_key_sawtooth_inv_A))

        # pub = secp256k1.PublicKey()
        # pub.deserialize(inv_pub_uncomp_A)
        # print("len {}".format(len(inv_pub_uncomp_A)))
        # secp256k1_pubkey_A = pub_key_instanceA.deserialize(pub_key_compressed_A)
        # print(secp256k1_pubkey_A)
        # public_key_instance_AB.combine()

        # ------ finding and sharing common key among three parties-----
        # # primary certifier = A. A encrypts data with symmetric key as A fills data.
        #         # learner = B
        #         # peer = C
        # print(pub_key_instanceB.serialize())
        # group_pub_key_B = pub_key_instanceC.tweak_mul(priv_bytes_A)
        # group_pub_key_A = pub_key_instanceC.tweak_mul(priv_bytes_B)
        # group_pub_key_C = pub_key_instanceA.tweak_mul(priv_bytes_B)  # shared by B
        #
        # r1 = os.urandom(32)
        # group_pub_key_B = group_pub_key_B.tweak_mul(r1)
        # group_pub_key_A = group_pub_key_A.tweak_mul(r1)
        # group_pub_key_C = group_pub_key_C.tweak_mul(r1)
        # # ABC
        # dh_pub_key_1 = group_pub_key_B.tweak_mul(priv_bytes_B)
        # dh_pub_key_2 = group_pub_key_A.tweak_mul(priv_bytes_A)
        # dh_pub_key_3 = group_pub_key_C.tweak_mul(priv_bytes_C)
        #
        # dh_pub_1 = dh_pub_key_1.serialize()
        # dh_pub_2 = dh_pub_key_2.serialize()
        # dh_pub_3 = dh_pub_key_3.serialize()
        # print(dh_pub_1)
        # print(dh_pub_2)
        # print(dh_pub_3)
        # if dh_pub_1 == dh_pub_2 and \
        #         dh_pub_2 == dh_pub_3:
        #     print(True)


        # dh_pub_1 = dh_pub_1[: -1]
        # symm_key = int.from_bytes(dh_pub_2, byteorder='big')
        #
        # print(symm_key)
        # backend = default_backend()
        # iv = os.urandom(16)
        # cipher = Cipher(algorithms.AES(dh_pub_1), modes.CBC(iv), backend=backend)
        # encryptor = cipher.encryptor()
        # msg = b"toothbrush"
        # msg = msg.ljust(16, b'-')
        # print(msg)
        # print(len(msg))
        # ct = encryptor.update(msg) + encryptor.finalize()
        # print(ct)
        # print(len(ct))
        # hashed_ct = hashlib.sha512(ct)
        # print(hashed_ct)
        # decryptor = cipher.decryptor()
        # text = decryptor.update(ct) + decryptor.finalize()
        # print(text)
        # new_pub_key = pub_key_instanceA.tweak_mul(dh_pub_1)
        # new_key_bytes = new_pub_key.serialize()
        # new_pub_key_hex = bytes.hex(new_key_bytes)
        # print(new_pub_key_hex)   # choice 1 for  pub_key_hash candidate
        # iv = os.urandom(16)
        # cipher = Cipher(algorithms.AES(dh_pub_1), modes.CBC(iv), backend=backend)
        # encryptor = cipher.encryptor()
        # # blockchain address
        # hashed_key = hashing.get_hash_from_bytes(pub_key2.encode('utf-8'))
        # print(len(hashed_key))
        # ct = encryptor.update(hashed_key) + encryptor.finalize()
        # ct_hex = bytes.hex(ct)
        # print(len(ct_hex))
        # print(len(ct))

        # pub_key_hash = double_hash(Sym_Encrypt(combine public keys (own_pub_key + receiver's_pub_key)))
        # sharing_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_SHAREDID,
        #                                                       pub_key_hash=self.to_address,
        #                                                       key=self.public_address)
        # public_key.ecdh()
    except ParseError as err:
        raise Exception('Failed to load private key:{}'.format(str(err)))


if __name__ == '__main__':
    main()

