# ! /usr/bin/env python3
import math

from sawtooth_signing.secp256k1 import Secp256k1PrivateKey
from sawtooth_signing.secp256k1 import Secp256k1PublicKey
import os
from sawtooth_signing import ParseError


def main():
    priv_key_str1 = 'f2712ca2f2ffaf55f468ccf332686c73bf3600a77b3140b9eddd5e26f44581b8'
    pub_key1 = '021f36fe23cfe09e25431903a7aa3cb71a211e74d701600ed91aa0ee413dbd8ac9'
    priv_key_str2 = '4039f7c886a39fa8377531e8956636f3889cc5e4f01b092fa673b46eb747eda9'
    pub_key2 = '03b345ab9ed3d7cdee0960f57e8bb3fe078a1d13adb00d60bce2f6a9715a8314cc'

    try:

        private_key = Secp256k1PrivateKey.from_hex(priv_key_str1)
        private_key2 = Secp256k1PrivateKey.from_hex(priv_key_str2)
        priv_bytes_A = private_key.as_bytes()
        priv_bytes_B = private_key2.as_bytes()

        public_key = Secp256k1PublicKey.from_hex(pub_key1)
        public_key2 = Secp256k1PublicKey.from_hex(pub_key2)
        pub_key_instanceA = public_key.secp256k1_public_key
        pub_key_instanceB = public_key2.secp256k1_public_key

        # ---diffie-hellman ecdsa----
        # code at A
        dh_pub_key_1 = pub_key_instanceB.tweak_mul(priv_bytes_A)   # center of the circle
        print(dh_pub_key_1)
        r1 = os.urandom(32)   # random code to append with data bytes
        ang = 45
        print("r1 {}".format(r1))
        r1_i = int.from_bytes(r1, 'big')
        print("r1_i {}".format(r1_i))
        x_comp = r1_i * math.cos(ang)
        print("x_comp {}".format(x_comp))
        y_comp = r1_i * math.sin(ang)
        print("y_comp {}".format(y_comp))
        dh_key_uncompressd = dh_pub_key_1.serialize(False)
        print(dh_key_uncompressd)
        print(bytes.hex(dh_key_uncompressd))
        x = dh_key_uncompressd[1:33]
        y = dh_key_uncompressd[33:65]
        y_hex = bytes.hex(y)
        x_hex = bytes.hex(x)
        print("x_hex {}".format(x_hex))
        print("y_hex {}".format(y_hex))

        x1_i = int.from_bytes(x, 'big')
        print("x1_i {}".format(x))

        y1_i = int.from_bytes(y, 'big')
        print("y1_i {}".format(y))

        x1 = x1_i + x_comp
        print("x1 {}".format(x1))  # share this securely
        y1 = y1_i + y_comp
        print("x1 {}".format(x1))  # share this securely

        # code at B
        dh_pub_key_2 = pub_key_instanceA.tweak_mul(priv_bytes_B)
        dh_key_uncompressd2 = dh_pub_key_2.serialize(False)
        print(dh_key_uncompressd2)
        print(bytes.hex(dh_key_uncompressd2))
        x2 = dh_key_uncompressd2[1:33]
        y2 = dh_key_uncompressd2[33:65]
        x2_i = int.from_bytes(x2, 'big')
        print("x2_i {}".format(x2_i))
        print("x1_i {}".format(x1_i))
        y2_i = int.from_bytes(y2, 'big')
        print("y2_i {}".format(y2_i))
        print("y1_i {}".format(y1_i))
        x_comp = x1 - x2_i
        print("x_comp {}".format(x_comp))
        y_comp = y1 - y2_i
        print("y_comp {}".format(y_comp))
        r = math.sqrt(x_comp * x_comp + y_comp * y_comp)
        print(r)
        print(r1_i)
        print(str(x1.hex()) + str(y1.hex()))

    except ParseError as err:
        raise Exception('Failed to load private key:{}'.format(str(err)))


if __name__ == '__main__':
    main()

