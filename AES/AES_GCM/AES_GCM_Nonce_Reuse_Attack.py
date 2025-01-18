from sage.all import *
from Crypto.Util.number import long_to_bytes
from Crypto.Util.number import bytes_to_long
import struct


class AES_GCM_Nonce_Reuse_Attack:

    def __init__(self):
        pass

    def bytes_to_polynomial(self, block: bytes, a):
        """
        Convert a block of 16 bytes to a polynomial over GF(2^128)
        """
        poly = 0 
        # pad to 128
        bin_block = bin(bytes_to_long(block))[2 :].zfill(128)
        for i in range(len(bin_block)):
            poly += a**i * int(bin_block[i])
        return poly

    def polynomial_to_bytes(self, poly):
        """
        Convert a polynomial over GF(2^128) to a block of 16 bytes
        """
        return long_to_bytes(int(bin(poly._integer_representation())[2:].zfill(128)[::-1], 2))

    def convert_to_blocks(self, ciphertext: bytes):
        """
        Convert the ciphertext to blocks of 16 bytes
        """
        return [ciphertext[i:i + 16] for i in range(0 , len(ciphertext), 16)]

    def xor(self, s1: bytes, s2: bytes):
        if(len(s1) == 1 and len(s1) == 1):
            return bytes([ord(s1) ^ ord(s2)])
        else:
            return bytes(x ^ y for x, y in zip(s1, s2))

    def attack(self, pt1: bytes, ct1: bytes, T1: bytes, ct2: bytes, T2: bytes, pt: bytes ):
        """
        Perform the attack on AES-GCM with nonce reuse and return the forged ciphertext and tag for the plaintext pt we want to send
        """
        # Setting the working polynomial ring
        F, a = GF(2**128, name="a").objgen()
        R, x = PolynomialRing(F, name="x").objgen()

        # Recovering the keystream of AES-GCM
        keystream = self.xor(pt1, ct1)
        print(keystream)

        # Getting ciphertext of pt
        ct = self.xor(pt, keystream)
        print(ct)

        # Converting the ciphertexts to blocks of 16 bytes
        C1 = self.convert_to_blocks(ct1)
        C2 = self.convert_to_blocks(ct2)
        C3 = self.convert_to_blocks(ct)

        # Getting the polynomial of the ciphertexts
        L = struct.pack(">QQ", 0 * 8, len(C1) * 8) # Get length of the ciphertext
        C1_p = [self.bytes_to_polynomial(C1[i], a) for i in range(len(C1))]
        C2_p = [self.bytes_to_polynomial(C2[i], a) for i in range(len(C2))]
        C3_p = [self.bytes_to_polynomial(C3[i], a) for i in range(len(C3))]
        T1_p = self.bytes_to_polynomial(T1, a)
        T2_p = self.bytes_to_polynomial(T2, a)
        L_p = self.bytes_to_polynomial(L, a)

        # Recovering the hash key H and forging the tag for the ciphertext we want to send
        G_1 = (C1_p[0] * x**2) + (L_p * x) + T1_p
        G_2 = (C2_p[0] * x**2) + (L_p * x) + T2_p
        G_3 = (C3_p[0] * x**2) + (L_p * x)
        P = G_1 + G_2

        for H, _ in P.roots():
            EJ = G_1(H)
            T3 = G_3(H) + EJ
        
        return ct, self.polynomial_to_bytes(T3)

   