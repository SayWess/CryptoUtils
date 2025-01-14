from sage.all import *


class AES_Linear_Attack():

    def __init__(self, encrypt_local, encrypt_remote, encr_flag: str):
        self.encrypt_local = encrypt_local
        self.encrypt_remote = encrypt_remote
        self.encr_flag = encr_flag
    
    def hex_to_vector(self, message_block):
        return vector(GF(2), map(int, bin(int(message_block, 16))[2:].zfill(128)))

    def message_block_to_vector(self, message_block):
        return vector(GF(2), map(int, bin(int(message_block, 16))[2:].zfill(128)))

    def vector_to_hex(self, vector):
        return hex(int(''.join([str(int(x)) for x in list(vector)]), 2))[2:].zfill(2)

    def get_b_aes(self, local = True):
        """
        Get the b value if AES is linear : ct = Ax + b
        """
        known_pt = hex(0)[2:].zfill(32)
        known_ct = self.encrypt_local(known_pt) if local else self.encrypt_remote(known_pt)
        b_aes = self.hex_to_vector(known_ct)
        return b_aes

    def get_A_aes(self):
        """
        Get the A value if AES is linear : ct = Ax + b
        """
        A_aes = matrix(GF(2), 128, 128)
        b_aes = self.get_b_aes()
        for i in range(128):
            input = "0"*i + "1" + "0"*(127-i)
            input = "".join([hex(int(input[8*i:8*(i+1)], 2))[2:].zfill(2) for i in range(16)])
            output = self.encrypt_local(input)
            output_vector = self.hex_to_vector(output)
            output_xor_b = vector(GF(2), [ int(a) ^ int(b) for a, b in zip(output_vector, b_aes)])
            A_aes[:, i] = vector(GF(2), map(int, output_xor_b))
        return A_aes

    def attack(self):
        A_aes = self.get_A_aes()
        b_aes = self.get_b_aes(False)
        flag_ct = self.encr_flag
        A_aes_inv = A_aes.inverse()

        flag = ""
        for i in range(0, len(flag_ct)//32):
            flag += self.vector_to_hex(A_aes_inv*(self.hex_to_vector(flag_ct[32*i:32*(i+1)]) + b_aes))
        return bytes.fromhex(flag)