

class LED():


    def __init__(self):
        self.constants = self._generate_constants(48)

        # PRESENT sbox
        self.sbox = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
        self.inv_sbox = [self.sbox.index(x) for x in range(16)]

        # MDS matrix
        self.mds = [
            [4, 1, 2, 2],
            [8, 6, 5, 6],
            [0xB, 0xE, 0xA, 9], 
            [2, 2, 0xF, 0xB]
        ]

        self.inv_mds = [
            [0xC, 0xC, 0xD, 0x4],
            [0x3, 0x8, 0x4, 0x5],
            [0x7, 0x6, 0x2, 0xE],
            [0xD, 0x9, 0x9, 0xD]
        ]


    def _generate_constants(self, n: int):
        consts = []
        lfsr = 0
        for _ in range(n):
            feedback = ((lfsr >> 5) ^ (lfsr >> 4) ^ 1) & 1
            lfsr = ((lfsr << 1) | feedback) & 0x3F
            consts.append(lfsr)
        return consts
    
    def g_mul(self, a: int, b: int):
        """Galois Field multiplication in GF(2^4) with poly x^4 + x + 1 (0x13)."""
        p = 0
        for _ in range(4):
            if b & 1: p ^= a
            hi = a & 0x8
            a <<= 1
            if hi: a ^= 0x13
            b >>= 1
        return p & 0xF

    def add_round_key(self, state, key: list[int]):
        return [[state[i][j] ^ (key[4*i + j]) for j in range(4)] for i in range(4)]
    
    def add_constants(self, state, round_index: int):
        rc = self.constants[round_index]
        ks = [8, 0] # keylength = 128 bits -> 1000 0000 -> [1000, 0000] -> [8, 0]
        rc_hi = (rc >> 3) & 0x7
        rc_low = rc & 0x7

        # Change 1st column
        state[0][0] ^= 0 ^ ks[0]
        state[1][0] ^= 1 ^ ks[0]
        state[2][0] ^= 2 ^ ks[1]
        state[3][0] ^= 3 ^ ks[1]

        # Change 2nd column
        state[0][1] ^= rc_hi
        state[1][1] ^= rc_low
        state[2][1] ^= rc_hi
        state[3][1] ^= rc_low

        return state

    def sub_cells(self, state, sbox):
        return [[sbox[state[i][j]] for j in range(4)] for i in range(4)]
    
    def shift_rows(self, state, direction="left"):
        """
            Shift by i the i_th row
        """
        new_state = [row[:] for row in state]
        for i in range(4):
            shift = i if direction == "left" else -i
            shift %= 4
            new_state[i] = state[i][shift:] + state[i][:shift]
        return new_state

    def mix_columns_serial(self, state, matrix):
        """
            returns the product of matrix * state
        """
        new_state = [[0]*4 for _ in range(4)]
        for j in range(4):
            for i in range(4):
                val = 0
                for k in range(4):
                    val ^= self.g_mul(matrix[i][k], state[k][j])
                new_state[i][j] = val
        return new_state

    def mix_columns_serial_2(self, state, mode="enc"):
        """The 'true' serial implementation of the LED MixColumns layer."""
        new_state = [[0]*4 for _ in range(4)]
        for j in range(4): # Process each column
            col = [state[i][j] for i in range(4)]
            for _ in range(4): # 4 serial steps make one MDS layer
                if mode == "enc":
                    # Feedback coefficients: 4, 1, 2, 2
                    v = self.g_mul(4, col[0]) ^ self.g_mul(1, col[1]) ^ \
                        self.g_mul(2, col[2]) ^ self.g_mul(2, col[3])
                    col = [col[1], col[2], col[3], v]
                else:
                    # Inverse: c0 = 13 * (v3 ^ v0 ^ 2v1 ^ 2v2)
                    # 13 is the inverse of 4 in GF(2^4)
                    v3, v0, v1, v2 = col[3], col[0], col[1], col[2]
                    c0 = self.g_mul(13, v3 ^ v0 ^ self.g_mul(2, v1) ^ self.g_mul(2, v2))
                    col = [c0, v0, v1, v2]
            for i in range(4):
                new_state[i][j] = col[i]
        return new_state
    
    def encrypt_block(self, pt: bytes, key: bytes):
        """
            pt: plaintext of 8 bytes
            
            key: key of 16 bytes to encrypt the ciphertext

            return ct: ciphertext of 8 bytes
        """
        assert len(pt) == 8 and len(key) == 16 
        pt = pt.hex().rjust(16, '0')
        key = key.hex().rjust(32, '0')
        # Separate the key in 2 blocks of 8 bytes
        key = [ [int(k, 16) for k in key[:16]], [int(k, 16) for k in key[16:]] ]

        state = [[int(pt[4*i + j], 16) for j in range(4)] for i in range(4)]

        for step in range(12):
            # Altern with key1 (first 8 bytes) and key2 (last 8 bytes) of the key
            state = self.add_round_key(state, key[step % 2])

            for r in range(4):
                state = self.add_constants(state, step * 4 + r)
                state = self.sub_cells(state, self.sbox)
                state = self.shift_rows(state)
                state = self.mix_columns_serial(state, self.mds)

        state = self.add_round_key(state, key[12 % 2])

        return bytes.fromhex("".join(f"{nibble:x}" for row in state for nibble in row))

    def decrypt_block(self, ct: bytes, key: bytes):
        """
            ct: ciphertext of 8 bytes

            key: key of 16 bytes to decrypt the ciphertext

            return pt: plaintext of 8 bytes
        """
        assert len(ct) == 8 and len(key) == 16 
        ct = ct.hex().rjust(16, '0')
        key = key.hex().rjust(32, '0')
        # Separate the key in 2 blocks of 8 bytes
        key = [ [int(k, 16) for k in key[:16]], [int(k, 16) for k in key[16:]] ]

        state = [[int(ct[4*i + j], 16) for j in range(4)] for i in range(4)]

        state = self.add_round_key(state, key[12 % 2])

        for step in range(11, -1, -1):
            for r in range(3, -1, -1):
                state = self.mix_columns_serial(state, self.inv_mds)
                state = self.shift_rows(state, "right")
                state = self.sub_cells(state, self.inv_sbox)
                state = self.add_constants(state, step * 4 + r)
            
            state = self.add_round_key(state, key[step % 2])

        return bytes.fromhex("".join(f"{nibble:x}" for row in state for nibble in row))


import os

cipher = LED()
# key = os.urandom(16)
# pt = os.urandom(8)
key = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
pt = b'\x00\x00\x00\x00\x00\x00\x00\x00'

key = b'\x01\x23\x45\x67\x89\xAB\xCD\xEF\x01\x23\x45\x67\x89\xAB\xCD\xEF'
pt = b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'

print(pt.hex())
ct = cipher.encrypt_block(pt, key)
print(ct.hex())
pt_ = cipher.decrypt_block(ct, key)
print(pt_.hex())
assert pt == pt_
