import tqdm

class Padding_Attack_AES_IGE():

    def __init__(self, send_msg, check_padding, encr_flag: str, c0: bytes, m0: bytes):
        self.send_msg = send_msg
        self.check_padding = check_padding
        self.encr_flag = encr_flag
        self.m0 = m0
        self.c0 = c0

    
    def get_blocks(self, ct: str):
        """
        Get the blocks of the ciphertext
        """
        blocks = []
        for i in range(0, len(ct), 32):
            blocks.append(ct[i:i+32])
        return blocks


    def search_padding_value(self, ct: str, m0: bytes, c0: bytes):
        """
        Search which byte to flip to have a wrong padding, which gives the padding value for pks7 padding (0x01, 0x02, 0x03, ...)
        """
        print("Searching  pks7 padding length...")
        for i in range(16):
            c0_to_test = c0[:i] + (c0[i] + 1 ).to_bytes() + c0[i+1:]

            good_padding = self.check_padding(self.send_msg(ct, m0.hex(), c0_to_test.hex()))
            if not good_padding:
                print(f"Found padding length {16 - i}")
                break
        return 16 - i


    def attack_block(self, ct_block: str = None, m0: bytes = None, c0: bytes = None):
        m0 = self.m0 if m0 is None else m0
        c0 = self.c0 if c0 is None else c0
        ct_block = self.get_blocks(self.encr_flag)[0] if ct_block is None else ct_block

        first_block_after_block_cipher_decryption = b''
        pt = b''

        for byte_to_determine in range(16):
            c0_to_test = c0[:16-byte_to_determine]
            # Determining bytes to add to have a good padding value when deci (0x01, 0x02,...)
            bytes_to_add = [first_block_after_block_cipher_decryption[j] ^ (byte_to_determine+1) for j in range(byte_to_determine)][::-1]
            c0_to_test += bytes(bytes_to_add)

            for i in tqdm.tqdm(range(256)):

                c0_to_test = c0_to_test[:-1 - byte_to_determine] + bytes([i]) + c0_to_test[16 - byte_to_determine:]
                good_padding = self.check_padding(self.send_msg(ct_block, m0.hex(), c0_to_test.hex()))
                
                if good_padding:
                    print(f"Found {i} as correct byte for padding")

                    padding_value = self.search_padding_value(ct_block, m0, c0_to_test)
                    first_block_after_block_cipher_decryption += bytes([i ^ padding_value])
                    pt = bytes([first_block_after_block_cipher_decryption[-1] ^ c0[-1 - byte_to_determine]]) + pt
                    break
            print("Partial decrypted flag :", pt)

        return pt
    
    def attack(self):
        blocks = self.get_blocks(self.encr_flag)
        decrypted_flag = b''
        for i in range(0, len(blocks)):
            m0 = self.m0 if i == 0 else decrypted_flag[16*(i-1): 16*i]
            c0 = self.c0 if i == 0 else bytes.fromhex(blocks[i-1])
            print(f"Attacking block {i}")
            decrypted_flag += self.attack_block(ct_block=blocks[i], m0=m0, c0=c0)
        print(decrypted_flag)
        return decrypted_flag
