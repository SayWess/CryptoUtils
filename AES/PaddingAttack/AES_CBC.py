import tqdm

class Padding_Attack_AES_CBC():

    def __init__(self, check_message, check_padding, encr_flag: str, rounds: int = 1, skip_padding_length_check: bool = False):
        self.check_message = check_message
        self.check_padding = check_padding
        self.encr_flag = encr_flag
        self.blocks = self.get_blocks(encr_flag)
        self.IV = bytes.fromhex(self.blocks[0])
        self.rounds = rounds
        self.skip_padding_length_check = skip_padding_length_check

    def get_blocks(self, ct: str):
        """
        Get the blocks of the ciphertext
        """
        blocks = []
        for i in range(0, len(ct), 32):
            blocks.append(ct[i:i+32])
        return blocks
    
    def search_padding_value(self, ct: str, IV: bytes):
        """
        Search which byte to flip to have a wrong padding, which gives the padding value for pks7 padding (0x01, 0x02, 0x03, ...)
        """
        print("Searching  pks7 padding length...")
        for i in range(16):
            IV_to_test = IV[:i] + ((IV[i] + 1) % 256 ).to_bytes() + IV[i+1:]
            for _ in range(self.rounds):
                good_padding = self.check_padding(IV_to_test.hex() + ct)
                if not good_padding:
                    break
            if not good_padding:
                print(f"Found padding length {16 - i}")
                break
        return 16 - i
    
    def attack_block(self, ct_block: str = None, IV: bytes = None):
        IV = self.IV if IV is None else IV
        ct_block = self.blocks[-1] if ct_block is None else ct_block

        first_block_after_block_cipher_decryption = b''
        pt = b''

        for byte_to_determine in range(16):
            IV_to_test = IV[:16-byte_to_determine]
            # Determining bytes to add to have a good padding value when deci (0x01, 0x02,...)
            bytes_to_add = [first_block_after_block_cipher_decryption[j] ^ (byte_to_determine+1) for j in range(byte_to_determine)][::-1]
            IV_to_test += bytes(bytes_to_add)

            for i in tqdm.tqdm(range(256)):

                IV_to_test = IV_to_test[:-1 - byte_to_determine] + bytes([i]) + IV_to_test[16 - byte_to_determine:]
                for _ in range(self.rounds):
                    good_padding = self.check_padding(IV_to_test.hex() + ct_block)
                    if not good_padding:
                        break
                
                if good_padding:
                    print(f"Found {i} as correct byte for padding")

                    if self.skip_padding_length_check:
                        padding_value = (byte_to_determine + 1)
                    else : 
                        padding_value = self.search_padding_value(ct_block, IV_to_test)

                    first_block_after_block_cipher_decryption += bytes([i ^ padding_value])
                    pt = bytes([first_block_after_block_cipher_decryption[-1] ^ IV[-1 - byte_to_determine]]) + pt
                    break
            print("Partial decrypted flag :", pt)

        return pt
    
    def attack(self):
        decrypted_flag = b''
        for i in range(1, len(self.blocks)):
            print(f"Attacking block {i}")
            print()
            decrypted_flag += self.attack_block(ct_block=self.blocks[i], IV=bytes.fromhex(self.blocks[i-1]))
        return self.check_message(decrypted_flag)