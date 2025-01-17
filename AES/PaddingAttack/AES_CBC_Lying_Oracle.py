from PaddingAttack.AES_CBC import Padding_Attack_AES_CBC

class Padding_Attack_AES_CBC_Lying_Oracle(Padding_Attack_AES_CBC):
    def __init__(self, check_message, check_padding, encr_flag, charset=None):
        super().__init__(check_message, check_padding, encr_flag, skip_padding_length_check=True)
        self.charset = charset

    def calculate_iv_byte(self, IV, plaintext_byte, byte_index, padding_value):
        """
        Calculate the IV byte needed to produce a specific plaintext byte for a given padding value.
        """
        return bytes([plaintext_byte ^ IV[-1 - byte_index] ^ padding_value])

    def get_possible_iv_bytes(self, IV, byte_index):
        """
        Get a list of possible IV bytes that produce plaintext bytes in the allowed charset.
        """
        padding_value = byte_index + 1
        return [
            self.calculate_iv_byte(IV, ord(char), byte_index, padding_value)
            for char in self.charset
        ]

    def determine_iv_byte(self, IV, ct_block, byte_index):
        """
        Determine the most probable IV byte for the given byte index.
        """
        possible_iv_bytes = self.get_possible_iv_bytes(IV, byte_index)
        scores = [0] * len(possible_iv_bytes)
        padding_value = byte_index + 1

        # Initialize IV prefix with known decrypted bytes
        iv_prefix = IV[:16 - byte_index - 1]
        decrypted_suffix = [
            self.block_after_decryption[j] ^ padding_value for j in range(byte_index)
        ][::-1]

        # Test possible IV bytes
        while max(scores) < 23:
            best_candidate_index = scores.index(max(scores))
            test_iv = (
                iv_prefix
                + possible_iv_bytes[best_candidate_index]
                + bytes(decrypted_suffix)

            )
            is_padding_valid = self.check_padding(test_iv.hex() + ct_block)
            scores[best_candidate_index] += 1 if not is_padding_valid else -1

        # Return the best IV byte
        best_byte = possible_iv_bytes[scores.index(max(scores))]
        return best_byte

    def determine_plaintext_byte(self, IV, byte_index):
        """
        Calculate the plaintext byte from the determined IV byte and padding value.
        """
        iv_byte = self.determine_iv_byte(IV, self.ct_block, byte_index)
        padding_value = byte_index + 1
        decrypted_byte = iv_byte[0] ^ padding_value
        plaintext_byte = decrypted_byte ^ IV[-1 - byte_index]
        self.block_after_decryption.append(decrypted_byte)
        return bytes([plaintext_byte])

    def attack_block(self, ct_block=None, IV=None):
        """
        Perform a padding attack on a single ciphertext block.
        """
        IV = self.IV if IV is None else IV
        self.ct_block = self.blocks[-1] if ct_block is None else ct_block
        self.block_after_decryption = []

        plaintext = b""
        for byte_index in range(16):
            print(f"Attacking byte {byte_index}")
            plaintext_byte = self.determine_plaintext_byte(IV, byte_index)
            plaintext = plaintext_byte + plaintext
            print(f"Decrypted so far: {plaintext}")

        print(f"Decrypted block: {plaintext}")
        return plaintext