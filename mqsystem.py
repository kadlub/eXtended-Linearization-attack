import numpy as np

# ==========================================
# CZĘŚĆ 1: SYSTEM KRYPTOGRAFICZNY MQ
# ==========================================


class MQSystem:
    def __init__(self, n, m):
        self.n = n
        self.m = m
        print(f"\n[SYSTEM] Inicjalizacja MQ (n={n} zmiennych, m={m} równań)")

    def generate_keys(self):
        print("[SYSTEM] Generowanie kluczy...")
        self.pub_gamma = np.random.randint(
            0, 2, (self.m, self.n, self.n), dtype=np.int8
        )
        self.pub_beta = np.random.randint(0, 2, (self.m, self.n), dtype=np.int8)
        self.pub_alpha = np.random.randint(0, 2, self.m, dtype=np.int8)

        print("  -> Klucz publiczny wygenerowany (zestaw wielomianów).")

    def encrypt_block(self, bits):
        """Szyfruje jeden blok n-bitowy."""
        ciphertext = np.zeros(self.m, dtype=np.int8)
        for i in range(self.m):
            quad = bits @ self.pub_gamma[i] @ bits
            lin = bits @ self.pub_beta[i]
            ciphertext[i] = (quad + lin + self.pub_alpha[i]) % 2
        return ciphertext

    def decrypt_block_legitimate(self, cipher_block):
        for i in range(2**self.n):
            candidate_bits = np.array(
                [int(b) for b in format(i, f"0{self.n}b")], dtype=np.int8
            )
            check = self.encrypt_block(candidate_bits)
            if np.array_equal(check, cipher_block):
                return candidate_bits
        return None

    def text_to_blocks(self, text):
        print(f"[SYSTEM] Konwersja tekstu: '{text}' na wektory bitowe...")
        blocks = []
        for char in text:
            val = ord(char)
            bits_str = format(val, f"0{self.n}b")
            if len(bits_str) > self.n:
                bits_str = bits_str[-self.n :]

            vec = np.array([int(b) for b in bits_str], dtype=np.int8)
            blocks.append(vec)
        return blocks

    def blocks_to_text(self, blocks):
        chars = []
        for b in blocks:
            val = 0
            for bit in b:
                val = (val << 1) | int(bit)
            chars.append(chr(val))
        return "".join(chars)
