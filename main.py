from mqsystem import MQSystem
from xlattacker import XLAttacker


def bits_to_hex(bits):
    byte_list = [bits[i : i + 8] for i in range(0, len(bits), 8)]

    hex_list = [format(int("".join(map(str, byte)), 2), "02x") for byte in byte_list]
    return " ".join(hex_list)


# ==========================================
# CZĘŚĆ 3: PREZENTACJA (MAIN)
# ==========================================


def main():
    print("==================================================")
    print("   DEMO: Kryptografia MQ i Atak XL")
    print("   Kryptografia Post-Kwantowa w Praktyce")
    print("==================================================\n")

    N = 16
    M = 30

    # 1. Inicjalizacja
    mq = MQSystem(N, M)
    mq.generate_keys()
    attacker = XLAttacker(mq)

    # 2. Wiadomość
    message = "KRYS to super przedmiot jest"
    print(f"\n[USER] Chcę wysłać tajną wiadomość: '{message}'")

    # 3. Szyfrowanie (Legalne)
    print("\n--- SZYFROWANIE (Użytkownik) ---")
    blocks = mq.text_to_blocks(message)
    ciphertexts = []

    for i, block in enumerate(blocks):
        ct = mq.encrypt_block(block)
        ciphertexts.append(ct)
        print(f"Blok {i} ('{message[i]}') -> zaszyfrowano do {len(ct)} bitów.")
        print(f"\t{bits_to_hex(ct)}")

    # 4. Deszyfrowanie (Legalne - z kluczem)
    print("\n--- DESZYFROWANIE (Właściciel klucza) ---")
    decrypted_msg = ""
    for ct in ciphertexts:
        dec_block = mq.decrypt_block_legitimate(ct)
        decrypted_msg += mq.blocks_to_text([dec_block])
    print(f"Właściciel odczytał: '{decrypted_msg}'")
    assert decrypted_msg == message

    # 5. ATAK XL (Hacker)
    print("\n==================================================")
    print("   ROZPOCZYNAM ATAK XL (Bez klucza prywatnego)")
    print("==================================================")

    hacked_msg = ""
    DEGREE = 7  # Stopień XL. Dla m=30, n=8, D=2 może nie wystarczyć, D=3 jest pewne.

    for i, ct in enumerate(ciphertexts):
        print(f"\n>>> Atakowanie bloku {i}...")
        # Hacker widzi tylko: Klucz Publiczny (w obiekcie mq) i Szyfrogram (ct)
        recovered_bits = attacker.solve(ct, D=DEGREE)

        if recovered_bits is not None:
            char = mq.blocks_to_text([recovered_bits])
            print(f"  -> Zdekodowano znak: '{char}'")
            hacked_msg += char
        else:
            hacked_msg += "?"

    print("\n==================================================")
    print("PODSUMOWANIE:")
    print(f"Oryginał:  {message}")
    print(f"Złamane:   {hacked_msg}")

    if message == hacked_msg:
        print("\n[SUKCES] Atak XL całkowicie przełamał szyfrowanie!")
    else:
        print("\n[CZĘŚCIOWY SUKCES] Niektóre bloki pozostały bezpieczne.")


if __name__ == "__main__":
    main()
