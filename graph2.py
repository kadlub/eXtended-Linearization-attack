import numpy as np
from itertools import combinations
import sys
import matplotlib.pyplot as plt  # Dodano do wizualizacji

# ==========================================
# CZĘŚĆ 1: SYSTEM KRYPTOGRAFICZNY MQ
# ==========================================


class MQSystem:
    def __init__(self, n, m):
        """
        Inicjalizacja systemu.
        n: liczba zmiennych (bitów w bloku)
        m: liczba równań (musi być m >= n, dla XL najlepiej m > n)
        """
        self.n = n
        self.m = m
        # print(f"\n[SYSTEM] Inicjalizacja MQ (n={n} zmiennych, m={m} równań)") # Mniej spamu przy eksperymencie

    def generate_keys(self):
        """
        Generuje klucz publiczny (losowe wielomiany) i 'symuluje' klucz prywatny.
        W prawdziwym HFE/Rainbow klucz publiczny jest tworzony przez złożenie S o F o T.
        Tutaj, dla celów edukacyjnych ataku XL, generujemy losowy układ.
        """
        # print("[SYSTEM] Generowanie kluczy...")
        # Klucz publiczny: P(x) = xGx + Bx + a
        # Gamma: część kwadratowa (m x n x n)
        self.pub_gamma = np.random.randint(
            0, 2, (self.m, self.n, self.n), dtype=np.int8
        )
        # Beta: część liniowa (m x n)
        self.pub_beta = np.random.randint(0, 2, (self.m, self.n), dtype=np.int8)
        # Alpha: wyraz wolny (m)
        self.pub_alpha = np.random.randint(0, 2, self.m, dtype=np.int8)

        # print("  -> Klucz publiczny wygenerowany (zestaw wielomianów).")

    def encrypt_block(self, bits):
        """Szyfruje jeden blok n-bitowy."""
        # Wzór: y_k = x * G_k * x^T + B_k * x^T + a_k  (wszystko mod 2)
        ciphertext = np.zeros(self.m, dtype=np.int8)
        for i in range(self.m):
            # Część kwadratowa: x^T * G * x
            quad = bits @ self.pub_gamma[i] @ bits
            # Część liniowa: B * x
            lin = bits @ self.pub_beta[i]
            # Suma + wyraz wolny
            ciphertext[i] = (quad + lin + self.pub_alpha[i]) % 2
        return ciphertext

    def decrypt_block_legitimate(self, cipher_block):
        """
        Symulacja legalnego deszyfrowania przez właściciela klucza.
        """
        for i in range(2**self.n):
            candidate_bits = np.array(
                [int(b) for b in format(i, f"0{self.n}b")], dtype=np.int8
            )
            check = self.encrypt_block(candidate_bits)
            if np.array_equal(check, cipher_block):
                return candidate_bits
        return None

    def text_to_blocks(self, text):
        """Zamienia tekst na listę bloków bitowych."""
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


# ==========================================
# CZĘŚĆ 2: IMPLEMENTACJA ATAKU XL
# ==========================================


class XLAttacker:
    def __init__(self, mq_system):
        self.sys = mq_system
        self.n = mq_system.n
        self.m = mq_system.m

    def generate_monomials(self, degree):
        """Generuje wszystkie unikalne monomiany do stopnia 'degree'."""
        monomials = []
        for d in range(1, degree + 1):
            for combo in combinations(range(self.n), d):
                monomials.append(combo)
        monomials.sort(key=lambda x: (len(x), x))
        return monomials

    def multiply_monomial(self, mono1, mono2):
        """Mnoży dwa monomiany w GF(2)."""
        combined = set(mono1) | set(mono2)
        return tuple(sorted(list(combined)))

    def solve(self, ciphertext, D=3, visualize=False, verbose=True):
        if verbose:
            print(f"\n[ATAK XL] Rozpoczynam atak z parametrem D={D}")

        # 1. Baza monomianów
        all_monos = self.generate_monomials(D)
        mono_to_col = {m: i for i, m in enumerate(all_monos)}
        num_cols = len(all_monos) + 1

        if verbose:
            print(f"  -> Liczba wszystkich monomianów (kolumn): {num_cols}")

        rows = []

        # 2. Generowanie równań (Expansion)
        if verbose:
            print("  -> Generowanie wierszy macierzy (Expansion)...")
        for eq_idx in range(self.m):
            base_eq_monos = []

            # Gamma
            for r in range(self.n):
                for c in range(r, self.n):
                    val = self.sys.pub_gamma[eq_idx, r, c]
                    if r != c:
                        val ^= self.sys.pub_gamma[eq_idx, c, r]
                    if val == 1:
                        base_eq_monos.append(tuple(sorted(set((r, c)))))

            # Beta
            for r in range(self.n):
                if self.sys.pub_beta[eq_idx, r] == 1:
                    base_eq_monos.append((r,))

            # Alpha + Ciphertext
            constant = (self.sys.pub_alpha[eq_idx] + ciphertext[eq_idx]) % 2

            # Expansion
            mult_monos = [()]
            if D > 2:
                mult_monos += self.generate_monomials(D - 2)

            for mult_m in mult_monos:
                row = np.zeros(num_cols, dtype=np.int8)
                for term in base_eq_monos:
                    new_term = self.multiply_monomial(term, mult_m)
                    if new_term in mono_to_col:
                        row[mono_to_col[new_term]] ^= 1

                if constant == 1:
                    if mult_m == ():
                        row[-1] ^= 1
                    else:
                        row[mono_to_col[mult_m]] ^= 1

                rows.append(row)

        matrix = np.array(rows, dtype=np.int8)
        if verbose:
            print(
                f"  -> Macierz XL zbudowana. Rozmiar: {matrix.shape[0]}x{matrix.shape[1]}"
            )

        matrix_before = None
        if visualize:
            matrix_before = matrix.copy()

        if verbose:
            print("  -> Rozpoczynam eliminację Gaussa...")

        # 3. Linearyzacja
        solved_matrix = self.gauss_elimination_gf2(matrix)

        # 4. Wizualizacja
        if visualize:
            self.visualize_attack(
                matrix_before, solved_matrix, all_monos, "Wizualizacja Ataku XL"
            )

        # 5. Odczytanie wyniku
        if verbose:
            print("  -> Analiza wyników...")
        res_bits = np.zeros(self.n, dtype=np.int8)
        solved_count = 0

        for row in solved_matrix:
            ones = np.where(row[:-1] == 1)[0]
            if len(ones) == 1:
                idx = ones[0]
                mono = all_monos[idx]
                if len(mono) == 1:
                    var_idx = mono[0]
                    res_bits[var_idx] = row[-1]
                    solved_count += 1

        if solved_count == self.n:
            if verbose:
                print(f"  [SUKCES] Odzyskano wszystkie {self.n} zmiennych!")
            return res_bits
        else:
            if verbose:
                print(f"  [PORAŻKA] Odzyskano tylko {solved_count}/{self.n} zmiennych.")
            return None

    def gauss_elimination_gf2(self, M):
        """Standardowa eliminacja Gaussa nad GF(2)."""
        M = M.copy()
        rows, cols = M.shape
        pivot_row = 0

        for j in range(cols - 1):
            if pivot_row >= rows:
                break
            candidates = np.where(M[pivot_row:, j] == 1)[0]
            if len(candidates) == 0:
                continue

            curr = candidates[0] + pivot_row
            M[[pivot_row, curr]] = M[[curr, pivot_row]]

            others = np.where(M[:, j] == 1)[0]
            for r_idx in others:
                if r_idx != pivot_row:
                    M[r_idx] ^= M[pivot_row]

            pivot_row += 1
        return M

    def visualize_attack(self, matrix_before, matrix_after, monomials, title):
        """Rysuje macierze z podpisanymi osiami monomianów."""
        print(f"  -> [GRAFIKA] Generowanie wykresu: {title}...")

        # Przygotowanie etykiet dla osi X (np. "x0", "x0x1")
        # Wyświetlamy tylko co n-tą etykietę, żeby nie zamazać wykresu
        labels = []
        for m in monomials:
            label = "".join([f"x{i}" for i in m])
            labels.append(label)
        labels.append("C")  # Constant column

        # Ograniczamy liczbę etykiet do max 20 dla czytelności
        step = max(1, len(labels) // 20)
        tick_indices = list(range(0, len(labels), step))
        tick_labels = [labels[i] for i in tick_indices]

        plt.figure(figsize=(14, 6))

        # Macierz przed
        plt.subplot(1, 2, 1)
        plt.title("1. Macierz XL (Przed Gaussem)", fontsize=12)
        plt.imshow(matrix_before, cmap="binary", interpolation="nearest", aspect="auto")
        plt.xlabel("Monomiany (np. x1, x1x2...)")
        plt.ylabel("Równania (Expansion)")
        plt.xticks(tick_indices, tick_labels, rotation=45, ha="right", fontsize=8)

        # Macierz po
        plt.subplot(1, 2, 2)
        plt.title("2. Po Redukcji (Widoczne rozwiązanie)", fontsize=12)
        plt.imshow(matrix_after, cmap="binary", interpolation="nearest", aspect="auto")
        plt.xlabel("Zmienne Liniowe (Rozwiązanie)")
        # Tutaj najważniejsze są pierwsze kolumny (x0, x1...), więc przybliżmy etykiety
        plt.xticks(tick_indices, tick_labels, rotation=45, ha="right", fontsize=8)

        plt.suptitle(title, fontsize=16)
        plt.tight_layout()
        plt.show()


def run_security_experiment(N, max_m_factor=6):
    """
    Eksperyment naukowy: Jak liczba równań wpływa na szansę złamania?
    """
    print("\n==================================================")
    print("   EKSPERYMENT: Skuteczność Ataku vs Liczba Równań")
    print("==================================================")

    m_values = list(range(N, N * max_m_factor, 2))

    m_values.append(98)
    m_values.append(102)
    m_values.append(112)
    m_values.append(130)
    m_values.append(168)
    m_values.append(244)
    m_values.append(394)
    m_values.append(696)
    success_rates = []

    # Próbka testowa
    test_bits = np.random.randint(0, 2, N, dtype=np.int8)
    D = 3

    for m in m_values:
        print(f"Testowanie dla m={m} równań...", end="")
        sys.stdout.flush()

        # Tworzymy system z m równaniami
        mq = MQSystem(N, m)
        mq.generate_keys()
        ct = mq.encrypt_block(test_bits)

        attacker = XLAttacker(mq)
        # Wyłączamy verbose/visualize dla szybkości
        res = attacker.solve(ct, D=D, visualize=False, verbose=False)

        if res is not None and np.array_equal(res, test_bits):
            print(" [SUKCES]")
            success_rates.append(1)
        else:
            print(" [PORAŻKA]")
            success_rates.append(0)

    # Wykres eksperymentu
    plt.figure(figsize=(10, 5))
    plt.plot(m_values, success_rates, marker="o", linestyle="-", color="crimson")
    plt.title(f"Przejście fazowe ataku XL (N={N}, Stopień D={D})")
    plt.xlabel("Liczba równań (m)")
    plt.ylabel("Czy złamano? (0/1)")
    plt.grid(True, linestyle="--", alpha=0.7)
    plt.axvline(
        x=696,
        color="green",
        linestyle=":",
        label=r"Teoretyczny próg ($m \approx \binom{16}{1} + \binom{16}{2} + \binom{16}{3} = 696$)",
    )
    plt.legend()
    plt.show()


# ==========================================
# CZĘŚĆ 3: PREZENTACJA (MAIN)
# ==========================================


def main():
    print("==================================================")
    print("   DEMO: Kryptografia MQ i Atak XL")
    print("==================================================\n")

    # KONFIGURACJA
    N = 16
    M = 42

    mq = MQSystem(N, M)
    mq.generate_keys()
    attacker = XLAttacker(mq)

    message = "Flag{X}"
    print(f"\n[USER] Wiadomość: '{message}'")

    print("\n--- SZYFROWANIE ---")
    blocks = mq.text_to_blocks(message)
    ciphertexts = []

    for i, block in enumerate(blocks):
        ct = mq.encrypt_block(block)
        ciphertexts.append(ct)
        # print(f"Blok {i} ('{message[i]}') -> zaszyfrowano.")

    print("\n==================================================")
    print("   ROZPOCZYNAM ATAK XL")
    print("==================================================")

    hacked_msg = ""
    DEGREE = 3

    for i, ct in enumerate(ciphertexts):
        print(f"\n>>> Atakowanie bloku {i}...")

        # Włączamy wizualizację TYLKO dla pierwszego bloku (i=0)
        show_plot = i == 0

        recovered_bits = attacker.solve(ct, D=DEGREE, visualize=show_plot)

        if recovered_bits is not None:
            char = mq.blocks_to_text([recovered_bits])
            print(f"  -> Zdekodowano: '{char}'")
            hacked_msg += char
        else:
            hacked_msg += "?"

    print("\n==================================================")
    print(f"Złamane hasło: {hacked_msg}")

    # --- URUCHOMIENIE EKSPERYMENTU ---
    # Odkomentuj poniższą linię, aby zobaczyć wykres zależności sukcesu od m
    run_security_experiment(N=16)  # Mniejsze N dla szybkości demo


if __name__ == "__main__":
    main()
