from itertools import combinations
import numpy as np


class XLAttacker:
    def __init__(self, mq_system):
        self.sys = mq_system
        self.n = mq_system.n
        self.m = mq_system.m

    def generate_monomials(self, degree):
        monomials = []

        for d in range(1, degree + 1):
            for combo in combinations(range(self.n), d):
                monomials.append(combo)

        monomials.sort(key=lambda x: (len(x), x))
        return monomials

    def multiply_monomial(self, mono1, mono2):
        combined = set(mono1) | set(mono2)
        return tuple(sorted(list(combined)))

    def solve(self, ciphertext, D=3):
        print(f"\n[ATAK XL] Rozpoczynam atak z parametrem D={D}")

        all_monos = self.generate_monomials(D)
        mono_to_col = {m: i for i, m in enumerate(all_monos)}
        num_cols = len(all_monos) + 1  # +1 na wyraz wolny (prawa strona równania)

        print(f"  -> Liczba wszystkich monomianów (kolumn): {num_cols}")

        rows = []

        print("  -> Generowanie wierszy macierzy (Expansion)...")
        for eq_idx in range(self.m):
            base_eq_monos = []  # Lista par (monomian, wartość=1)

            for r in range(self.n):
                for c in range(r, self.n):
                    val = self.sys.pub_gamma[eq_idx, r, c]
                    if r != c:
                        val ^= self.sys.pub_gamma[eq_idx, c, r]

                    if val == 1:
                        m = tuple(sorted(set((r, c))))
                        base_eq_monos.append(m)

            for r in range(self.n):
                if self.sys.pub_beta[eq_idx, r] == 1:
                    m = (r,)
                    base_eq_monos.append(m)

            constant = (self.sys.pub_alpha[eq_idx] + ciphertext[eq_idx]) % 2

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
        print(
            f"  -> Macierz XL zbudowana. Rozmiar: {matrix.shape[0]}x{matrix.shape[1]}"
        )
        print("  -> Rozpoczynam eliminację Gaussa (to może chwilę potrwać)...")

        # 3. Linearyzacja (Gauss)
        solved_matrix = self.gauss_elimination_gf2(matrix)

        # 4. Odczytanie wyniku
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
                    val = row[-1]
                    res_bits[var_idx] = val
                    solved_count += 1

        if solved_count == self.n:
            print(f"  [SUKCES] Odzyskano wszystkie {self.n} zmiennych!")
            return res_bits
        else:
            print(
                f"  [PORAŻKA] Odzyskano tylko {solved_count}/{self.n} zmiennych. Zwiększ D lub liczbę równań."
            )
            return None

    def gauss_elimination_gf2(self, M):
        """Standardowa eliminacja Gaussa nad GF(2)."""
        M = M.copy()
        rows, cols = M.shape
        pivot_row = 0

        for j in range(cols - 1):
            if pivot_row >= rows:
                break

            # Znajdź wiersz z jedynką w kolumnie j
            candidates = np.where(M[pivot_row:, j] == 1)[0]
            if len(candidates) == 0:
                continue

            # Zamień wiersze
            curr = candidates[0] + pivot_row
            M[[pivot_row, curr]] = M[[curr, pivot_row]]

            # Zeruj pozostałe wiersze w tej kolumnie
            others = np.where(M[:, j] == 1)[0]
            for r_idx in others:
                if r_idx != pivot_row:
                    M[r_idx] ^= M[pivot_row]

            pivot_row += 1
        return M
