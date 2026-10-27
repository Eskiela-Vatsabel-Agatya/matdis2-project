# menyediakan algoritma teori bilangan dari Euclid sampai uji prima Fermat
import secrets

# Menetapkan bilangan prima kecil untuk pembagian percobaan sebelum uji Fermat
SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
                59, 61, 67, 71, 73, 79, 83, 89, 97]


# mencari FPB dengan Euclid Algorithm
def gcd(a: int, b: int, log: list | None = None) -> int:
    a, b = abs(a), abs(b)
    while b != 0:
        q, r = a // b, a % b
        if log is not None:
            log.append(f"{a} = {q}*{b} + {r}")
        a, b = b, r
    return a


# menghitung g, s, t dengan s*a + t*b = g (koefisien Bezout).
def extended_gcd(a: int, b: int, log: list | None = None) -> tuple[int, int, int]:
    # Error jika bilangan yang diterima negatif
    if a < 0 or b < 0:
        raise ValueError("extended_gcd hanya menerima bilangan tak negatif.")
    old_r, r = a, b      # Sisa pembagian
    old_s, s = 1, 0      # Koefisien untuk a
    old_t, t = 0, 1      # Koefisien untuk b
    if log is not None:
        log.append("Tabel Euclid diperluas  (q, r, s, t):")
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
        if log is not None:
            log.append(f"  q={q:<6} r={r:<8} s={s:<8} t={t}")
    if log is not None:
        log.append(f"Hasil: {old_s}*{a} + {old_t}*{b} = {old_r}")
    return old_r, old_s, old_t


# mencari invers a modulo m (gcd(a, m) = 1)
def mod_inverse(a: int, m: int, log: list | None = None) -> int:
    # Modulus kurang dari 2 untuk invers tidak terdefinisi/tidak ada, jadi error
    if m < 2:
        raise ValueError("Modulus harus bilangan bulat >= 2.")
    g, s, _ = extended_gcd(a % m, m, log)
    # Kalau FPB bukan 1, angka ini tidak punya pasangan invers
    if g != 1:
        raise ValueError(f"{a} tidak punya invers modulo {m} karena gcd = {g} (bukan 1).")
    return s % m


# menghitung base^exp mod mod dengan square-and-multiply, membaca bit eksponen dari kiri
def mod_pow(base: int, exp: int, mod: int, log: list | None = None) -> int:
    # Pangkat tidak boleh negatif dan pembagi minimal 1
    if mod < 1:
        raise ValueError("Modulus harus bilangan bulat positif.")
    if exp < 0:
        raise ValueError("Eksponen tidak boleh negatif.")
    result = 1 % mod
    base = base % mod
    # catat bentuk biner dari pangkat
    if log is not None:
        log.append(f"{base}^{exp} mod {mod},  eksponen biner = {bin(exp)[2:]}")
    for bit in bin(exp)[2:]:
        squared = (result * result) % mod          # Kuadratkan hasil sebelumnya
        result = squared
        # Bit 1 berarti hasilnya juga dikalikan dengan angka dasar
        if bit == "1":
            result = (squared * base) % mod        # Kalikan dengan base jika bitnya 1
        if log is not None:
            kali = f", kali {base} -> {result}" if bit == "1" else " (kali dilewati)"
            log.append(f"  bit {bit}: kuadrat -> {squared}{kali}")
    return result


# menguji prima dengan membagi dengan prima kecil, lalu menggunakan Fermat
def is_probable_prime(n: int, log: list | None = None) -> bool:
    # Angka di bawah 2 bukan prima
    if n < 2:
        return False
    for p in SMALL_PRIMES:                      # Periksa lebih dulu dengan pembagian oleh prima kecil
        # Kalau n sama dengan prima kecil, berarti n pasti prima
        if n == p:
            return True
        # Kalau n habis dibagi dengan prima kecil, berarti n bukan prima
        if n % p == 0:
            if log is not None:
                log.append(f"{n} habis dibagi {p} -> komposit")
            return False
    for a in (2, 3, 5, 7, 11):                  # Uji Fermat dengan beberapa basis
        # Kalau hasilnya tidak sama dengan 1, n pasti bukan prima
        if mod_pow(a, n - 1, n) != 1:
            if log is not None:
                log.append(f"{a}^{n - 1} mod {n} != 1 -> {n} komposit")
            return False
    if log is not None:
        log.append(f"{n} lolos uji Fermat (basis 2, 3, 5, 7, 11) -> kemungkinan prima")
    return True


# membuat bilangan prima acak dengan panjang dalam bit
def generate_prime(bits: int, top_two: bool = False) -> int:    #top_two=True untuk membuat dua bit teratas bernilai 1
    if bits < 8:
        raise ValueError("Panjang bit prima minimal 8.")
    while True:
        # Dua bit paling depan dibuat bernilai 1 agar panjang hasil kali p*q pas
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        # bit dibuat bernilai 1 agar angkanya ganjil
        if top_two:
            candidate |= 1 << (bits - 2)
        if is_probable_prime(candidate):
            return candidate


# menghitung phi(n) = (p-1)(q-1) untuk n = p*q.
def euler_phi_semiprime(p: int, q: int) -> int:
    # Error jika nilai p dan q sama
    if p == q:
        raise ValueError("p dan q harus berbeda.")
    # Nilai p dan q harus prima
    if not (is_probable_prime(p) and is_probable_prime(q)):
        raise ValueError("p dan q harus bilangan prima.")
    return (p - 1) * (q - 1)
