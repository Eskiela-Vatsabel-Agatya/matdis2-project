# Menyediakan algoritma teori bilangan dari Euclid sampai uji prima Fermat.
import secrets

# Menetapkan bilangan prima kecil untuk pembagian percobaan sebelum uji Fermat.
SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
                59, 61, 67, 71, 73, 79, 83, 89, 97]


# Mencari FPB dengan algoritma Euclid.
def gcd(a: int, b: int, log: list | None = None) -> int:
    a, b = abs(a), abs(b)
    while b != 0:
        q, r = a // b, a % b
        if log is not None:
            log.append(f"{a} = {q}*{b} + {r}")
        a, b = b, r
    return a


# Menerapkan Euclid diperluas untuk menghasilkan identitas Bezout s*a + t*b = g.
def extended_gcd(a: int, b: int, log: list | None = None) -> tuple[int, int, int]:
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


# Mencari invers a modulo m; inversnya hanya ada jika gcd(a, m) = 1.
def mod_inverse(a: int, m: int, log: list | None = None) -> int:
    if m < 2:
        raise ValueError("Modulus harus bilangan bulat >= 2.")
    g, s, _ = extended_gcd(a % m, m, log)
    if g != 1:
        raise ValueError(f"{a} tidak punya invers modulo {m} karena gcd = {g} (bukan 1).")
    return s % m


# Menghitung base^exp mod mod dengan square-and-multiply, membaca bit eksponen dari kiri.
def mod_pow(base: int, exp: int, mod: int, log: list | None = None) -> int:
    if mod < 1:
        raise ValueError("Modulus harus bilangan bulat positif.")
    if exp < 0:
        raise ValueError("Eksponen tidak boleh negatif.")
    result = 1 % mod
    base = base % mod
    if log is not None:
        log.append(f"{base}^{exp} mod {mod},  eksponen biner = {bin(exp)[2:]}")
    for bit in bin(exp)[2:]:
        squared = (result * result) % mod          # Kuadratkan hasil sebelumnya
        result = squared
        if bit == "1":
            result = (squared * base) % mod        # Kalikan dengan base jika bitnya 1
        if log is not None:
            kali = f", kali {base} -> {result}" if bit == "1" else " (kali dilewati)"
            log.append(f"  bit {bit}: kuadrat -> {squared}{kali}")
    return result


# Menguji prima dengan Fermat; bilangan Carmichael seperti 3828001 dapat lolos.
def is_probable_prime(n: int, log: list | None = None) -> bool:
    if n < 2:
        return False
    for p in SMALL_PRIMES:                      # Periksa lebih dulu dengan pembagian oleh prima kecil
        if n == p:
            return True
        if n % p == 0:
            if log is not None:
                log.append(f"{n} habis dibagi {p} -> komposit")
            return False
    for a in (2, 3, 5, 7, 11):                  # Uji Fermat dengan beberapa basis
        if mod_pow(a, n - 1, n) != 1:
            if log is not None:
                log.append(f"{a}^{n - 1} mod {n} != 1 -> {n} komposit")
            return False
    if log is not None:
        log.append(f"{n} lolos uji Fermat (basis 2, 3, 5, 7, 11) -> kemungkinan prima")
    return True


# Membangkitkan prima acak sepanjang bits bit; top_two=True membuat dua bit teratas bernilai 1.
def generate_prime(bits: int, top_two: bool = False) -> int:
    if bits < 8:
        raise ValueError("Panjang bit prima minimal 8.")
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if top_two:
            candidate |= 1 << (bits - 2)
        if is_probable_prime(candidate):
            return candidate


# Menghitung phi(n) = (p-1)(q-1) untuk n = p*q.
def euler_phi_semiprime(p: int, q: int) -> int:
    if p == q:
        raise ValueError("p dan q harus berbeda.")
    if not (is_probable_prime(p) and is_probable_prime(q)):
        raise ValueError("p dan q harus bilangan prima.")
    return (p - 1) * (q - 1)
