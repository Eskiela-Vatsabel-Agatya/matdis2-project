# pembanding sederhana ini hanya dipanggil oleh fitur benchmark, bukan operasi RSA utama
import secrets

from mathcore import gcd


# menghitung pangkat modular dengan perkalian berulang
def naive_mod_pow(base: int, exp: int, mod: int) -> int:
    if exp < 0 or mod < 1:
        raise ValueError("Eksponen harus nonnegatif dan modulus harus positif.")
    result = 1 % mod
    for _ in range(exp):
        result = (result * base) % mod
    return result


# mencari invers modular dengan mencoba setiap kandidat
def naive_inverse(a: int, m: int, limit: int | None = None) -> int | None:
    if m < 2:
        return None
    stop = m if limit is None else min(m, limit)
    for d in range(1, stop + 1):
        if (a * d) % m == 1:
            return d
    return None


# menguji prima dengan pembagian sampai akar kuadrat
def naive_is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    divisor = 3
    while divisor * divisor <= n:
        if n % divisor == 0:
            return False
        divisor += 2
    return True


# memilih e dengan cara acak lama untuk pembanding
def random_e(phi: int) -> int:
    if phi <= 3:
        raise ValueError("phi(n) terlalu kecil untuk memilih e.")
    while True:
        e = 3 + secrets.randbelow(phi - 3)
        if gcd(e, phi) == 1:
            return e
