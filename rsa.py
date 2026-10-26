# Menjelaskan bahwa RSA buku teks ini tanpa padding dan hanya untuk pembelajaran.
import secrets
from dataclasses import dataclass

from mathcore import gcd, mod_inverse, mod_pow, is_probable_prime, generate_prime, euler_phi_semiprime


# Menyimpan satu pasang kunci RSA: n = p*q, phi = (p-1)(q-1), e publik, dan d privat.
@dataclass
class RSAKey:
    p: int
    q: int
    n: int
    phi: int
    e: int
    d: int


# Menyiapkan fungsi pembuatan kunci.

# Memilih e acak yang relatif prima dengan phi.
def _choose_e(phi: int) -> int:
    if phi <= 3:
        raise ValueError("phi(n) terlalu kecil untuk memilih e.")
    while True:
        e = 3 + secrets.randbelow(phi - 3)
        if gcd(e, phi) == 1:
            return e


# Membuat kunci dari dua prima p dan q; e dipilih acak jika tidak diberikan.
def make_key(p: int, q: int, e: int | None = None) -> RSAKey:
    if not is_probable_prime(p):
        raise ValueError(f"p = {p} bukan bilangan prima.")
    if not is_probable_prime(q):
        raise ValueError(f"q = {q} bukan bilangan prima.")
    phi = euler_phi_semiprime(p, q)
    if e is None:
        e = _choose_e(phi)
    if not 1 < e < phi:
        raise ValueError(f"e harus memenuhi 1 < e < phi(n) = {phi}.")
    if gcd(e, phi) != 1:
        raise ValueError(f"e = {e} tidak relatif prima dengan phi(n) = {phi}.")
    return RSAKey(p=p, q=q, n=p * q, phi=phi, e=e, d=mod_inverse(e, phi))


# Membuat kunci acak dengan modulus n sepanjang bits bit (minimal 16).
def generate_key(bits: int) -> RSAKey:
    if bits < 16:
        raise ValueError("Panjang kunci minimal 16 bit.")
    half = bits // 2
    while True:
        p = generate_prime(half, top_two=True)
        q = generate_prime(bits - half, top_two=True)
        if p != q and (p * q).bit_length() == bits:
            return make_key(p, q)


# Menyiapkan fungsi enkoding Rosen.

# Menentukan lebar blok (2N digit) agar 2525...25 tetap lebih kecil dari n.
def rosen_block_digits(n: int) -> int:
    if n <= 25:
        raise ValueError("Mode Rosen memerlukan n > 25.")
    pairs = 1
    while int("25" * (pairs + 1)) < n:
        pairs += 1
    return 2 * pairs


# Mengambil huruf A-Z saja dan mengubahnya menjadi huruf besar.
def rosen_clean_letters(text: str) -> str:
    return "".join(ch.upper() for ch in text if ch.isascii() and ch.isalpha())


# Mengembalikan karakter selain huruf dan spasi agar CLI dapat memberi peringatan.
def rosen_dropped_chars(text: str) -> str:
    return "".join(ch for ch in text if not (ch.isascii() and ch.isalpha()) and not ch.isspace())


# Mengubah teks menjadi blok angka (A=00 sampai Z=25); blok terakhir diisi X jika kurang.
def rosen_encode(text: str, n: int) -> tuple[list[int], int]:
    width = rosen_block_digits(n)
    letters = rosen_clean_letters(text)
    if not letters:
        raise ValueError("Tidak ada huruf A-Z pada teks.")
    digits = "".join(f"{ord(ch) - ord('A'):02d}" for ch in letters)
    while len(digits) % width != 0:
        digits += "23"                       # Isi dengan huruf X (23) sampai panjangnya sesuai
    return [int(digits[i:i + width]) for i in range(0, len(digits), width)], width


# Kebalikan rosen_encode: blok angka dikembalikan menjadi huruf.
def rosen_decode(blocks: list[int], width: int) -> str:
    digits = ""
    for block in blocks:
        if block < 0 or block >= 10 ** width:
            raise ValueError(f"Blok {block} tidak muat dalam {width} digit.")
        digits += f"{block:0{width}d}"
    letters = ""
    for i in range(0, len(digits), 2):
        value = int(digits[i:i + 2])
        if value > 25:
            raise ValueError("Hasil bukan pesan huruf yang valid (kunci salah atau data rusak).")
        letters += chr(ord("A") + value)
    return letters


# Menyiapkan fungsi enkripsi dan dekripsi.

# Memastikan setiap blok berada di antara 0 dan n-1.
def _check_range(blocks: list[int], n: int) -> None:
    for block in blocks:
        if block < 0 or block >= n:
            raise ValueError(f"Blok {block} harus berada pada 0 <= blok < n = {n}.")


# Mengenkripsi tiap blok dengan C = M^e mod n.
def encrypt_blocks(blocks: list[int], e: int, n: int, log: list | None = None) -> list[int]:
    _check_range(blocks, n)
    return [mod_pow(m, e, n, log) for m in blocks]


# Mendekripsi tiap blok dengan M = C^d mod n.
def decrypt_blocks(blocks: list[int], d: int, n: int, log: list | None = None) -> list[int]:
    _check_range(blocks, n)
    return [mod_pow(c, d, n, log) for c in blocks]


# Tanda tangan versi kuliah: S = x^d mod n dengan kunci privat (tanpa hash).
def sign_blocks(blocks: list[int], d: int, n: int) -> list[int]:
    return decrypt_blocks(blocks, d, n)


# Verifikasi tanda tangan: x = S^e mod n dengan kunci publik.
def verify_blocks(blocks: list[int], e: int, n: int) -> list[int]:
    return encrypt_blocks(blocks, e, n)


# Mengenkripsi teks dengan kunci publik (n, e); hasilnya blok plaintext, lebar blok, dan blok ciphertext.
def encrypt_text(text: str, pub: tuple[int, int],
                 log: list | None = None) -> tuple[list[int], int, list[int]]:
    n, e = pub
    plain, width = rosen_encode(text, n)
    return plain, width, encrypt_blocks(plain, e, n, log)


# Mendekripsi blok ciphertext lalu mengubahnya kembali menjadi teks.
def decrypt_text(blocks: list[int], key: RSAKey, log: list | None = None) -> str:
    plain = decrypt_blocks(blocks, key.d, key.n, log)
    return rosen_decode(plain, rosen_block_digits(key.n))


# Menyiapkan fungsi pemformatan blok.

# Menampilkan blok dengan nol di depan, misalnya 0981 0461.
def format_blocks(blocks: list[int], width: int) -> str:
    return " ".join(f"{b:0{width}d}" for b in blocks)


# Membaca teks berisi angka (dipisah spasi atau koma) menjadi daftar bilangan bulat.
def parse_blocks(text: str) -> list[int]:
    pieces = text.replace(",", " ").replace(";", " ").split()
    if not pieces:
        raise ValueError("Tidak ada blok bilangan yang dimasukkan.")
    for piece in pieces:
        if not piece.isdigit():
            raise ValueError(f"'{piece}' bukan bilangan bulat tak negatif.")
    return [int(piece) for piece in pieces]
