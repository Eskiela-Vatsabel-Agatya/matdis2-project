# membandingkan metode efisien dengan pembanding sederhana secara terukur
import sys
import time
from collections.abc import Callable

import baseline
import mathcore as mc
import rsa

# menghitung median waktu satu pemanggilan
def _median(function: Callable[[], object], repeats: int = 5) -> float:
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        function()
        samples.append(time.perf_counter() - start)
    samples.sort()
    return samples[len(samples) // 2]

# memformat waktu dalam us, ms, atau s
def format_time(seconds: float | None) -> str:
    if seconds is None: return "dihentikan"
    if seconds < 0.001: return f"{seconds * 1_000_000:.1f} us"
    if seconds < 1: return f"{seconds * 1000:.2f} ms"
    return f"{seconds:.2f} s"

# menghitung rasio waktu kedua metode
def _ratio(ours: float, other: float | None) -> str:
    if other is None: return "dihentikan"
    ratio = other / ours if ours else 0
    if ratio >= 1: return f"{ratio:.2f}x lebih cepat"
    return f"{1 / ratio:.2f}x lebih lambat" if ratio else "tak terukur"

# memverifikasi hasil dan mengukur sepasang fungsi
def _row(size: int, ours: Callable[[], object], other: Callable[[], object], repeats: int = 5) -> tuple[int, float, float, str]:
    if ours() != other(): raise AssertionError("Hasil kedua metode tidak sama.")
    t1, t2 = _median(ours, repeats), _median(other, repeats)
    return size, t1, t2, _ratio(t1, t2)

# mencetak baris hasil dalam tabel ASCII
def _print_rows(title: str, rows: list[tuple[int, float, float | None, str]]) -> None:
    print(); print(title); print("ukuran | metode kami | pembanding | rasio")
    print("-------|-------------|------------|------")
    for size, ours, other, ratio in rows:
        print(f"{size} | {format_time(ours)} | {format_time(other)} | {ratio}")

# membandingkan square-and-multiply dengan perkalian berulang
def bench_mod_pow(fast: bool = False) -> list[tuple[int, float, float, str]]:
    rows = []
    for bits in ((8, 12, 16) if fast else (8, 12, 16, 20, 24)):
        exp, base, mod = (1 << (bits - 1)) + 37, 987654321, (1 << 127) - 1
        rows.append(_row(bits, lambda: mc.mod_pow(base, exp, mod),
                         lambda: baseline.naive_mod_pow(base, exp, mod), 25 if bits <= 12 else 5))
    return rows

# membandingkan Euclid diperluas dengan pencarian invers berulang
def bench_inverse(fast: bool = False) -> list[tuple[int, float, float | None, str]]:
    rows = []
    for bits in ((16, 20) if fast else (16, 20, 24)):
        mod = (1 << bits) - 1
        a = next(x for x in (7, 11, 13, 17, 19, 23, 29) if mc.gcd(x, mod) == 1)
        ours = mc.mod_inverse(a, mod)
        other = baseline.naive_inverse(a, mod, 2_000_000)
        if other is None:
            rows.append((bits, _median(lambda: mc.mod_inverse(a, mod)), None, "dihentikan"))
        else:
            rows.append(_row(bits, lambda: mc.mod_inverse(a, mod),
                             lambda: baseline.naive_inverse(a, mod, 2_000_000), 10))
    return rows

# membandingkan uji Fermat dengan trial division pada bilangan prima
def bench_primality(fast: bool = False) -> list[tuple[int, float, float, str]]:
    rows = []
    for bits, n in (((24, 16777213), (32, 4294967291)) if fast else ((24, 16777213), (32, 4294967291), (40, 1099511627689))):
        rows.append(_row(bits, lambda: mc.is_probable_prime(n),
                         lambda: baseline.naive_is_prime(n), 25 if bits == 24 else 5))
    return rows

# membandingkan dekripsi RSA biasa dengan dekripsi CRT
def bench_decryption(fast: bool = False) -> list[tuple[int, float, float, str]]:
    rows = []
    sizes = (128, 256, 512) if fast else (128, 256, 512, 1024)
    for bits in sizes:
        key = rsa.generate_key(bits); blocks = [42, 12345, key.n - 1]
        rows.append(_row(bits, lambda: rsa.decrypt_blocks_crt(blocks, key),
                         lambda: rsa.decrypt_blocks(blocks, key.d, key.n), 10))
    return rows

# membangkitkan kunci dengan e = 65537 untuk pengukuran
def _key_small_e(bits: int) -> rsa.RSAKey:
    key = rsa.generate_key(bits)
    while key.e != 65537: key = rsa.generate_key(bits)
    return key

# membandingkan enkripsi dengan e kecil dan e acak
def bench_public_exponent(fast: bool = False) -> list[tuple[int, float, float, str]]:
    rows = []; sizes = (128, 256, 512) if fast else (128, 256, 512, 1024)
    for bits in sizes:
        key = _key_small_e(bits); e2 = baseline.random_e(key.phi)
        while e2 == key.e: e2 = baseline.random_e(key.phi)
        d1, d2, m = mc.mod_inverse(key.e, key.phi), mc.mod_inverse(e2, key.phi), 42
        c1, c2 = mc.mod_pow(m, key.e, key.n), mc.mod_pow(m, e2, key.n)
        if mc.mod_pow(c1, d1, key.n) != m or mc.mod_pow(c2, d2, key.n) != m:
            raise AssertionError("Pemeriksaan enkripsi/dekripsi gagal.")
        t1 = _median(lambda: mc.mod_pow(m, key.e, key.n))
        t2 = _median(lambda: mc.mod_pow(m, e2, key.n))
        rows.append((bits, t1, t2, _ratio(t1, t2)))
    return rows

# menjalankan pilihan benchmark dan menampilkan lingkungan ukur
def run_bench(selection: str = "semua", fast: bool = False) -> None:
    jobs = {"1": ("Eksponensiasi modular", bench_mod_pow), "2": ("Pencarian invers d", bench_inverse),
            "3": ("Uji primalitas", bench_primality), "4": ("Dekripsi RSA", bench_decryption),
            "5": ("Eksponen publik", bench_public_exponent)}
    print(f"Python: {sys.version.split()[0]} | OS: {sys.platform}")
    print("Pengulangan median: pangkat 25x (<=12-bit) / 5x; invers 10x (5x saat baseline 24-bit dihentikan);")
    print("prima 25x (24-bit) / 5x; dekripsi 10x; eksponen publik 5x.")
    print("Hasil kedua metode diperiksa sebelum pencatatan waktu; kunci benchmark dibangkitkan acak.")
    print("Satu pemanggilan menghasilkan satu run. Ulangi --bench untuk membandingkan beberapa run.")
    print("Untuk e berbeda, kedua ciphertext diverifikasi dengan dekripsi sebelum pengukuran.")
    choices = list(jobs) if selection == "semua" else [selection]
    for choice in choices:
        if choice not in jobs: print("Pilihan benchmark tidak valid."); return
        title, function = jobs[choice]; _print_rows(title, function(fast=fast))
