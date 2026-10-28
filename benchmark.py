"""Bandingkan waktu dekripsi RSA biasa dan CRT."""
import secrets
import time

import rsa

KEY_SIZES = [128, 256, 512, 1024]
N_BLOCKS = 20


def average_ms(decrypt, ciphertexts):
    start = time.perf_counter()
    plaintexts = decrypt(ciphertexts)
    elapsed = time.perf_counter() - start
    return elapsed * 1000 / len(ciphertexts), plaintexts


def run_bench():
    print(f"{'Ukuran':>9} | {'RSA biasa (ms)':>14} | {'RSA-CRT (ms)':>12} | {'Speedup':>7}")
    print("-" * 53)

    for bits in KEY_SIZES:
        key = rsa.generate_key(bits)
        messages = [secrets.randbelow(key.n) for _ in range(N_BLOCKS)]
        ciphertexts = rsa.encrypt_blocks(messages, key.e, key.n)

        time_biasa, plain_biasa = average_ms(
            lambda values: rsa.decrypt_blocks(values, key.d, key.n), ciphertexts
        )
        time_crt, plain_crt = average_ms(
            lambda values: rsa.decrypt_blocks_crt(values, key), ciphertexts
        )

        assert plain_biasa == plain_crt == messages
        print(
            f"{bits:>5} bit | {time_biasa:>14.4f} | {time_crt:>12.4f} | "
            f"{time_biasa / time_crt:>6.2f}x"
        )


if __name__ == "__main__":
    run_bench()
