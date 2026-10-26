# uji otomatis (run pakai : python -m unittest -v); di sini boleh memakai pow dan math.gcd sebagai pembanding
import math
import os
import random
import unittest

import mathcore as mc
import rsa

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = rsa.make_key(43, 59, 13)


# contoh contoh
class TestLectureVectors(unittest.TestCase):

    def test_euclid_and_bezout(self):
        log = []
        self.assertEqual(mc.gcd(13, 2436, log), 1)
        self.assertIn("2436 = 187*13 + 5", log)
        g, s, t = mc.extended_gcd(13, 2436)
        self.assertEqual((g, s * 13 + t * 2436), (1, 1))
        g, s, t = mc.extended_gcd(252, 198)
        self.assertEqual((g, s * 252 + t * 198), (18, 18))

    def test_inverses(self):
        self.assertEqual(mc.mod_inverse(13, 2436), 937)
        self.assertEqual(mc.mod_inverse(3, 7), 5)
        self.assertEqual(mc.mod_inverse(101, 4620), 1601)

    def test_square_and_multiply(self):
        log = []
        self.assertEqual(mc.mod_pow(1819, 13, 2537, log), 2081)
        for value in ("2068", "1779", "2081"):
            self.assertIn(value, "\n".join(log))
        self.assertEqual(mc.mod_pow(7, 222, 11), 5)          # contoh Fermat 

    def test_phi(self):
        self.assertEqual(mc.euler_phi_semiprime(43, 59), 2436)

    def test_key_and_blocks(self):
        self.assertEqual((KEY.n, KEY.phi, KEY.d), (2537, 2436, 937))
        self.assertEqual(rsa.rosen_block_digits(2537), 4)

    def test_encrypt_stop_decrypt_help(self):
        blocks, width = rsa.rosen_encode("STOP", 2537)
        self.assertEqual((blocks, width), ([1819, 1415], 4))
        self.assertEqual(rsa.format_blocks(rsa.encrypt_blocks(blocks, 13, 2537), 4), "2081 2182")
        self.assertEqual(rsa.decrypt_blocks([981, 461], 937, 2537), [704, 1115])
        self.assertEqual(rsa.decrypt_text([981, 461], KEY), "HELP")

    def test_signature(self):
        blocks, _ = rsa.rosen_encode("MEET AT NOON", 2537)
        sig = rsa.sign_blocks(blocks, 937, 2537)
        self.assertEqual(rsa.format_blocks(sig, 4), "0817 0555 1310 2173 1026")
        self.assertEqual(rsa.verify_blocks(sig, 13, 2537), blocks)
        tampered = [818] + sig[1:]
        self.assertNotEqual(rsa.verify_blocks(tampered, 13, 2537), blocks)

    def test_parse_blocks(self):
        self.assertEqual(rsa.parse_blocks("0981, 0461\n0001"), [981, 461, 1])


# uji Fermat dibandingkan dengan saringan Eratosthenes
class TestPrimality(unittest.TestCase):

    def test_against_sieve(self):
        limit = 100000
        sieve = [True] * limit
        sieve[0] = sieve[1] = False
        for i in range(2, int(limit ** 0.5) + 1):
            if sieve[i]:
                for j in range(i * i, limit, i):
                    sieve[j] = False
        for n in range(limit):
            self.assertEqual(mc.is_probable_prime(n), sieve[n], f"n = {n}")

    def test_pseudoprimes_are_rejected(self):
        for n in (341, 561, 1105, 1729, 2465):
            self.assertFalse(mc.is_probable_prime(n), n)

    def test_known_primes(self):
        for p in (2 ** 127 - 1, 2 ** 61 - 1, 18446744073709551557):
            self.assertTrue(all(pow(a, p - 1, p) == 1 for a in (2, 3, 5, 7)))   # pembanding memakai pow bawaan Python
            self.assertTrue(mc.is_probable_prime(p), p)


# perbandingan acak dengan fungsi bawaan Python
class TestOracles(unittest.TestCase):

    def test_random_cases(self):
        for _ in range(300):
            m, b, e = random.randint(2, 10 ** 30), random.randint(0, 10 ** 30), random.randint(0, 10 ** 6)
            self.assertEqual(mc.mod_pow(b, e, m), pow(b, e, m))
            a, c = random.randint(0, 10 ** 18), random.randint(0, 10 ** 18)
            g, s, t = mc.extended_gcd(a, c)
            self.assertEqual(mc.gcd(a, c), math.gcd(a, c))
            self.assertEqual((g, s * a + t * c), (math.gcd(a, c), g))     # memeriksa identitas Bezout
            if math.gcd(b, m) == 1:
                self.assertEqual(mc.mod_inverse(b, m), pow(b, -1, m))


# kunci acak, round trip, dan input yang tidak valid
class TestRoundTripAndNegative(unittest.TestCase):

    def test_round_trip(self):
        for bits in (16, 32, 64, 128):
            key = rsa.generate_key(bits)
            self.assertEqual(key.n.bit_length(), bits)
            _, _, cipher = rsa.encrypt_text("Kriptografi RSA itu seru!", (key.n, key.e))
            result = rsa.decrypt_text(cipher, key)
            cleaned = rsa.rosen_clean_letters("Kriptografi RSA itu seru!")
            self.assertEqual(result[:len(cleaned)], cleaned)
            self.assertTrue(set(result[len(cleaned):]) <= {"X"})

    def test_negative(self):
        for bad in (lambda: rsa.make_key(15, 59, 13), lambda: rsa.make_key(43, 43, 13),
                    lambda: rsa.make_key(43, 59, 7), lambda: rsa.rosen_block_digits(25),
                    lambda: rsa.rosen_encode("", 2537), lambda: rsa.encrypt_blocks([2537], 13, 2537)):
            with self.assertRaises(ValueError):
                bad()

    def test_no_forbidden_imports(self):
        for name in ("mathcore.py", "rsa.py"):
            with open(os.path.join(ROOT, name), encoding="utf-8") as f:
                source = f.read()
            for word in ("import math", "hashlib", "tkinter"):
                self.assertNotIn(word, source, f"{name} memuat {word}")


if __name__ == "__main__":
    unittest.main()

# menguji menu CLI menggunakan input yang sudah ditentukan.
class TestCLI(unittest.TestCase):
    def run_cli(self, answers):
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch
        import cli
        output = StringIO()
        with patch("builtins.input", side_effect=answers), redirect_stdout(output):
            cli.run()
        return output.getvalue()

    def test_key_encrypt_decrypt_session(self):
        output = self.run_cli(["1", "a", "n", "2", "STOP", "n", "3", "0981 0461", "0"])
        self.assertIn("d = 937", output)
        self.assertIn("2081 2182", output)
        self.assertIn("HELP", output)

    def test_signature_and_forgery(self):
        output = self.run_cli(["1", "a", "n", "4", "a", "MEET AT NOON", "4", "c", "MEET AT NOON", "0"])
        self.assertIn("0817 0555 1310 2173 1026", output)
        self.assertIn("Tanda tangan cocok: tidak", output)

    def test_invalid_inputs_and_no_key(self):
        output = self.run_cli(["x", "3", "0"])
        self.assertIn("Pilihan menu tidak valid", output)
        self.assertIn("Buat kunci terlebih dahulu", output)
        self.assertNotIn("Traceback", output)

    def test_bad_key_values_return_to_menu(self):
        output = self.run_cli(["1", "b", "15", "59", "13", "1", "b", "43", "59", "7", "0"])
        self.assertIn("bukan bilangan prima", output)
        self.assertIn("tidak relatif prima", output)
        self.assertNotIn("Traceback", output)

    def test_eof_is_graceful(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch
        import cli
        output = StringIO()
        with patch("cli.ask", side_effect=EOFError), redirect_stdout(output):
            cli.run()
        output = output.getvalue()
        self.assertIn("Program dihentikan.", output)
        self.assertNotIn("Traceback", output)

    def test_demo_is_deterministic(self):
        from contextlib import redirect_stdout
        from io import StringIO
        import cli
        captures = []
        for _ in range(2):
            output = StringIO()
            with redirect_stdout(output):
                cli.run(["--demo"])
            captures.append(output.getvalue())
        self.assertEqual(captures[0], captures[1])
        for expected in ("2081 2182", "HELP", "0817 0555 1310 2173 1026", "d = 937"):
            self.assertIn(expected, captures[0])

    def test_forbidden_program_imports(self):
        for name in ("mathcore.py", "rsa.py", "cli.py", "main.py"):
            with open(os.path.join(ROOT, name), encoding="utf-8-sig") as source_file:
                source = source_file.read().lower()
            forbidden_lines = ("import tkinter", "import math\n", "import hashlib", "import threading", "import argparse")
            for word in forbidden_lines:
                self.assertNotIn(word, source, f"{name} memuat {word}")
