# mengelola menu, input, output, dan demonstrasi RSA
from dataclasses import dataclass, field

import benchmark
import mathcore as mc
import rsa


# menyimpan kunci yang sedang aktif
@dataclass
class Session:
    key: rsa.RSAKey | None = None
    message_lengths: dict[tuple[int, int, tuple[int, ...]], set[int]] = field(default_factory=dict)


# membaca satu baris masukan dari user
def ask(prompt: str) -> str:
    return input(prompt)


# menampilkan beberapa baris output
def show(lines: list[str]) -> None:
    for line in lines:
        print(line)


# mengingat panjang pesan agar huruf pengisi X tidak dianggap sebagai isi teks
def message_length_for(session: Session, key: rsa.RSAKey, blocks: list[int]) -> int | None:
    lookup = (key.n, key.e, tuple(blocks))
    known_lengths = session.message_lengths.get(lookup, set())
    if len(known_lengths) == 1:
        known_length = next(iter(known_lengths))
        print(f"Panjang pesan asli dikenali: {known_length} huruf")
        return known_length
    if len(known_lengths) > 1:
        print("Ciphertext ini pernah dipakai untuk beberapa panjang pesan; pilih panjang yang benar dari keluaran enkripsi.")
    raw_length = ask("Panjang pesan asli dalam huruf (lihat keluaran enkripsi; kosong jika tidak tahu): ").strip()
    return int(raw_length) if raw_length else None


# menampilkan menu utama dan status kunci
def show_menu(session: Session) -> None:
    print("=" * 50)
    print("  PROGRAM RSA - MATEMATIKA DISKRIT 2")
    print("=" * 50)
    if session.key is None:
        print("Kunci aktif : belum ada")
    else:
        print(f"Kunci aktif : n = {session.key.n}, e = {session.key.e}")
    print("  1. Buat kunci RSA")
    print("  2. Enkripsi pesan")
    print("  3. Dekripsi pesan")
    print("  4. Tanda tangan digital")
    print("  5. Alat bantu: langkah-langkah algoritma")
    print("  6. Benchmark dekripsi RSA biasa vs CRT")
    print("  0. Keluar")


# menampilkan rincian pasangan kunci
def show_key(key: rsa.RSAKey) -> None:
    print(f"p = {key.p}; q = {key.q}; n = {key.n}; phi(n) = {key.phi}")
    print(f"e = {key.e}; d = {key.d}")
    print(f"Kunci publik (n, e) = ({key.n}, {key.e})")
    print(f"Kunci privat (n, d) = ({key.n}, {key.d})")
    print(f"dp = {key.dp}; dq = {key.dq}; q_inv = {key.q_inv}")


# membuat kunci dari contoh kuliah, masukan manual, atau bilangan acak
def create_key(session: Session) -> None:
    print("  a. Contoh kuliah (43, 59, 13)")
    print("  b. Masukkan p, q, e")
    print("  c. Buat kunci acak (16/32/64/128 bit)")
    choice = ask("Pilih cara: ").strip().lower()
    if choice == "a":
        key = rsa.make_key(43, 59, 13)
    elif choice == "b":
        p, q = int(ask("Masukkan p: ")), int(ask("Masukkan q: "))
        raw_e = ask("Masukkan e (kosong untuk memilih acak): ").strip()
        key = rsa.make_key(p, q, int(raw_e) if raw_e else None)
    elif choice == "c":
        bits = int(ask("Panjang kunci (16/32/64/128): "))
        if bits not in (16, 32, 64, 128):
            raise ValueError("Pilih panjang 16, 32, 64, atau 128 bit.")
        key = rsa.generate_key(bits)
    else:
        raise ValueError("Pilihan pembuatan kunci tidak dikenal.")
    session.key = key
    show_key(key)
    if ask("Tampilkan langkah mencari d? (y/n): ").strip().lower() == "y":
        if key.n < 10**9:
            trace: list[str] = []
            mc.mod_inverse(key.e, key.phi, trace)
            show(trace)
        else:
            print("Langkah tidak ditampilkan untuk kunci sebesar ini.")


# mengenkripsi teks dan menampilkan blok sebelum dan sesudah enkripsi
def encrypt(session: Session) -> None:
    if session.key is None:
        print("Buat kunci terlebih dahulu (menu 1).")
        return
    key = session.key
    text = ask("Masukkan pesan: ")
    clean = rsa.rosen_clean_letters(text)
    blocks, width, cipher = rsa.encrypt_text(text, (key.n, key.e))
    print(f"Huruf yang digunakan: {clean}")
    print(f"Rangkaian digit: {' '.join(f'{ord(c)-65:02d}' for c in clean)}")
    print(f"Lebar blok: {width} digit")
    print(f"Blok pesan: {rsa.format_blocks(blocks, width)}")
    print(f"Blok ciphertext: {rsa.format_blocks(cipher, len(str(key.n)))}")
    message_length = len(clean)
    session.message_lengths.setdefault((key.n, key.e, tuple(cipher)), set()).add(message_length)
    print(f"Panjang pesan asli: {message_length} huruf")
    dropped = rsa.rosen_dropped_chars(text)
    if dropped:
        print(f"Karakter yang diabaikan: {dropped}")
    if ask("Tampilkan langkah blok pertama? (y/n): ").strip().lower() == "y":
        trace: list[str] = []
        mc.mod_pow(blocks[0], key.e, key.n, trace)
        show(trace)


# mendekripsi blok angka dengan metode standar atau CRT
def decrypt(session: Session) -> None:
    if session.key is None:
        print("Buat kunci terlebih dahulu (menu 1).")
        return
    key = session.key
    blocks = rsa.parse_blocks(ask("Masukkan blok ciphertext: "))
    use_crt = ask("Gunakan CRT? (y/n): ").strip().lower() == "y"
    trace: list[str] = []
    if use_crt:
        plain = rsa.decrypt_blocks_crt(blocks, key, trace)
        show(trace)
    else:
        plain = rsa.decrypt_blocks(blocks, key.d, key.n)
    width = rsa.rosen_block_digits(key.n)
    message_length = message_length_for(session, key, blocks)
    print(f"Blok pesan: {rsa.format_blocks(plain, width)}")
    print(f"Pesan hasil dekripsi: {rsa.rosen_decode(plain, width, message_length)}")
    if message_length is None:
        print("Catatan: tanpa panjang asli, huruf X pengisi mungkin masih terlihat di akhir pesan.")


# menjalankan penandatanganan, verifikasi, / simulasi perubahan tanda tangan
def signature(session: Session) -> None:
    if session.key is None:
        print("Buat kunci terlebih dahulu (menu 1).")
        return
    key = session.key
    print("  a. Tanda tangani pesan")
    print("  b. Verifikasi tanda tangan")
    print("  c. Simulasi pemalsuan")
    choice = ask("Pilih cara: ").strip().lower()
    width = rsa.rosen_block_digits(key.n)
    if choice == "a":
        text = ask("Masukkan pesan: ")
        blocks, _ = rsa.rosen_encode(text, key.n)
        signed = rsa.sign_blocks(blocks, key.d, key.n)
        message_length = len(rsa.rosen_clean_letters(text))
        session.message_lengths.setdefault((key.n, key.e, tuple(signed)), set()).add(message_length)
        print(f"Blok pesan: {rsa.format_blocks(blocks, width)}")
        print(f"Tanda tangan: {rsa.format_blocks(signed, len(str(key.n)))}")
        print(f"Panjang pesan asli: {message_length} huruf")
    elif choice == "b":
        signed = rsa.parse_blocks(ask("Masukkan blok tanda tangan: "))
        recovered = rsa.verify_blocks(signed, key.e, key.n)
        message_length = message_length_for(session, key, signed)
        print(f"Pesan terverifikasi: {rsa.rosen_decode(recovered, width, message_length)}")
        if message_length is None:
            print("Catatan: tanpa panjang asli, huruf X pengisi mungkin masih terlihat di akhir pesan.")
    elif choice == "c":
        text = ask("Masukkan pesan: ")
        blocks, _ = rsa.rosen_encode(text, key.n)
        signed = rsa.sign_blocks(blocks, key.d, key.n)
        message_length = len(rsa.rosen_clean_letters(text))
        altered = signed[:]
        altered[0] = altered[0] + 1 if altered[0] % 10 != 9 else altered[0] - 1
        recovered = rsa.verify_blocks(altered, key.e, key.n)
        print(f"Tanda tangan asli: {rsa.format_blocks(signed, len(str(key.n)))}")
        print(f"Tanda tangan diubah: {rsa.format_blocks(altered, len(str(key.n)))}")
        try:
            result = rsa.rosen_decode(recovered, width, message_length)
        except ValueError:
            result = "hasil bukan pesan huruf yang valid"
        print(f"Hasil verifikasi: {result}")
        print("Tanda tangan cocok: tidak")
    else:
        raise ValueError("Pilihan tanda tangan tidak dikenal.")


# meminta bilangan dan menampilkan jejak algoritma teori bilangan
def tools_menu() -> None:
    print("  1. FPB (Euclid)")
    print("  2. Bezout dan invers modular")
    print("  3. Perpangkatan modular")
    print("  4. Uji prima Fermat")
    choice = ask("Pilih alat: ").strip()
    if choice == "1":
        a, b = int(ask("Masukkan a: ")), int(ask("Masukkan b: "))
        log: list[str] = []
        print(f"FPB = {mc.gcd(a, b, log)}")
        show(log)
    elif choice == "2":
        a, m = int(ask("Masukkan a: ")), int(ask("Masukkan modulus: "))
        log = []
        print(f"Invers = {mc.mod_inverse(a, m, log)}")
        show(log)
    elif choice == "3":
        a, e, m = int(ask("Masukkan basis: ")), int(ask("Masukkan eksponen: ")), int(ask("Masukkan modulus: "))
        log = []
        print(f"Hasil = {mc.mod_pow(a, e, m, log)}")
        show(log)
    elif choice == "4":
        n = int(ask("Masukkan bilangan: "))
        log = []
        print("Status: " + ("kemungkinan prima" if mc.is_probable_prime(n, log) else "komposit"))
        show(log)
    else:
        raise ValueError("Pilihan alat tidak dikenal.")


# menjalankan contoh deterministik untuk presentasi dan pemeriksaan
def demo() -> None:
    key = rsa.make_key(43, 59, 13)
    print("=== PEMBUATAN KUNCI ===")
    show_key(key)
    trace: list[str] = []
    mc.mod_inverse(key.e, key.phi, trace)
    show(trace)
    print("=== ENKRIPSI STOP ===")
    plain, width, cipher = rsa.encrypt_text("STOP", (key.n, key.e))
    print(f"Blok pesan: {rsa.format_blocks(plain, width)}")
    trace = []
    mc.mod_pow(plain[0], key.e, key.n, trace)
    show(trace)
    print(f"Ciphertext: {rsa.format_blocks(cipher, len(str(key.n)))}")
    print("=== DEKRIPSI HELP ===")
    print(f"0981 0461 -> {rsa.decrypt_text([981, 461], key)}")
    print("=== DEKRIPSI CRT ===")
    crt_trace: list[str] = []
    print(f"0981 0461 -> {rsa.decrypt_text([981, 461], key, crt_trace, use_crt=True)}")
    show(crt_trace)
    print("=== TANDA TANGAN ===")
    blocks, _ = rsa.rosen_encode("MEET AT NOON", key.n)
    signed = rsa.sign_blocks(blocks, key.d, key.n)
    print(f"Tanda tangan: {rsa.format_blocks(signed, len(str(key.n)))}")
    recovered = rsa.verify_blocks(signed, key.e, key.n)
    print(f"Verifikasi: {rsa.rosen_decode(recovered, width)}")
    altered = signed[:]
    altered[0] += 1
    print(f"Verifikasi tanda tangan diubah: {rsa.verify_blocks(altered, key.e, key.n) != blocks}")


# menjalankan benchmark dekripsi RSA biasa dan CRT
def benchmark_menu() -> None:
    benchmark.run_bench()


# memilih mode demo / menjalankan menu interaktif
def run(args: list[str] | None = None) -> None:
    args = args or []
    if args == ["--demo"]:
        demo()
        return
    if args == ["--bench"]:
        benchmark.run_bench()
        return
    if args:
        print("Argumen tidak dikenal. Gunakan --demo atau --bench.")
        return
    session = Session()
    try:
        while True:
            show_menu(session)
            choice = ask("Pilih menu: ").strip()
            try:
                if choice == "0":
                    print("Program selesai.")
                    return
                actions = {"1": lambda: create_key(session), "2": lambda: encrypt(session),
                           "3": lambda: decrypt(session), "4": lambda: signature(session),
                           "5": tools_menu, "6": benchmark_menu}
                if choice not in actions:
                    print("Pilihan menu tidak valid.")
                else:
                    actions[choice]()
            except ValueError as error:
                print(f"Kesalahan: {error}")
    except (EOFError, KeyboardInterrupt):
        print("Program dihentikan.")
