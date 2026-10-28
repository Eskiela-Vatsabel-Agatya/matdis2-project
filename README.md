# Menjalankan proyek RSA Matdis 2 melalui CLI.
Persyaratan: Python 3.10 atau lebih baru.

- `python main.py` membuka menu interaktif.
- `python main.py --demo` menjalankan contoh deterministik.
- `python benchmark.py` atau pilih menu `6` membandingkan dekripsi RSA biasa dan CRT.

Benchmark mengukur satu putaran atas 20 blok untuk kunci 128, 256, 512, dan 1024 bit. Kedua metode harus menghasilkan plaintext yang sama. Waktu yang ditampilkan adalah rata-rata per blok untuk putaran tersebut.

Proyek ini memakai RSA textbook untuk pembelajaran, tanpa OAEP/PSS dan bukan untuk melindungi data nyata. Enkripsi mencantumkan jumlah huruf asli; ketika ciphertext ditempel ke sesi lain, masukkan panjang tersebut saat diminta agar padding `X` dibuang tanpa menghapus `X` yang memang bagian pesan.
