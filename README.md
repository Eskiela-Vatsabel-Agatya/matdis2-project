# Menjalankan proyek RSA Matdis 2 melalui CLI.
Persyaratan: Python 3.10 atau lebih baru.
Gunakan `python main.py` untuk menu atau `python main.py --demo` untuk contoh deterministik.
Pilih menu `6` untuk membuka benchmark, atau jalankan `python main.py --bench` untuk semua lima perbandingan.
Gunakan `python main.py --bench-cepat` untuk ringkasan yang melewati ukuran terbesar. Benchmark menampilkan hasil di terminal dan membandingkan algoritma proyek dengan baseline sederhana; tiap pemanggilan adalah satu run. Untuk mereplikasi tabel makalah, jalankan `--bench` tiga kali pada mesin yang sama dan catat setiap keluaran.
Benchmark mengukur square-and-multiply, invers Euclid, uji prima, dekripsi standar dibanding CRT, serta eksponen publik kecil dibanding eksponen acak. Pengukuran ini untuk demonstrasi kelas, bukan evaluasi keamanan atau klaim bahwa kode Python mengungguli pustaka kriptografi produksi.
Enkripsi menampilkan jumlah huruf asli. Jika ciphertext didekripsi dalam sesi yang sama, panjangnya dikenali otomatis. Jika ciphertext ditempel dari sesi lain, masukkan jumlah huruf asli saat diminta agar huruf `X` pengisi dibuang tanpa menghapus `X` yang memang bagian dari pesan.
