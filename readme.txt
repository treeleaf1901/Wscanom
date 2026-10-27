=== WScanom ===
Contributors: treeleaf1901
Tags: security, malware, scanner, backdoor, webshell
Requires at least: 5.8
Tested up to: 6.6
Requires PHP: 7.4
Stable tag: 1.6.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Pemindai pola webshell/backdoor pada file .php di wp-content, plus proteksi aktif: brute-force login, CAPTCHA, 2FA, pengerasan XML-RPC/privasi, log aktivitas, pemeriksaan kesehatan server, dan aksi darurat. 100% gratis, tanpa versi pro — selamanya.

**Distribusi:** plugin ini dibagikan lewat GitHub (bukan direktori resmi WordPress.org), persis sesuai berkas ini — unduh, install lewat upload zip, dan semua fiturnya langsung aktif tanpa lisensi atau akun apa pun.

== Description ==

WScanom memindai semua file `.php` di dalam `wp-content` (tema, plugin, mu-plugins, uploads) untuk mencari pola yang umum dipakai webshell dan backdoor WordPress: eksekusi kode tersembunyi (eval atas data ter-encode), eksekusi perintah sistem dari input pengunjung, pembuatan akun administrator secara terprogram, cron job tersembunyi, dropper yang mengunduh payload dari luar, serta cloaking/redirect untuk pembajakan traffic.

**Proteksi otomatis (aktif sejak plugin diaktifkan, tanpa konfigurasi apa pun):**

* Theme/Plugin Editor bawaan WordPress dimatikan otomatis — mencegah total jalur paling umum kalau akun admin bobol lewat password lemah/bruteforce: penyerang tidak akan pernah bisa menyimpan kode lewat editor itu.
* Eksekusi PHP dilarang di folder `uploads` lewat `.htaccess` otomatis — file masih bisa tertulis ke sana lewat jalur apa pun, tapi tidak akan pernah bisa dijalankan selama berada di folder itu.
* Plugin dan tema dipindai **seketika** setelah diinstall, diaktifkan, atau diupdate (bukan menunggu jadwal scan berikutnya) — menangkap plugin "nulled"/bajakan yang sudah bawa backdoor sejak awal, di titik paling dini yang bisa dijangkau dari level plugin.
* Auto-karantina untuk temuan yang sangat meyakinkan (satu pola berbobot tinggi, bukan sekadar gabungan beberapa pola ringan) — tertindak otomatis tanpa menunggu siapa pun membuka dashboard, tetap tercatat dan bisa dipulihkan.
* Pembatas percobaan login (brute-force): login yang gagal berulang kali dikunci sementara, dilacak baik per-IP maupun per-username lintas IP (menangkap brute-force terdistribusi dari banyak alamat sekaligus).
* CAPTCHA aritmatika sederhana di form login — tanpa layanan pihak ketiga, tanpa kunci API, tanpa mengirim data apa pun keluar dari situsmu.
* Verifikasi dua langkah (2FA) berbasis TOTP, kompatibel dengan Google Authenticator/Authy/Microsoft Authenticator — opsional, diaktifkan sendiri oleh tiap user lewat halaman profilnya, lengkap dengan 8 kode cadangan sekali pakai.
* Metode pingback XML-RPC (celah DDoS amplifikasi/brute-force klasik) dimatikan otomatis, tanpa mematikan XML-RPC itu sendiri (supaya integrasi sah seperti Jetpack atau aplikasi mobile WordPress tetap jalan).
* Versi WordPress disembunyikan, penebakan username lewat `?author=1` dan REST API `/wp/v2/users` diblokir, akses langsung ke `readme.html`/`license.txt`/`wp-config-sample.php` ditolak, dan header HTTP protektif standar (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`) dikirim di setiap permintaan.
* Cookie login dipaksa "Secure" otomatis — **tapi hanya kalau situs memang sudah HTTPS** (dicek otomatis setiap saat), supaya tidak pernah mengunci semua orang keluar dari situs yang belum HTTPS.
* Log aktivitas ringan: login gagal, login berhasil, perubahan pengaturan, dan aksi darurat semuanya tercatat dengan waktu dan keterangan, langsung terlihat di halaman admin.

**Pengerasan lanjutan (manual, admin yang aktifkan sendiri):**

* Fitur yang berisiko mematahkan fungsi situs kalau diaktifkan sembarangan — matikan XML-RPC total, paksa redirect semua trafik ke HTTPS, matikan feed RSS/Atom — semuanya **default MATI** dan tidak pernah otomatis. Tiap opsi menampilkan status "deteksi dini" situsmu saat ini (misalnya terdeteksi plugin yang butuh XML-RPC seperti Jetpack, atau status HTTPS situs) tepat sebelum kamu menekan tombol aktifkan, supaya keputusannya berdasarkan kondisi situsmu sendiri, bukan tebakan.

**Aksi darurat (sekali klik, untuk dipakai setelah situs dicurigai disusupi):**

* **Paksa Reset Password Semua User** — semua akun wajib ganti password di login berikutnya, dan semua sesi login aktif langsung diputus seketika.
* **Keluarkan Semua User dari Sesi Login** — memutus semua sesi aktif tanpa memaksa reset password, untuk bersih-bersih cepat.

**Pemeriksaan kesehatan server (baca-saja):**

* Laporan status versi PHP, HTTPS, mode debug, listing folder, dan update keamanan otomatis — WScanom tidak bisa mengubah konfigurasi server (itu butuh akses hosting), jadi panel ini murni melaporkan dan menyarankan.

**Pemindaian:**

* Scan bertahap lewat AJAX (batch kecil per permintaan) sehingga tidak membebani server dan tidak timeout di situs dengan banyak file.
* Karantina satu klik: file yang dicurigai dipindah (bukan dihapus permanen) ke folder terkunci dan ekstensinya diganti supaya tidak bisa dieksekusi, dengan opsi pulihkan kapan saja kalau ternyata salah tuduh.
* Pembersihan file sentinel root (`index.php`, `wp-config.php`, dll): file-file ini tidak bisa dikarantina karena situs butuh untuk jalan, jadi hanya blok kode yang cocok pola backdoor "self-replicating" yang dibuang in-place, dengan backup isi lengkap sebelum dibersihkan.
* Whitelist per file: tandai hasil yang kamu yakin aman, dan whitelist otomatis batal kalau isi file itu berubah di kemudian hari (dihitung dari hash SHA-256 isinya, bukan sekadar nama file).
* Scan terjadwal harian lewat WP-Cron, dengan notifikasi email ke admin saat ditemukan file berskor tinggi. Kalau situsnya besar dan satu kali jalan tidak cukup sebelum batas waktu eksekusi PHP, proses otomatis menyambung dirinya sendiri lewat event terpisah sampai selesai (atau menyerah dengan jelas kalau situsnya benar-benar luar biasa besar) — hasilnya tidak pernah hilang diam-diam.
* Ringkasan scan terjadwal terakhir ditampilkan langsung di halaman admin, tidak hanya lewat email.
* Dukungan multisite: halaman ringkasan di Network Admin, dengan tautan ke scanner tiap situs (uploads tiap situs ikut terpindai secara terpisah).
* Tidak mengirim data ke server pihak ketiga mana pun. Seluruh pemindaian berjalan di server kamu sendiri.

**Penting untuk dipahami:** WScanom adalah pemindai berbasis pola (heuristik), bukan database signature besar yang di-update berkala seperti Wordfence atau Sucuri. Ia bisa salah tuduh (false positive) pada plugin yang memang memakai teknik mirip obfuscation untuk tujuan sah (misalnya sebagian plugin caching/minifier), dan bisa kelewatan (false negative) untuk teknik backdoor baru yang belum dikenali. Gunakan sebagai lapisan pemeriksaan tambahan, bukan satu-satunya alat keamanan situsmu.

= Sumber kode =

Kode sumber plugin ini juga tersedia di GitHub: https://github.com/treeleaf1901/Wscanom

== Installation ==

1. Unggah folder `wscanom` ke direktori `/wp-content/plugins/`, atau unggah file zip-nya lewat **Plugins → Add New → Upload Plugin**.
2. Aktifkan plugin lewat menu **Plugins** di WordPress.
3. Buka **Tools → WScanom**, lalu klik **Jalankan Scan Sekarang**.

== Frequently Asked Questions ==

= Apakah plugin ini menghapus file berbahaya secara otomatis? =

Tidak ada yang dihapus permanen secara otomatis. WScanom melaporkan file yang mencurigakan beserta alasannya, dan kamu yang memutuskan tindak lanjutnya lewat tombol **Karantina** (memindahkan file keluar dari lokasi aslinya, masih bisa dipulihkan) atau **Bersihkan Blok Tersuntik** (khusus file sentinel root, hanya membuang blok yang cocok pola, dengan backup penuh sebelum dibersihkan). Ini sengaja tidak otomatis, supaya file yang salah tuduh (false positive) tidak ikut rusak tanpa sepengetahuanmu.

= Apa bedanya "Karantina" dan "Bersihkan Blok Tersuntik"? =

Karantina memindahkan seluruh file (misalnya webshell berdiri sendiri di folder uploads) keluar dari lokasi aslinya. Ini tidak bisa dipakai untuk file seperti `wp-config.php` atau `index.php` di root WordPress, karena situs butuh file itu untuk tetap berjalan. Untuk file-file sentinel itu, WScanom hanya membuang bagian kode yang cocok pola blok tersuntik (format penanda "XXX-CORE-START/END" yang umum dipakai backdoor self-replicating), lalu menyimpan salinan isi lengkap SEBELUM dibersihkan ke tabel karantina sebagai backup yang bisa dipulihkan.

= Kenapa ada hasil yang menurutku salah tuduh? =

Klik **Tandai Aman** pada baris itu. File tersebut tidak akan muncul lagi di scan berikutnya selama isinya tidak berubah. Kalau isinya berubah (misalnya file itu ditimpa backdoor di kemudian hari), tanda aman akan batal otomatis dan file itu akan terdeteksi lagi.

= Apakah scan ini memperlambat situsku? =

Scan manual lewat tombol di dashboard berjalan bertahap (batch kecil per permintaan AJAX), jadi tidak membebani server dalam satu permintaan besar. Scan terjadwal harian berjalan di background lewat WP-Cron.

= Apakah plugin ini mengirim data situsku ke server luar? =

Tidak. Semua pemindaian dan penyimpanan hasil terjadi di server situsmu sendiri (database WordPress-mu). Satu-satunya komunikasi keluar adalah email notifikasi ke alamat admin situsmu sendiri, yang bisa dimatikan.

= Apakah proteksi otomatis (matikan editor, larang eksekusi uploads, auto-karantina) bisa mematahkan situsku? =

Theme/Plugin Editor yang dimatikan tidak memengaruhi situs berjalan sama sekali (cuma satu halaman di dashboard yang hilang dari menu); matikan lewat panel **Pengaturan Proteksi** kalau kamu memang rutin memakainya. Larangan eksekusi PHP di `uploads` tidak memengaruhi gambar/dokumen yang memang seharusnya ada di sana — cuma menolak file `.php` yang seharusnya memang tidak ada di situ. Auto-karantina sengaja dibuat sangat konservatif (hanya memicu untuk pola yang nyaris pasti bukan false positive) dan semua tindakannya tetap tercatat serta bisa dipulihkan lewat tabel karantina — tidak ada yang dihapus permanen.

= Apakah proteksi ini mencegah SEMUA cara backdoor masuk? =

Tidak, dan tidak ada plugin keamanan mana pun yang bisa mengklaim itu jujur. Plugin WordPress tidak bisa mencegat penulisan file dari jalur di luar WordPress sama sekali (kredensial FTP/hosting bocor, misalnya) atau dari dalam kode plugin lain yang rentan/berbahaya. Yang WScanom lakukan adalah mempersempit dan memperlambat: eksekusi PHP di folder yang semestinya cuma berisi media diblokir apa pun jalurnya, dan file yang berhasil tertulis di tempat lain tetap dipindai secepat mungkin (seketika untuk plugin/tema yang berubah, berkala untuk sisanya) lalu ditindak otomatis kalau pola-nya sangat meyakinkan.

= Apakah pembatas login bisa mengunci saya sendiri dari situs saya? =

Secara default tidak mudah: batasnya longgar (5 kali percobaan gagal, kunci 20 menit), cukup untuk menampung salah ketik password wajar. Kalau memang terlanjur terkunci, kuncinya otomatis hilang sendiri setelah jangka waktu yang ditentukan — tidak ada penguncian permanen. Ambang dan lama kuncian bisa disesuaikan di panel **Pengaturan Proteksi**.

= Apakah fitur "Paksa Reset Password" atau "Keluarkan Semua User" aman dipakai? =

Keduanya memang dirancang untuk situasi darurat (situs dicurigai disusupi) dan efeknya langsung terasa oleh semua user, termasuk kamu sendiri — makanya tombolnya selalu minta konfirmasi dulu di browser sebelum benar-benar jalan. "Paksa Reset Password" tidak menghapus akun siapa pun; user tetap bisa masuk lagi lewat alur resmi "Lupa password?" WordPress.

= Kenapa fitur "Matikan XML-RPC total", "Paksa HTTPS", dan "Matikan Feed" tidak otomatis aktif? =

Karena ketiganya BISA mematahkan fungsi situs tertentu kalau diaktifkan tanpa situsnya siap (contoh: mematikan XML-RPC total bisa memutus Jetpack; memaksa HTTPS di situs yang sertifikatnya belum valid bisa membuat situs tidak bisa diakses sama sekali). Sesuai prinsip WScanom, fitur yang berisiko seperti ini harus dikustomisasi dan diaktifkan sendiri oleh admin — tidak pernah ditebak otomatis oleh plugin. Panel **Pengerasan Lanjutan** menampilkan status situsmu saat ini (deteksi dini) sebelum kamu menekan tombol aktifkan.

= Apakah WScanom bisa memasang sertifikat SSL/HTTPS untuk saya? =

Tidak bisa — itu di luar jangkauan plugin WordPress mana pun, karena butuh akses di level server/hosting. WScanom hanya bisa mendeteksi status HTTPS situsmu saat ini dan mengarahkanmu ke hosting (panel **Pemeriksaan Kesehatan Server** menampilkan status ini).

= Bagaimana cara mengaktifkan 2FA? =

Buka halaman profilmu sendiri (**Users → Profile**, atau klik nama akunmu di pojok kanan atas dashboard), gulir ke bagian **WScanom — Verifikasi Dua Langkah**, lalu klik **Aktifkan Verifikasi Dua Langkah**. Pindai kunci yang muncul dengan aplikasi authenticator (atau masukkan manual), lalu ketik kode 6 digit yang muncul di aplikasi untuk mengonfirmasi. 2FA baru benar-benar menyala setelah kode itu terbukti cocok — kamu tidak mungkin terkunci dari akunmu sendiri karena salah pasang.

= Saya kehilangan ponsel dan kode cadangan saya juga hilang. Bagaimana cara masuk lagi? =

Minta admin lain (yang punya kapabilitas `manage_options`) membuka profilmu dan menekan **Matikan Paksa 2FA User Ini** sebagai pemulihan darurat. Kalau kamu satu-satunya admin dan benar-benar terkunci total, hubungi developer situsmu untuk menghapus baris `wscanom_2fa_enabled` dan `wscanom_2fa_secret` di tabel `wp_usermeta` lewat phpMyAdmin/database situsmu.

= Apakah CAPTCHA di form login memperlambat atau mempersulit login? =

Tidak signifikan — cuma soal penjumlahan dua angka kecil (1-10). Soalnya tidak pernah disimpan di database (ditandatangani secara kriptografis dan kedaluwarsa otomatis dalam 10 menit), jadi tidak menambah beban server sama sekali.

== Changelog ==

= 1.6.0 =
* **Baru — Header IP tepercaya (deteksi dini):** untuk situs di belakang Cloudflare/nginx reverse proxy/CDN, pembatas brute-force kini bisa diatur memakai IP asli pengunjung dari header proxy (CF-Connecting-IP, True-Client-IP, X-Real-IP, atau X-Forwarded-For) alih-alih REMOTE_ADDR mentah. Default TETAP kosong (cuma REMOTE_ADDR, selalu aman) — admin memilih sendiri lewat panel Pengerasan Lanjutan, setelah melihat perbandingan nilai REMOTE_ADDR vs isi header tersebut secara langsung di layar yang sama (deteksi dini sebelum pengaturan berdampak diterapkan).
* **Baru — Lockout progresif (manual):** IP/akun yang berulang kali kena lockout brute-force dalam 7 hari terakhir sekarang bisa dikenai durasi kunci yang naik bertahap (2x, 4x, 8x dari durasi dasar, dibatasi mutlak 24 jam) — membuat serangan yang gigih makin mahal tiap kali dicoba ulang. Default MATI (manual, panel Pengerasan Lanjutan) karena admin yang sering lupa password sendiri juga ikut terdampak; riwayat eskalasi langsung direset ke nol begitu login berhasil.
* **Perbaikan keamanan penting — verifikasi NYATA larangan eksekusi PHP di uploads:** sebelumnya plugin hanya menulis file `.htaccess` dan berasumsi itu cukup. Sekarang plugin benar-benar MENCOBA menjalankan file PHP uji coba lewat permintaan HTTP sungguhan ke folder uploads dan memeriksa hasilnya — baris baru di Pemeriksaan Kesehatan Server melaporkan status "Terverifikasi"/"PENTING: tidak terblokir"/"Tidak bisa diperiksa" alih-alih berasumsi dari keberadaan file semata. Ini menutup false sense of security di server nginx (yang tidak pernah membaca `.htaccess` sama sekali) atau Apache dengan `AllowOverride None`. Dilengkapi tombol "Uji Sekarang" untuk memaksa pengecekan ulang, dan hasil dicache 12 jam supaya tidak memicu permintaan HTTP di setiap buka halaman admin.
* **Ditingkatkan — penyamaran versi WordPress:** parameter `?ver=` pada URL script/style kini diganti dengan token versi palsu-tapi-masuk-akal yang STABIL per situs (bukan sekadar dibuang begitu saja, yang justru jadi sidik jari tersendiri), dibuat dengan sumber acak kriptografis WordPress — bukan pendekatan `str_shuffle(time())` yang mudah dipersempit kemungkinannya. Token diperbarui otomatis setiap WordPress core diupdate (menjaga manfaat cache-busting asli), tidak pernah berubah di luar itu (menjaga cache browser tetap efektif).
* Keempat penambahan di atas diuji lewat 4 harness fungsional terpisah (33 + 16 + 21 + 17 = 87 pemeriksaan), lalu sekali lagi lewat satu regresi penuh yang memuat SELURUH file plugin sekaligus dan menguji interaksi antar-fitur (header IP tepercaya + lockout progresif berjalan bersamaan, verifikasi exec-deny dan token versi berjalan berdampingan dengan CAPTCHA/2FA yang sudah ada) — 25 pemeriksaan tambahan, semuanya lolos.

= 1.5.0 =
* **Perombakan UI/UX:** halaman WScanom dirapikan jadi dashboard berbasis kartu (ikon, status ringkas di atas, badge aktif/nonaktif per fitur) — bukan lagi tumpukan form datar. Bahasa di seluruh halaman ditulis ulang supaya lebih natural dan profesional.
* **Baru — CAPTCHA login:** soal aritmatika sederhana di wp-login.php, ditandatangani HMAC tanpa penyimpanan sesi di server, tanpa layanan pihak ketiga. Default aktif, bisa dimatikan di Pengaturan Proteksi.
* **Baru — Verifikasi Dua Langkah (2FA):** TOTP (RFC 6238) murni PHP, kompatibel Google Authenticator/Authy/Microsoft Authenticator. Diaktifkan sendiri oleh tiap user lewat halaman profil, baru menyala setelah kode dari aplikasi terbukti cocok (tidak mungkin mengunci diri sendiri secara tidak sengaja), lengkap dengan 8 kode cadangan sekali pakai dan jalur pemulihan darurat oleh admin lain.
* Kartu ringkasan status di bagian atas halaman WScanom: berapa proteksi inti yang aktif, status HTTPS, dan status 2FA akunmu — semua dalam satu pandangan.
* Seluruh logika baru (CAPTCHA + TOTP) diuji lewat 43 pemeriksaan fungsional, termasuk validasi terhadap tiga angka uji resmi RFC 6238 Appendix B, bukan cuma pengecekan sintaks.
* Distribusi dipindah ke GitHub saja (tidak diajukan ke direktori WordPress.org) — selaras dengan plugin ini yang gratis selamanya tanpa versi pro.

= 1.4.0 =
* **Baru — Pembatas percobaan login (brute-force):** default aktif, 5 percobaan gagal/20 menit kunci (bisa disesuaikan), dilacak per-IP DAN per-username lintas IP sekaligus supaya brute-force terdistribusi tetap tertangkap.
* **Baru — Pengerasan XML-RPC:** metode pingback dimatikan otomatis (aman untuk semua situs); opsi matikan XML-RPC total tersedia manual di panel Pengerasan Lanjutan, lengkap dengan deteksi dini plugin yang bergantung padanya (mis. Jetpack).
* **Baru — Pengerasan privasi:** sembunyikan versi WordPress, blokir penebakan username (`?author=N` dan REST API users), blokir akses `readme.html`/`license.txt`/`wp-config-sample.php`, header HTTP protektif, dan cookie login "Secure" otomatis yang HANYA aktif kalau situs terdeteksi HTTPS (mencegah situs terkunci total di situs non-HTTPS).
* **Baru — Panel Pengerasan Lanjutan:** matikan XML-RPC total, paksa HTTPS, matikan feed RSS/Atom — semua default MATI, manual, dengan status deteksi dini situs ditampilkan sebelum diaktifkan.
* **Baru — Aksi Darurat:** tombol sekali klik untuk memaksa reset password semua user atau memutus semua sesi login aktif, dipakai setelah situs dicurigai disusupi.
* **Baru — Log Aktivitas:** mencatat login gagal/berhasil, perubahan pengaturan, dan aksi darurat, ditampilkan langsung di halaman admin.
* **Baru — Pemeriksaan Kesehatan Server:** laporan baca-saja untuk versi PHP, HTTPS, mode debug, listing folder, dan update keamanan otomatis.
* Semua fitur baru di atas diuji lewat harness fungsional (bukan sekadar pengecekan sintaks) sebelum dirilis, termasuk skenario brute-force terdistribusi dan urutan prioritas filter autentikasi.

= 1.3.0 =
* **Perbaikan deteksi (penting):** scanner sebelumnya hanya memindai file berekstensi literal `.php` — webshell dengan ekstensi `.phtml`, `.php3/4/5/6/7/8`, `.pht`, `.phar`, `.phps`, atau `.inc` (semua masih bisa dieksekusi sebagai PHP di sebagian konfigurasi server) lolos total tanpa terdeteksi sama sekali. Diuji dengan 14 file percobaan berbagai ekstensi: sebelum perbaikan, 10 di antaranya tidak terdeteksi; sesudah perbaikan, 14/14 terdeteksi.
* Daftar ekstensi ini sekarang satu sumber (`wscanom_scannable_extensions()`), dipakai bersama oleh scanner, bonus skor "nama file mencurigakan", dan aturan exec-deny di folder uploads — supaya ketiganya tidak bisa lagi saling menyimpang di kemudian hari.

= 1.2.1 =
* **Perbaikan keamanan (defense-in-depth):** fungsi "scan seketika setelah plugin/tema berubah" (ditambahkan di 1.1.0) tidak memvalidasi ulang bahwa folder yang dipindai tetap berada di dalam `wp-content`, berbeda dari jalur AJAX yang sudah memvalidasi ini sejak awal. Secara normal data ini datang dari WordPress core yang sudah disaring, tapi fungsi ini sekarang tidak lagi mempercayainya begitu saja — disaring ulang dan divalidasi dengan `realpath()` sebelum dipindai, supaya fitur auto-karantina tidak mungkin bertindak di luar `wp-content` dalam skenario apa pun.

= 1.2.0 =
* **Baru:** halaman sambutan otomatis muncul sesaat setelah plugin diaktifkan — menjelaskan dengan bahasa awam proteksi apa saja yang baru saja dipasang (sebelumnya terpasang diam-diam tanpa pemberitahuan), dan langsung menjalankan scan pertama saat itu juga (sebelumnya scan pertama baru terjadwal ~1 jam setelah aktivasi lewat WP-Cron). Bisa dilewati, dan pengaturan proteksi bisa disesuaikan langsung dari halaman itu sebelum lanjut.

= 1.1.0 =

= 1.1.0 =
* **Baru:** proteksi otomatis aktif sejak plugin diaktifkan — matikan Theme/Plugin Editor bawaan WordPress, larang eksekusi PHP di folder uploads, scan seketika setelah plugin/tema diinstall/diaktifkan/diupdate, dan auto-karantina untuk temuan yang sangat meyakinkan. Lihat panel **Pengaturan Proteksi** di halaman WScanom untuk menyesuaikan atau mematikan.

= 1.0.1 =
* Perbaikan deteksi: tiga pola (eksekusi `create_function` dari input, `mail()` dari input, target `curl` dari input) sebelumnya gagal mendeteksi kalau kode malware ditulis di beberapa baris — sudah diperbaiki.
* Perbaikan keandalan: scan terjadwal (WP-Cron) sekarang membagi diri jadi beberapa kali jalan kalau situsnya besar, alih-alih berisiko terpotong paksa oleh batas waktu eksekusi PHP tanpa jejak kegagalan. Hasil sebagian ditandai jelas ("incomplete") di halaman admin, bukan hilang diam-diam.
* Ringkasan scan terjadwal terakhir kini ditampilkan di halaman admin, tidak hanya lewat email.
* Folder karantina plugin sendiri (termasuk file index.php penjaganya) tidak lagi ikut terhitung dan terpindai ulang di setiap scan.
* Halaman Network Admin kini memberi tahu kalau jaringan punya lebih dari 200 situs (sebelumnya situs ke-201 dan seterusnya diam-diam tidak muncul di daftar).

= 1.0.0 =
* Rilis pertama: scan bertahap, whitelist berbasis hash, scan terjadwal + notifikasi email, dukungan multisite.
