# WScanom

Pemindai pola webshell/backdoor untuk WordPress. WScanom memeriksa seluruh file `.php` di dalam `wp-content` (tema, plugin, mu-plugins, uploads) serta file sentinel di root WordPress (`wp-config.php`, `index.php`, dll), mencari pola yang umum dipakai webshell dan backdoor — lalu memberi kamu alat untuk menindaklanjutinya (karantina, bersihkan, atau tandai aman) langsung dari dashboard.

**Versi:** 1.6.0 · **Requires PHP:** 7.4+ · **Requires WordPress:** 5.8+ · **Lisensi:** GPLv2 atau lebih baru · **100% gratis, tanpa versi pro, selamanya**

> Dibagikan lewat GitHub, bukan direktori resmi WordPress.org — unduh rilis di bawah, upload sebagai zip, selesai. Tidak ada lisensi, akun, atau fitur yang dikunci di balik pembayaran apa pun.

> WScanom adalah pemeriksaan **tambahan**, bukan pengganti scanner keamanan utama seperti Wordfence atau Sucuri. Baca bagian [Batasan](#batasan-wajib-dibaca) sebelum dipakai di situs produksi.

WScanom dirancang untuk dipasang lalu **ditinggal** — semua proteksi di bawah aktif sejak aktivasi tanpa admin perlu mengatur apa pun. Lihat [Proteksi otomatis](#proteksi-otomatis) untuk penjelasan lengkap apa yang sebenarnya bisa dan tidak bisa dicegah oleh plugin WordPress.

---

## Daftar isi

- [Fitur](#fitur)
- [Proteksi otomatis](#proteksi-otomatis)
- [Proteksi login & XML-RPC](#proteksi-login--xml-rpc)
- [Pengerasan privasi](#pengerasan-privasi)
- [Pengerasan lanjutan (manual)](#pengerasan-lanjutan-manual)
- [Aksi darurat](#aksi-darurat)
- [Log aktivitas & pemeriksaan kesehatan server](#log-aktivitas--pemeriksaan-kesehatan-server)
- [Cara kerja deteksi](#cara-kerja-deteksi)
- [Batasan (wajib dibaca)](#batasan-wajib-dibaca)
- [Instalasi](#instalasi)
- [Pemakaian](#pemakaian)
- [Multisite](#multisite)
- [Privasi & keamanan data](#privasi--keamanan-data)
- [Untuk pengembang](#untuk-pengembang)
- [Pengujian](#pengujian)
- [Uninstall](#uninstall)
- [Kontribusi](#kontribusi)
- [Lisensi](#lisensi)

---

## Fitur

**Pemindaian**
- Scan manual bertahap lewat AJAX — file dipecah jadi batch kecil (default 75 file/permintaan) supaya satu kali scan tidak membebani server atau kena batas waktu eksekusi PHP, bahkan di situs dengan ribuan file.
- Scan terjadwal harian lewat WP-Cron yang berjalan di background. Kalau situsnya besar dan satu kali jalan tidak cukup sebelum batas waktu eksekusi PHP habis, proses **menyambung dirinya sendiri otomatis** lewat event terpisah sampai selesai — bukan terpotong paksa tanpa jejak. Kalau situsnya benar-benar luar biasa besar, proses menyerah dengan batas aman dan tetap melaporkan hasil sebagian, ditandai jelas sebagai "belum lengkap" di halaman admin.
- Pemeriksaan terpisah untuk file sentinel di root WordPress (`index.php`, `wp-config.php`, `wp-load.php`, `wp-settings.php`, `wp-blog-header.php`) — target umum backdoor yang menyuntik dirinya sendiri ke file inti.
- Lebih dari 20 pola deteksi: eksekusi kode tersembunyi (`eval` atas data base64/gzinflate/rot13), eksekusi perintah sistem dari input pengunjung, dropper pengunduh payload dari URL luar, pembuatan akun administrator secara terprogram, cron job tersembunyi, cloaking bot mesin pencari, iframe tersembunyi, serta blok "penanda" generik (`XXX-CORE-START/END`) khas backdoor *self-replicating*. Daftar lengkap di [`includes/patterns.php`](wscanom/includes/patterns.php).

**Tindak lanjut**
- **Karantina satu klik** — file dipindah (bukan dihapus permanen) ke folder terkunci di luar jangkauan eksekusi web, ekstensinya diganti jadi `.suspected`, dan dicatat di log supaya bisa **dipulihkan** kapan saja kalau ternyata salah tuduh.
- **Bersihkan Blok Tersuntik** — khusus untuk file sentinel root yang tidak bisa dipindah (situs butuh file itu untuk jalan). Hanya blok kode yang cocok pola backdoor yang dibuang *in-place*; isi lengkap sebelum dibersihkan disimpan sebagai backup yang bisa dipulihkan penuh.
- **Whitelist berbasis hash** — tandai hasil yang kamu yakin aman. Ditandai per `(path file, hash SHA-256 isi file)`, sehingga kalau file itu ditimpa backdoor baru di kemudian hari, tanda aman otomatis batal dan file terdeteksi lagi.

**Visibilitas**
- Ringkasan scan terjadwal terakhir (waktu, jumlah file, jumlah temuan, status lengkap/sebagian) ditampilkan langsung di halaman admin — tidak hanya lewat email.
- Notifikasi email ke admin saat ditemukan file dengan skor di atas ambang yang bisa dikonfigurasi.
- Dukungan multisite: halaman ringkasan di Network Admin dengan tautan ke scanner tiap situs, lengkap dengan peringatan kalau jaringan punya lebih banyak situs daripada yang bisa ditampilkan dalam satu daftar.

**Privasi**
- Tidak ada data situs yang dikirim ke server pihak ketiga mana pun. Seluruh pemindaian dan penyimpanan hasil berjalan di server kamu sendiri; satu-satunya komunikasi keluar adalah email notifikasi ke alamat admin situs sendiri (bisa dimatikan).

## Proteksi otomatis

Di luar fitur scan/karantina di atas (yang butuh admin membuka dashboard), WScanom juga memasang tiga lapis proteksi yang berjalan sendiri sejak aktivasi — relevan untuk tiga pola serangan paling umum: **plugin/tema bajakan ("nulled") yang sudah bawa backdoor**, **akun admin bobol lewat password lemah/bruteforce**, dan **file yang merembet dari situs lain di shared hosting yang sama**.

Penting untuk jujur soal batasnya: **plugin WordPress tidak bisa mencegat penulisan file dari sembarang jalur.** Kalau backdoor ditulis dari dalam kode plugin lain yang rentan, lewat SQL injection, atau lewat kredensial FTP/hosting yang bocor, tidak ada hook WordPress yang bisa mencegatnya — itu butuh akses level server (inotify/fanotify, ModSecurity, EDR) yang berada di luar jangkauan plugin apa pun, termasuk Wordfence/Sucuri sekalipun. Karena itu strateginya bukan "cegah file tertulis" (mustahil dari level plugin), tapi **pastikan file itu tidak bisa dieksekusi, dan kalaupun bisa, ketahuan secepat mungkin lalu ditindak tanpa menunggu manusia**:

1. **Matikan Theme/Plugin Editor bawaan WordPress** (`DISALLOW_FILE_EDIT`, didefinisikan otomatis). Ini satu-satunya dari ketiga lapis yang benar-benar **mencegah total**, bukan cuma mendeteksi lebih cepat: kalau akun admin bobol, penyerang tidak akan pernah bisa menyimpan kode lewat editor bawaan itu, titik.
2. **Larang eksekusi PHP di folder `uploads`** lewat `.htaccess` yang ditulis otomatis saat aktivasi (Apache/LiteSpeed; pengguna nginx perlu menambahkan aturan setara secara manual — nginx tidak membaca `.htaccess`, catatan lengkap otomatis dibuat di folder `uploads`). File masih bisa tertulis ke sana dari jalur mana pun, tapi tidak akan pernah bisa dijalankan selama ada di situ. **Tidak berlaku** untuk file yang ditulis langsung ke dalam folder plugin/tema — folder itu memang harus boleh menjalankan PHP. **Diverifikasi NYATA sejak v1.6.0:** menulis `.htaccess` saja tidak membuktikan server benar-benar menghormatinya (nginx tidak pernah membacanya; Apache dengan `AllowOverride None` juga mengabaikannya diam-diam) — plugin sekarang benar-benar **mencoba menjalankan** file PHP uji coba lewat permintaan HTTP sungguhan ke folder itu dan memeriksa hasilnya, dilaporkan sebagai baris baru di panel **Pemeriksaan Kesehatan Server** (lihat di bawah).
3. **Scan seketika + auto-karantina** — begitu plugin/tema diinstall, diaktifkan, atau diupdate, langsung dipindai saat itu juga (hook `upgrader_process_complete`, `activated_plugin`, `switch_theme`), bukan menunggu jadwal scan berikutnya. Temuan dengan pola yang sangat meyakinkan (bukan sekadar gabungan beberapa pola ringan — lihat `wscanom_findings_max_weight()` di `includes/hardening.php`) langsung dikarantina otomatis. Diuji lewat simulasi: instalasi plugin "nulled" dengan backdoor `eval(base64_decode(...))` terdeteksi dan terkarantina dalam **<2 milidetik** sejak instalasi selesai, tanpa ada yang mengklik apa pun.

Ketiganya bisa disesuaikan atau dimatikan lewat panel **Pengaturan Proteksi** di halaman Tools → WScanom, tapi defaultnya **aktif semua** — konsisten dengan tujuan plugin ini: admin cukup install dan aktifkan, proteksi jalan sendiri.

## Proteksi login & XML-RPC

Melengkapi tiga lapis di atas dengan proteksi untuk skenario serangan yang masuk lewat **login**, bukan lewat file — semuanya default aktif karena aman untuk semua situs:

- **Pembatas percobaan login (brute-force)** — dilacak dengan dua kunci sekaligus: per kombinasi (IP, username) dan per-username lintas semua IP. Yang pertama menangkap brute-force biasa dari satu sumber; yang kedua menangkap brute-force **terdistribusi** (banyak IP/proxy berbeda menyasar satu akun yang sama, pola umum di serangan modern). Default 5 percobaan gagal → kunci 20 menit (bisa disesuaikan di **Pengaturan Proteksi**), sengaja longgar supaya admin yang salah ketik password sendiri tidak langsung terkunci.
- **Header IP tepercaya** *(baru v1.6.0, manual)* — untuk situs di belakang Cloudflare/nginx reverse proxy/CDN, pembatas brute-force di atas bisa diatur memakai IP asli pengunjung dari header proxy (CF-Connecting-IP, True-Client-IP, X-Real-IP, atau X-Forwarded-For) alih-alih `REMOTE_ADDR` mentah yang di balik proxy selalu sama untuk semua pengunjung. Default **TETAP kosong** (cuma `REMOTE_ADDR`, selalu aman terhadap pemalsuan header) — admin memilih sendiri di panel **Pengerasan Lanjutan**, setelah melihat perbandingan `REMOTE_ADDR` vs isi header tersebut secara langsung di layar yang sama. Memilih header yang **tidak benar-benar** dipakai proxy situsmu membuat siapa pun bisa memalsukannya dan melewati pembatas brute-force sepenuhnya — makanya tidak pernah otomatis.
- **Lockout progresif** *(baru v1.6.0, manual)* — IP/akun yang berulang kali kena lockout dalam 7 hari terakhir bisa dikenai durasi kunci yang naik bertahap (2x, 4x, 8x dari durasi dasar, dibatasi mutlak 24 jam), membuat serangan yang gigih makin mahal tiap kali dicoba ulang. Default **MATI** karena admin yang sering lupa password sendiri juga ikut terdampak; riwayat eskalasi langsung direset ke nol begitu login berhasil, jadi kesalahan ketik sesekali tidak pernah terbawa-bawa.
- **CAPTCHA login** *(baru v1.5.0)* — soal aritmatika sederhana (mis. "berapa 4 + 7?") disisipkan ke wp-login.php, ditandatangani lewat HMAC memakai `AUTH_KEY` situs sendiri dan kedaluwarsa otomatis dalam 10 menit. Tidak ada penyimpanan sesi di server, tidak ada layanan pihak ketiga, tidak ada kunci API — cukup untuk menghalau bot yang tidak benar-benar merender halaman.
- **Verifikasi Dua Langkah (2FA)** *(baru v1.5.0)* — TOTP (RFC 6238) ditulis murni dengan PHP bawaan (`hash_hmac`), kompatibel dengan Google Authenticator, Authy, dan Microsoft Authenticator. **Opsional dan per-user**: tiap akun mengaktifkan 2FA miliknya sendiri lewat halaman profil, dan baru benar-benar menyala setelah kode dari aplikasi authenticator terbukti cocok — mustahil mengunci diri sendiri secara tidak sengaja. Dilengkapi 8 kode cadangan sekali pakai, dan jalur pemulihan darurat (admin lain bisa mematikan paksa 2FA milik user yang kehilangan akses, tapi tidak bisa mengaktifkan atau melihat kunci rahasia milik user lain).
- **Pengerasan XML-RPC** — metode `pingback.*` (vektor DDoS amplifikasi dan pemindaian brute-force paling umum lewat XML-RPC) dihapus otomatis tanpa mematikan XML-RPC itu sendiri, jadi integrasi sah (Jetpack, aplikasi mobile WordPress resmi) tetap jalan tanpa perlu dikonfigurasi apa pun.

## Pengerasan privasi

Juga default aktif — mempersempit informasi yang bisa dikumpulkan pemindai otomatis, tanpa downside fungsional bagi pengunjung biasa:

- Versi WordPress disembunyikan dari `<head>` dan tag generator. Parameter `?ver=` di URL script/style **tidak sekadar dibuang** (sejak v1.6.0) — diganti dengan token versi palsu-tapi-masuk-akal yang **stabil per situs** (dibuat dengan sumber acak kriptografis, bukan `str_shuffle(time())`), supaya tidak jadi sidik jari baru ("semua aset situs ini tidak punya versi sama sekali") dan tidak merusak cache browser. Token ikut diperbarui otomatis tiap kali WordPress core diupdate.
- Penebakan username lewat `?author=1`, `?author=2`, dst. diblokir (redirect ke beranda); endpoint REST API publik `/wp-json/wp/v2/users` ditutup untuk pengunjung yang belum login.
- Akses langsung ke `readme.html`, `license.txt`, dan `wp-config-sample.php` ditolak (403) — file-file ini sering jadi langkah pertama pemindai otomatis untuk sidik jari versi situs.
- Header HTTP protektif standar (`X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin`) dikirim di setiap permintaan. **Content-Security-Policy penuh sengaja TIDAK disertakan** karena terlalu mudah mematahkan tema/plugin lain kalau dipasang tanpa penyesuaian per situs.
- Cookie login (`auth`, `logged_in`) dipaksa flag **Secure** — **hanya kalau `is_ssl()` mengembalikan true saat itu juga**. Ini contoh konkret "deteksi dini sebelum pengaturan berdampak diterapkan": memaksa flag Secure di situs yang belum benar-benar HTTPS akan membuat browser **menolak cookie itu sepenuhnya**, yang berarti tidak ada seorang pun yang bisa login. Notice peringatan juga muncul di halaman WScanom kalau situs terdeteksi belum HTTPS.

## Pengerasan lanjutan (manual)

Pengaturan berikut **BISA mematahkan fungsi situs tertentu** kalau diaktifkan tanpa situsnya siap, jadi semuanya **default MATI** dan **tidak pernah otomatis** — sesuai prinsip inti plugin ini: fitur berisiko dikustomisasi dan diaktifkan sendiri oleh penggunanya, bukan ditebak oleh plugin. Panel **Pengerasan Lanjutan** di halaman WScanom menampilkan status "deteksi dini" situsmu tepat di atas tiap opsi, sebelum kamu menekan tombol aktifkan:

| Opsi | Risiko kalau dipaksa tanpa siap | Deteksi dini yang ditampilkan |
|---|---|---|
| Matikan XML-RPC total | Memutus Jetpack, aplikasi mobile WordPress resmi, dan integrasi lain yang butuh XML-RPC | Memindai plugin aktif yang diketahui bergantung XML-RPC (Jetpack, Jetpack Boost, WP Time Capsule) |
| Paksa redirect semua trafik ke HTTPS | Situs tidak bisa diakses sama sekali kalau sertifikat belum valid | Status `is_ssl()`/HTTPS situs saat ini; kotak centang **terkunci** kalau situs belum terdeteksi HTTPS |
| Matikan feed RSS/Atom | Memutus pembaca RSS, layanan sindikasi, atau newsletter yang bergantung pada feed | — (bukan risiko keamanan besar, cuma mempersempit permukaan info) |
| Header IP tepercaya *(v1.6.0)* | Kalau situs ternyata bisa diakses langsung tanpa lewat proxy tersebut, pengunjung mana pun bisa memalsukan header itu sendiri dan melewati pembatas brute-force | Tabel perbandingan `REMOTE_ADDR` saat ini vs isi tiap header proxy (CF-Connecting-IP, True-Client-IP, X-Real-IP, X-Forwarded-For) pada permintaan yang sedang berjalan |
| Lockout progresif *(v1.6.0)* | Admin yang sendiri sering lupa password ikut kena durasi kunci yang naik bertahap sampai maksimal 24 jam | Pratinjau jadwal eskalasi (lockout ke-1 sampai ke-4) dihitung langsung dari durasi lockout dasar yang sedang berlaku |

## Aksi darurat

Dua tombol sekali-klik di halaman WScanom, dipakai **setelah** admin curiga atau yakin situsnya kena kompromi — untuk langsung memutus akses penyerang yang mungkin sudah mencuri sesi login atau password, sebelum kerusakan berlanjut. Keduanya minta konfirmasi browser dulu sebelum benar-benar jalan:

- **Paksa Reset Password Semua User** — semua akun ditandai wajib ganti password di login berikutnya (dicek lewat filter `authenticate`, jadi password lama tidak bisa dipakai login lagi sampai diganti lewat alur resmi "Lupa password?"), dan semua sesi login aktif saat ini langsung diputus (`WP_Session_Tokens::destroy_all()`).
- **Keluarkan Semua User dari Sesi Login** — memutus semua sesi aktif tanpa memaksa reset password, untuk bersih-bersih cepat kalau admin yakin tidak ada akun yang benar-benar dibobol.

## Log aktivitas & pemeriksaan kesehatan server

- **Log Aktivitas** — mencatat login gagal, login berhasil, perubahan pengaturan proteksi, dan aksi darurat yang dijalankan, masing-masing dengan waktu dan keterangan. Disimpan sebagai satu option (bukan tabel database terpisah), dibatasi 300 entri terbaru supaya tidak tumbuh tanpa batas.
- **Pemeriksaan Kesehatan Server** — panel **baca-saja**: versi PHP, status HTTPS, `display_errors`, status Theme/Plugin Editor, listing folder `wp-content`, mode `WP_DEBUG`, status update keamanan otomatis WordPress, dan (sejak v1.6.0) status **terverifikasi NYATA** larangan eksekusi PHP di folder `uploads` — bukan sekadar "file `.htaccess` ada", tapi hasil percobaan eksekusi sungguhan lewat HTTP, dengan tombol "Uji Sekarang" untuk memaksa pengecekan ulang kapan saja (hasil dicache 12 jam supaya tidak membebani tiap buka halaman admin). WScanom jujur soal batasnya di sini: plugin WordPress **tidak bisa** mengubah konfigurasi server (itu butuh akses di luar jangkauan PHP) — panel ini murni melaporkan dan menyarankan, tidak pernah mengubah apa pun secara otomatis.

## Cara kerja deteksi

WScanom membaca isi tiap file `.php` dan mencocokkannya terhadap kumpulan pola regex (format eksekusi kode, pemanggilan fungsi berbahaya dengan input pengunjung, nama file yang lazim dipakai webshell, lokasi file yang mencurigakan seperti `.php` di folder `uploads`). Tiap pola punya bobot risiko; skor total menentukan urutan temuan yang ditampilkan.

Semua pola ditulis case-insensitive dan tahan terhadap kode yang diformat ulang di beberapa baris (bukan cuma mencari pola dalam satu baris saja), supaya tidak mudah dilewati hanya dengan menambahkan baris baru di tengah pemanggilan fungsi.

## Batasan (wajib dibaca)

WScanom adalah pemindai **berbasis pola/heuristik**, bukan database signature besar yang di-update berkala seperti Wordfence atau Sucuri. Konsekuensinya:

- **False positive** mungkin terjadi, terutama pada plugin caching/minifier yang memang memakai teknik mirip obfuscation untuk tujuan sah. Gunakan **Tandai Aman**, jangan langsung karantina tanpa diperiksa dulu.
- **False negative** mungkin terjadi untuk teknik backdoor baru yang polanya belum terdaftar, atau yang sengaja dirancang untuk menghindari pola yang ada.
- Scan terjadwal memindai seluruh `wp-content`; pada situs yang **sangat** besar (puluhan ribu file), scan bisa butuh beberapa kali "sambungan" background sebelum selesai dalam satu siklus harian — ini normal dan tetap aman, tapi perlu diketahui kalau kamu mengharapkan hasil instan dari cron.

Gunakan sebagai lapisan pemeriksaan tambahan, bukan satu-satunya alat keamanan situsmu.

## Instalasi

### Dari rilis (disarankan untuk pengguna biasa)

1. Unduh `wscanom.zip` dari halaman [Releases](../../releases).
2. WordPress Dashboard → **Plugins → Add New → Upload Plugin**.
3. Pilih file zip, **Install Now**, lalu **Activate**.
4. Buka **Tools → WScanom**.

### Dari source (untuk pengembangan)

```bash
git clone https://github.com/treeleaf1901/Wscanom.git wscanom
cp -r wscanom /path/ke/wordpress/wp-content/plugins/
```

## Pemakaian

1. Buka **Tools → WScanom** dan klik **Jalankan Scan Sekarang**. Progress bar menunjukkan batch yang sedang dipindai; hasil muncul bertahap, terurut skor tertinggi di atas.
2. Untuk tiap temuan di `wp-content`, pilih salah satu:
   - **Tandai Aman** — kalau yakin ini false positive. File tidak akan muncul lagi selama isinya tidak berubah.
   - **Karantina** — pindahkan file keluar dari lokasi aslinya. Masih bisa dipulihkan lewat tabel **File dalam Karantina** di bagian bawah halaman.
3. Untuk temuan di file sentinel root (ditandai `(root)/...`), satu-satunya aksi adalah **Bersihkan Blok Tersuntik** — file tidak dipindah, hanya blok kode yang cocok pola yang dibuang, dengan backup penuh tersimpan otomatis.
4. Aktifkan/matikan notifikasi email dan atur ambang skor alert sesuai kebutuhan (pengaturan terjadwal berjalan otomatis setiap hari setelah plugin aktif).

## Multisite

- `wp-content` (tema dan plugin) umumnya dibagi oleh semua situs di jaringan, jadi memindai satu situs biasanya sudah mencakupnya.
- Folder `uploads` tiap situs terpisah, jadi tetap jalankan scan dari tiap situs secara berkala.
- Whitelist dan log karantina disimpan per-situs (option biasa, otomatis terpisah per blog berkat `switch_to_blog()`), jadi menandai aman di satu situs tidak memengaruhi situs lain.
- Halaman **Network Admin → WScanom** menampilkan daftar situs dengan tautan langsung ke scanner masing-masing.

## Privasi & keamanan data

- Tidak ada telemetri, tidak ada pemanggilan API eksternal, tidak ada data situs yang dikirim keluar.
- File yang dikarantina disimpan di `wp-content/wscanom-quarantine/`, dilindungi dari akses web langsung lewat `.htaccess` (`Deny from all`) dan `index.php` kosong, serta ekstensi filenya diganti jadi `.suspected` (tidak bisa dieksekusi PHP walau ada misconfig server).
- Semua aksi yang mengubah filesystem (karantina, bersihkan blok, pulihkan) butuh kapabilitas `manage_options` dan diverifikasi nonce (`wp_nonce` untuk form, `check_ajax_referer` untuk AJAX).
- Semua path dari input disanitasi dan divalidasi ulang dengan `realpath()` supaya tetap berada di dalam base dir yang diizinkan (mencegah path traversal).

## Untuk pengembang

Beberapa filter yang tersedia untuk kustomisasi:

| Filter | Default | Kegunaan |
|---|---|---|
| `wscanom_scan_base_dir` | `WP_CONTENT_DIR` | Ubah direktori dasar yang dipindai. |
| `wscanom_cron_time_budget` | `20` (detik) | Anggaran waktu per "jalan" scan terjadwal sebelum menyambung lewat event terpisah. Naikkan kalau hosting kamu punya `max_execution_time` yang longgar. |

Struktur kode:

```
wscanom/
├── wscanom.php              # bootstrap plugin, hook aktivasi/deaktivasi
├── uninstall.php            # pembersihan data saat plugin dihapus penuh
└── includes/
    ├── patterns.php         # daftar pola deteksi
    ├── scanner.php          # mesin scan, whitelist, karantina, strip blok
    ├── cron.php             # scan terjadwal + notifikasi email + pengaturan default
    ├── activity-log.php     # log aktivitas ringan (login, pengaturan, aksi darurat)
    ├── hardening.php        # proteksi otomatis: disable editor, exec-deny uploads, scan seketika + auto-karantina
    ├── login-protection.php # brute-force login, pengerasan XML-RPC, aksi darurat
    ├── captcha.php          # CAPTCHA aritmatika stateless di wp-login.php
    ├── two-factor.php       # 2FA (TOTP), kode cadangan, layar verifikasi login
    ├── privacy-hardening.php# sembunyikan versi, anti username-enum, header HTTP, cookie aman
    ├── health-check.php     # pemeriksaan kesehatan server (baca-saja)
    ├── admin-page.php       # halaman admin, menu, enqueue asset, semua panel pengaturan
    └── ajax.php             # handler AJAX (nonce + capability check)
```

## Pengujian

Selain unit test terisolasi untuk logika deteksi, whitelist, dan path-sanitization, rilis ini sudah melalui pengujian adversarial yang menyasar skenario kegagalan, bukan hanya jalur normal — di antaranya:

- Kode malware yang diformat ke beberapa baris (menguji apakah pola deteksi bisa dilewati hanya dengan menambah baris baru).
- Symlink folder yang mengarah ke dirinya sendiri (menguji potensi infinite loop saat membangun daftar file).
- Simulasi scan terjadwal pada situs besar dengan anggaran waktu sangat kecil, memastikan proses menyambung diri dengan benar dan tidak pernah kehilangan hasil secara diam-diam.
- File sentinel root dengan beberapa blok tersuntik berbeda sekaligus dalam satu file.
- Folder karantina milik plugin sendiri, memastikan tidak ikut terhitung ulang di scan berikutnya.
- **v1.4.0:** seluruh logika proteksi login & privasi diuji lewat harness fungsional terpisah (bukan sekadar `php -l`) — skenario brute-force dual-key (per-IP dan per-username lintas IP), brute-force terdistribusi, urutan prioritas filter `authenticate` (pembatas lockout → pemaksa reset password), aksi darurat (paksa reset + logout massal, termasuk bahwa akun yang sudah reset bisa login lagi sementara akun lain tetap terkunci), deteksi dini ketergantungan XML-RPC (Jetpack), flag cookie "Secure" yang hanya aktif kalau situs benar-benar HTTPS, dan pembatasan log aktivitas di 300 entri terbaru — total 32 pemeriksaan, semuanya lolos sebelum dirilis.
- **v1.5.0:** CAPTCHA (token HMAC valid/salah/dipalsukan/kedaluwarsa) dan 2FA (base32 round-trip, inti HOTP diverifikasi terhadap **tiga angka uji resmi RFC 6238 Appendix B**, toleransi pergeseran jam ±30 detik, penolakan kode dari secret akun lain, kode cadangan sekali-pakai, serta gerbang "jangan pernah mencegat REST API/XML-RPC/Application Passwords" yang kalau sampai lolos akan mengunci total akses API untuk akun ber-2FA) — total 43 pemeriksaan tambahan, semuanya lolos. Alur layar verifikasi dua langkah di wp-login.php sendiri tidak bisa diuji otomatis tanpa browser sungguhan (tergantung siklus muat halaman WordPress) — sudah ditinjau manual terhadap kode inti `wp-login.php`, tapi tetap uji langsung di staging sebelum dipakai di situs produksi.
- **v1.6.0:** setiap penambahan diuji TERPISAH dengan harness fungsionalnya sendiri sebelum digabung, lalu seluruhnya diuji ULANG bersama-sama lewat satu regresi penuh di akhir — header IP tepercaya (11 pemeriksaan: resistensi pemalsuan default, header dipercaya secara eksplisit, parsing X-Forwarded-For, nilai cacat/kosong/tidak dikenal selalu jatuh aman ke `REMOTE_ADDR`) plus persistensi pengaturannya di handler simpan (13 pemeriksaan: nilai valid tersimpan, nilai hasil tempelan/injeksi ditolak, pengaturan lain tidak ikut terhapus, penjaga kapabilitas/nonce tetap berfungsi); lockout progresif (33 pemeriksaan: matematika eskalasi murni, perilaku non-progresif tidak berubah/regresi, eskalasi bertahap sampai batas pengganda 8x DAN batas mutlak 24 jam, tidak ada eskalasi berulang saat masih terkunci, reset total begitu login berhasil, lockout lintas-IP per-username tetap berfungsi) plus persistensi kotak centangnya (3 pemeriksaan); verifikasi NYATA larangan eksekusi PHP di uploads (21 pemeriksaan: folder tidak terbaca/tidak bisa ditulis, server berhasil memblokir, server GAGAL memblokir — skenario paling kritis, kegagalan jaringan tidak pernah disalahartikan sebagai blokir berhasil, **file probe selalu terhapus di SEMUA jalur termasuk saat exception tak terduga**, acak/tidak bisa ditebak antar-percobaan, cache 12 jam dan tombol uji-ulang paksa); token versi palsu (17 pemeriksaan: format masuk akal, **stabil** di permintaan berulang — bukan berubah tiap saat seperti `str_shuffle(time())` di pendekatan yang kami bandingkan, nilai versi asli tidak pernah bocor, parameter "ver" milik plugin lain yang bukan format versi tidak disentuh, rotasi hanya terjadi saat WordPress CORE diupdate bukan tiap plugin/tema). **Regresi akhir:** seluruh 12 file plugin dimuat bersamaan dalam satu proses (bukan terisolasi per fitur) dan 25 pemeriksaan interaksi dijalankan — header IP tepercaya + lockout progresif berjalan bersamaan tanpa saling melemahkan postur aman-default, verifikasi exec-deny dan token versi berjalan berdampingan dengan CAPTCHA/2FA/scanner yang sudah ada tanpa regresi, lalu `php -l` dijalankan ulang di SELURUH file `.php` plugin tanpa kecuali. Total gabungan ronde ini: **87 pemeriksaan per-fitur + 25 pemeriksaan regresi gabungan = 112 pemeriksaan**, semuanya lolos sebelum dirilis.

Beberapa temuan dari pengujian ini sudah diperbaiki di v1.0.1 — lihat [`wscanom/readme.txt`](wscanom/readme.txt) bagian Changelog untuk detail. **Plugin ini belum diuji di instalasi WordPress produksi sungguhan** (admin UI dan AJAX end-to-end lewat browser nyata, WP-Cron di hosting asli, email, dan konteks multisite nyata). Sebelum dipakai di situs produksi:

1. Install di staging/localhost dulu, jalankan scan manual, periksa hasilnya.
2. Coba fitur **Tandai Aman** dan **Karantina**, pastikan keduanya berperilaku seperti dijelaskan di atas dan file bisa dipulihkan.
3. Kalau pakai multisite, cek halaman **Network Admin → WScanom**.
4. Laporkan isu lewat [Issues](../../issues) kalau menemukan bug atau false positive yang mengganggu.

## Uninstall

Menonaktifkan plugin **tidak** menghapus data apa pun (supaya aktivasi ulang tidak kehilangan histori). Menghapus plugin lewat halaman **Plugins** akan menghapus seluruh data miliknya: whitelist, riwayat scan, pengaturan, log karantina, log aktivitas, jadwal cron, tanda "wajib reset password" yang mungkin masih tersisa di user meta, dan folder karantina beserta isinya — di semua situs kalau dipakai di multisite.

## Kontribusi

Pull request terbuka. Ikuti [WordPress Coding Standards](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/) dan sertakan alasan untuk pola deteksi baru yang ditambahkan (contoh nyata atau referensi, bukan tebakan). Untuk perubahan pada `scanner.php` atau `cron.php`, sertakan juga skenario uji yang menunjukkan perilaku di kasus gagal (bukan cuma kasus sukses) — lihat bagian [Pengujian](#pengujian) di atas untuk contoh pendekatannya.

## Lisensi

GPLv2 atau lebih baru. Lihat [LICENSE.txt](wscanom/LICENSE.txt).
