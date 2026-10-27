<?php
/**
 * WScanom — Lapisan proteksi aktif: hal-hal yang berjalan sendiri tanpa
 * admin perlu membuka dashboard sama sekali ("terima beres").
 *
 * Tiga mekanisme di file ini menjawab tiga jalur serangan paling umum yang
 * TIDAK bisa dicegat di titik penulisan file (plugin WordPress tidak punya
 * akses untuk mengintersep setiap file_put_contents() dari kode plugin lain,
 * apalagi tulisan lewat FTP/cPanel di luar PHP sama sekali):
 *
 * 1. wscanom_maybe_disallow_file_edit() — matikan Theme/Plugin Editor
 *    bawaan WordPress. Ini SATU-SATUNYA dari ketiganya yang benar-benar
 *    MENCEGAH (bukan cuma mendeteksi lebih cepat): kalau akun admin bobol
 *    lewat password lemah/bruteforce, penyerang tidak akan pernah bisa
 *    menyimpan kode lewat editor itu sama sekali, titik.
 *
 * 2. wscanom_write_uploads_exec_deny() — larang eksekusi PHP di folder
 *    uploads lewat .htaccess. File masih bisa tertulis ke sana (dari upload
 *    form, plugin rentan, dst), tapi tidak akan pernah bisa DIJALANKAN lewat
 *    web selama ia tetap di folder itu. Tidak berlaku untuk file yang
 *    ditulis LANGSUNG ke dalam folder plugin/tema (folder itu memang harus
 *    boleh menjalankan PHP, di situlah kode asli plugin hidup) — untuk kasus
 *    itu cuma deteksi-cepat (poin 3) yang bisa menolong.
 *
 * 3. wscanom_scan_on_plugin_theme_change() + auto-karantina — begitu plugin
 *    atau tema baru diinstall/diaktifkan/diupdate, langsung dipindai saat
 *    itu juga (bukan menunggu jadwal cron besok). Backdoor yang dibawa
 *    plugin nulled biasanya sudah ada sejak menit nol, jadi ini menangkapnya
 *    di titik paling awal yang mungkin dari sisi plugin.
 *
 * @package WScanom
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// ============================================================
// 1. MATIKAN THEME/PLUGIN EDITOR BAWAAN WORDPRESS
// ============================================================

/**
 * Definisikan DISALLOW_FILE_EDIT sedini mungkin (hook 'plugins_loaded',
 * jauh sebelum pengecekan kapabilitas 'edit_plugins'/'edit_themes' terjadi
 * di admin_menu/admin_init) kalau pengaturan plugin mengaktifkannya dan
 * konstanta itu belum didefinisikan oleh wp-config.php atau plugin lain.
 *
 * Tidak dilakukan lewat auto-define tanpa syarat di awal file supaya tetap
 * menghormati wp-config.php sebagai sumber kebenaran kalau situs sudah
 * mengatur ini sendiri (baik mengaktifkan maupun sengaja mematikannya).
 *
 * @return void
 */
function wscanom_maybe_disallow_file_edit() {
    $settings = wscanom_get_settings();

    if ( empty( $settings['disable_file_editor'] ) ) {
        return;
    }

    if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
        define( 'DISALLOW_FILE_EDIT', true );
    }
}
add_action( 'plugins_loaded', 'wscanom_maybe_disallow_file_edit', 1 );

// ============================================================
// 2. LARANG EKSEKUSI PHP DI FOLDER UPLOADS
// ============================================================

/**
 * Isi .htaccess yang HANYA melarang eksekusi/akses file mirip-PHP, file
 * lain (gambar, dokumen, dst — tujuan folder uploads) tetap bisa diakses
 * pengunjung seperti biasa. Dua bentuk (mod_authz_core modern dan mod_access
 * lama) disertakan supaya kompatibel dengan versi Apache yang berbeda-beda
 * di hosting bersama.
 *
 * @return string
 */
function wscanom_exec_deny_htaccess_content() {
    // Dibangun dari daftar yang SAMA PERSIS dengan yang dipakai scanner
    // (wscanom_scannable_extensions() di scanner.php) — supaya ekstensi
    // yang dianggap "kode PHP" untuk tujuan deteksi dan untuk tujuan
    // pemblokiran eksekusi tidak pernah lagi bisa menyimpang satu sama lain
    // (lihat riwayat: versi sebelumnya sempat berbeda daftar, membuat ada
    // ekstensi yang diblokir eksekusinya tapi tidak pernah dipindai, atau
    // sebaliknya).
    $ext_group = implode( '|', array_map( 'preg_quote', wscanom_scannable_extensions() ) );

    return "# WScanom: cegah eksekusi PHP di folder ini (uploads seharusnya\n"
        . "# cuma berisi media, bukan kode). File lain tetap bisa diakses.\n"
        . "<FilesMatch \"\\.(?:{$ext_group})$\">\n"
        . "    <IfModule mod_authz_core.c>\n"
        . "        Require all denied\n"
        . "    </IfModule>\n"
        . "    <IfModule !mod_authz_core.c>\n"
        . "        Order allow,deny\n"
        . "        Deny from all\n"
        . "    </IfModule>\n"
        . "</FilesMatch>\n";
}

/**
 * Catatan untuk pengguna nginx: nginx TIDAK membaca .htaccess sama sekali
 * (berbeda dari Apache), jadi proteksi ini tidak otomatis berlaku di sana.
 * Alih-alih diam-diam tidak berfungsi, kita tinggalkan file info di folder
 * uploads supaya terlihat jelas kalau ada yang memeriksa, plus instruksi
 * konkret yang bisa ditambahkan admin ke konfigurasi server-nya sendiri.
 *
 * @return string
 */
function wscanom_exec_deny_nginx_note_content() {
    return "WScanom: proteksi \"larang eksekusi PHP\" di folder ini memakai .htaccess,\n"
        . "yang HANYA berlaku di server Apache/LiteSpeed. Kalau situs ini berjalan\n"
        . "di nginx, .htaccess di folder ini TIDAK berpengaruh sama sekali — nginx\n"
        . "tidak pernah membaca file .htaccess.\n\n"
        . "Untuk proteksi yang setara di nginx, tambahkan blok berikut ke konfigurasi\n"
        . "server situs ini (biasanya di dalam blok `server { ... }`), lalu reload nginx:\n\n"
        . "    location ~* /wp-content/uploads/.*\\.(?:php|php[0-9]|phtml|phar|pht)$ {\n"
        . "        deny all;\n"
        . "    }\n\n"
        . "WScanom tidak bisa menulis file ini secara otomatis karena mengubah\n"
        . "konfigurasi nginx butuh akses di luar jangkauan PHP/WordPress.\n";
}

/**
 * Tulis .htaccess exec-deny ke folder uploads kalau belum ada. Idempoten
 * (aman dipanggil berulang) dan dibuat gagal-senyap kalau direktori uploads
 * tidak bisa ditulis — situs tetap jalan seperti biasa, cuma proteksi ini
 * yang tidak aktif (konsisten dengan filosofi "tidak pernah mematahkan
 * situs demi keamanan tambahan").
 *
 * @return void
 */
function wscanom_write_uploads_exec_deny() {
    $upload_dir = wp_upload_dir();
    if ( empty( $upload_dir['basedir'] ) || ! empty( $upload_dir['error'] ) ) {
        return;
    }

    $dir = rtrim( $upload_dir['basedir'], '/' );
    if ( ! is_dir( $dir ) || ! is_writable( $dir ) ) {
        return;
    }

    $htaccess = $dir . '/.htaccess';
    if ( ! file_exists( $htaccess ) ) {
        @file_put_contents( $htaccess, wscanom_exec_deny_htaccess_content() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_put_contents
    }

    $nginx_note = $dir . '/wscanom-nginx-note.txt';
    if ( ! file_exists( $nginx_note ) ) {
        @file_put_contents( $nginx_note, wscanom_exec_deny_nginx_note_content() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_put_contents
    }
}
// Diperiksa ulang tiap scan terjadwal (idempoten — cuma menulis kalau belum
// ada) untuk berjaga-jaga kalau folder uploads belum ada saat aktivasi,
// atau .htaccess-nya terhapus migrasi/backup restore. Pemasangan pertama
// sendiri dipicu langsung saat aktivasi lewat register_activation_hook di
// wscanom.php (lihat wscanom_on_activate()).
add_action( WSCANOM_CRON_HOOK, 'wscanom_write_uploads_exec_deny', 1 );

// ============================================================
// 2b. VERIFIKASI NYATA: APAKAH LARANGAN EKSEKUSI DI ATAS BENAR-BENAR
// BERFUNGSI DI SERVER INI?
//
// Menulis .htaccess (di atas) TIDAK SAMA DENGAN membuktikan file itu
// benar-benar dihormati server — di nginx, .htaccess tidak pernah dibaca
// sama sekali; di Apache dengan "AllowOverride None", file itu juga
// diam-diam diabaikan. Kedua kasus itu membuat proteksi terlihat
// "terpasang" (filenya ADA) padahal nol efek sungguhan. Fungsi-fungsi di
// bawah ini menutup celah itu dengan benar-benar MENCOBA menjalankan file
// PHP probe lewat HTTP sungguhan (bukan cuma mengasumsikan dari keberadaan
// file), dan HANYA melaporkan "aman" kalau percobaan itu sungguh gagal.
// ============================================================

define( 'WSCANOM_EXEC_DENY_PROBE_TRANSIENT', 'wscanom_exec_deny_probe' );
define( 'WSCANOM_EXEC_DENY_PROBE_CACHE_SECONDS', 12 * HOUR_IN_SECONDS );

/**
 * Jalankan satu kali uji coba NYATA: tulis file PHP kecil berisi penanda
 * acak ke folder uploads, minta server menjalankannya lewat HTTP (loopback
 * ke situs sendiri), lalu periksa apakah penanda itu muncul di respons.
 * Muncul = file benar-benar TEREKSEKUSI/TERBACA oleh pengunjung web =
 * proteksi TIDAK berfungsi, apa pun isi .htaccess-nya. File probe SELALU
 * dihapus di akhir, apa pun hasilnya (lewat blok finally) — probe ini
 * tidak boleh pernah tertinggal di folder uploads.
 *
 * @return array{status:string,detail:string,checked_at:int} status: 'verified_blocked'|'not_blocked'|'inconclusive'.
 */
function wscanom_run_exec_deny_probe() {
    $now        = time();
    $upload_dir = wp_upload_dir();

    if ( empty( $upload_dir['basedir'] ) || ! empty( $upload_dir['error'] ) || empty( $upload_dir['baseurl'] ) ) {
        return array(
            'status'     => 'inconclusive',
            'detail'     => __( 'Tidak bisa diperiksa: informasi folder uploads tidak terbaca.', 'wscanom' ),
            'checked_at' => $now,
        );
    }

    $dir = rtrim( $upload_dir['basedir'], '/' );
    if ( ! is_dir( $dir ) || ! is_writable( $dir ) ) {
        return array(
            'status'     => 'inconclusive',
            'detail'     => __( 'Tidak bisa diperiksa: folder uploads tidak bisa ditulis untuk uji coba sementara.', 'wscanom' ),
            'checked_at' => $now,
        );
    }

    // Nama file DAN penanda isi keduanya acak per percobaan — supaya tidak
    // bisa ditebak/diputar ulang dari luar, dan supaya penanda yang
    // ditemukan di respons benar-benar berasal dari percobaan KALI INI.
    $marker   = 'wscanom_probe_' . wp_generate_password( 24, false, false );
    $filename = 'wscanom-probe-' . wp_generate_password( 12, false, false ) . '.php';
    $path     = $dir . '/' . $filename;
    $url      = rtrim( $upload_dir['baseurl'], '/' ) . '/' . $filename;

    $written = @file_put_contents( $path, "<?php echo '{$marker}'; // Probe WScanom, aman dihapus otomatis.\n" ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_put_contents

    if ( false === $written ) {
        return array(
            'status'     => 'inconclusive',
            'detail'     => __( 'Tidak bisa diperiksa: gagal menulis file uji coba ke folder uploads.', 'wscanom' ),
            'checked_at' => $now,
        );
    }

    try {
        $response = wp_remote_get(
            $url,
            array(
                'timeout'   => 8,
                // Loopback ke situs sendiri — sertifikat lokal/self-signed
                // di lingkungan staging TIDAK BOLEH menggagalkan uji coba
                // keamanan ini dengan kesalahan SSL yang tidak relevan.
                'sslverify' => false,
            )
        );

        if ( is_wp_error( $response ) ) {
            return array(
                'status'     => 'inconclusive',
                'detail'     => sprintf(
                    /* translators: %s: pesan error */
                    __( 'Tidak bisa diperiksa: permintaan uji coba ke situs sendiri gagal (%s). Situs ini kemungkinan tidak bisa mengakses dirinya sendiri lewat HTTP (loopback diblokir firewall/hosting) — ini BUKAN berarti proteksinya gagal, cuma tidak bisa diverifikasi otomatis dari sini.', 'wscanom' ),
                    $response->get_error_message()
                ),
                'checked_at' => $now,
            );
        }

        $body = (string) wp_remote_retrieve_body( $response );
        $code = (int) wp_remote_retrieve_response_code( $response );

        if ( false !== strpos( $body, $marker ) ) {
            return array(
                'status'     => 'not_blocked',
                'detail'     => __( 'PENTING: file PHP di folder uploads BISA diakses/dijalankan lewat web — penanda uji coba muncul di respons server. Proteksi .htaccess tidak (atau belum) berfungsi di server ini. Penyebab paling umum: server memakai nginx (.htaccess tidak pernah dibaca nginx sama sekali — lihat wscanom-nginx-note.txt di folder uploads untuk konfigurasi penggantinya), atau hosting mengabaikan .htaccess lewat "AllowOverride None".', 'wscanom' ),
                'checked_at' => $now,
            );
        }

        return array(
            'status'     => 'verified_blocked',
            'detail'     => sprintf(
                /* translators: %d: kode status HTTP respons */
                __( 'Terverifikasi lewat percobaan nyata: file PHP uji coba di folder uploads berhasil DITOLAK server (kode HTTP %d), bukan cuma diasumsikan dari keberadaan file .htaccess.', 'wscanom' ),
                $code
            ),
            'checked_at' => $now,
        );
    } finally {
        // Jaminan pembersihan: berlaku pada SEMUA jalur keluar di atas
        // (termasuk kalau terjadi error tak terduga sebelum fungsi sempat
        // return secara normal) — file probe tidak boleh pernah tertinggal.
        @unlink( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
    }
}

/**
 * Ambil hasil uji coba exec-deny, dari cache (12 jam) kalau ada supaya
 * TIDAK memicu permintaan HTTP baru di setiap buka halaman admin WScanom —
 * atau paksa uji coba baru lewat tombol "Uji Sekarang" di UI.
 *
 * @param bool $force Lewati cache dan jalankan uji coba baru.
 * @return array{status:string,detail:string,checked_at:int}
 */
function wscanom_get_exec_deny_probe_result( $force = false ) {
    if ( ! $force ) {
        $cached = get_transient( WSCANOM_EXEC_DENY_PROBE_TRANSIENT );
        if ( is_array( $cached ) && isset( $cached['status'] ) ) {
            return $cached;
        }
    }

    $result = wscanom_run_exec_deny_probe();
    set_transient( WSCANOM_EXEC_DENY_PROBE_TRANSIENT, $result, WSCANOM_EXEC_DENY_PROBE_CACHE_SECONDS );

    return $result;
}

// ============================================================
// 3. SCAN SEKETIKA SAAT PLUGIN/TEMA BERUBAH + AUTO-KARANTINA
// ============================================================

/**
 * Bobot tertinggi dari seluruh temuan pada satu file. Dipakai sebagai
 * gerbang auto-karantina yang lebih ketat daripada skor total gabungan:
 * skor total bisa mencapai ambang hanya dari tumpukan beberapa pola
 * berbobot rendah-menengah (lebih rawan false positive gabungan), sedangkan
 * ambang berbasis bobot-tunggal-tertinggi memastikan tindakan OTOMATIS
 * hanya terjadi kalau ADA SATU pola yang sendirian sudah sangat meyakinkan
 * (mis. eval(base64_decode) berbobot 10).
 *
 * @param array $findings Daftar temuan dari wscanom_scan_file().
 * @return int
 */
function wscanom_findings_max_weight( $findings ) {
    $max = 0;
    foreach ( $findings as $finding ) {
        if ( isset( $finding['bobot'] ) && $finding['bobot'] > $max ) {
            $max = (int) $finding['bobot'];
        }
    }
    return $max;
}

/**
 * Pindai semua file .php di bawah satu subfolder relatif terhadap base dir
 * (mis. "plugins/nama-plugin"), lalu tangani hasilnya: email alert untuk
 * temuan di atas ambang, dan auto-karantina untuk temuan yang sangat
 * meyakinkan (kalau fitur itu aktif).
 *
 * Dipanggil seketika setelah plugin/tema berubah — sengaja TIDAK memindai
 * seluruh situs (itu tugas scan terjadwal/manual), hanya folder yang baru
 * saja berubah, supaya ringan dan responsif.
 *
 * @param string $relative_subdir Path relatif terhadap base dir, mis. "plugins/foo" atau "themes/bar".
 * @return void
 */
function wscanom_scan_changed_subdir( $relative_subdir ) {
    // Pertahanan berlapis: $relative_subdir datang dari data upgrader WP
    // (nama slug plugin/tema) yang NORMALNYA sudah disaring oleh WordPress
    // core sendiri, tapi fungsi ini tetap TIDAK BOLEH mempercayainya begitu
    // saja — ini salah satu dari sedikit jalur di plugin ini yang bisa
    // berujung pada tindakan DESTRUKTIF (auto-karantina memindah/menghapus
    // file). Saring segmen ".."/"." dulu (sama seperti ajax.php), baru nanti
    // divalidasi ulang dengan realpath() di bawah sebelum dipakai.
    $relative_subdir = wscanom_sanitize_relative_path( $relative_subdir );
    if ( '' === $relative_subdir ) {
        return;
    }

    $base       = wscanom_scan_base_dir();
    $target_dir = rtrim( $base, '/' ) . '/' . $relative_subdir;

    // Validasi akhir: path HASIL GABUNGAN harus tetap di dalam base dir,
    // dicek lewat realpath() (bukan cuma pencocokan string) persis seperti
    // wscanom_resolve_within_base() di ajax.php. Dicek untuk KEDUA bentuk
    // yang mungkin dipakai di bawah (folder, atau "folder.php" untuk kasus
    // plugin satu-file) — bukan cuma salah satu — supaya tidak ada jalur
    // yang lolos tanpa diperiksa. Kalau target belum ada di disk sama sekali
    // (realpath() = false), fungsi berhenti dengan aman lewat pengecekan
    // is_dir()/is_file() di bawah seperti biasa, bukan dianggap "lolos".
    $real_base = realpath( $base );
    if ( ! $real_base ) {
        return;
    }
    $is_within_base = function ( $path ) use ( $real_base ) {
        $real = realpath( $path );
        return $real && 0 === strpos( $real, $real_base );
    };

    $settings = wscanom_get_settings();
    $alerts   = array();

    if ( is_dir( $target_dir ) && $is_within_base( $target_dir ) ) {
        // Folder (kasus umum): pindai semua .php di bawahnya.
        $files = wscanom_list_php_files( $target_dir );
        foreach ( $files as $leaf ) {
            wscanom_process_fast_scan_target( $relative_subdir . '/' . $leaf, $target_dir . '/' . $leaf, $settings, $alerts );
        }
    } elseif ( is_file( $target_dir . '.php' ) && $is_within_base( $target_dir . '.php' ) ) {
        // Kasus plugin satu-file tanpa subfolder (mis. "hello.php" langsung
        // di wp-content/plugins/), $relative_subdir di sini sudah berupa
        // nama file tanpa ekstensi dari pemanggil.
        wscanom_process_fast_scan_target( $relative_subdir . '.php', $target_dir . '.php', $settings, $alerts );
    }

    if ( ! empty( $alerts ) ) {
        wscanom_send_fast_alert( $alerts );
    }
}

/**
 * Proses satu file hasil scan cepat: kumpulkan untuk alert kalau di atas
 * ambang, dan auto-karantina kalau sangat meyakinkan.
 *
 * @param string $relative_path Path relatif terhadap base dir.
 * @param string $full_path     Path absolut.
 * @param array  $settings      Pengaturan plugin saat ini.
 * @param array  $alerts        Dikumpulkan secara by-reference untuk dikirim lewat email.
 * @return void
 */
function wscanom_process_fast_scan_target( $relative_path, $full_path, $settings, array &$alerts ) {
    $scan = wscanom_scan_file( $full_path, $relative_path );

    if ( 0 === $scan['score'] || $scan['whitelisted'] ) {
        return;
    }

    if ( $scan['score'] >= (int) $settings['alert_min_score'] ) {
        $alerts[] = array(
            'file'  => $relative_path,
            'score' => $scan['score'],
        );
    }

    if ( ! empty( $settings['auto_quarantine'] ) ) {
        $max_weight = wscanom_findings_max_weight( $scan['findings'] );
        if ( $max_weight >= (int) $settings['auto_quarantine_min_weight'] ) {
            $result = wscanom_quarantine_file( $full_path, $relative_path );
            if ( ! is_wp_error( $result ) ) {
                $log               = wscanom_get_quarantine_log();
                if ( isset( $log[ $result ] ) ) {
                    $log[ $result ]['auto']   = true;
                    $log[ $result ]['reason'] = wp_list_pluck( $scan['findings'], 'catatan' );
                    update_option( WSCANOM_QUARANTINE_LOG_OPTION, $log, false );
                }
            }
        }
    }
}

/**
 * Kirim email alert "cepat" terpisah dari alert scan terjadwal biasa,
 * supaya jelas konteksnya ini dipicu perubahan plugin/tema, bukan jadwal
 * harian.
 *
 * @param array $alerts Daftar [file, score].
 * @return void
 */
function wscanom_send_fast_alert( array $alerts ) {
    $settings = wscanom_get_settings();
    if ( empty( $settings['email_alerts'] ) ) {
        return;
    }

    $admin_email = get_option( 'admin_email' );
    $site_name   = get_bloginfo( 'name' );
    $scan_url    = admin_url( 'tools.php?page=wscanom' );

    $lines   = array();
    $lines[] = sprintf(
        /* translators: %s: nama situs */
        __( 'WScanom menemukan file mencurigakan segera setelah ada plugin/tema yang diinstall/diaktifkan/diupdate di situs %s.', 'wscanom' ),
        $site_name
    );
    $lines[] = '';
    foreach ( $alerts as $row ) {
        $lines[] = sprintf( '[%d] %s', $row['score'], $row['file'] );
    }
    $lines[] = '';
    $lines[] = sprintf(
        /* translators: %s: tautan ke halaman scanner */
        __( 'Buka halaman WScanom untuk detail dan tindak lanjut: %s', 'wscanom' ),
        $scan_url
    );

    wp_mail(
        $admin_email,
        sprintf(
            /* translators: %s: nama situs */
            __( '[%s] WScanom: file mencurigakan terdeteksi segera setelah perubahan plugin/tema', 'wscanom' ),
            $site_name
        ),
        implode( "\n", $lines )
    );
}

/**
 * Tangani event upgrader selesai (install BARU atau UPDATE), untuk plugin
 * maupun tema. Ini jalur paling penting untuk menangkap plugin "nulled"
 * yang sudah bawa backdoor sejak awal — dipindai detik itu juga, bukan
 * menunggu jadwal cron berikutnya.
 *
 * @param WP_Upgrader $upgrader   Instance upgrader (tidak dipakai langsung, demi kompatibilitas signature hook).
 * @param array       $hook_extra Detail proses: action, type, plugin(s)/theme(s).
 * @return void
 */
function wscanom_on_upgrader_process_complete( $upgrader, $hook_extra ) {
    if ( empty( $hook_extra['type'] ) || ! in_array( $hook_extra['type'], array( 'plugin', 'theme' ), true ) ) {
        return;
    }

    $is_plugin = 'plugin' === $hook_extra['type'];
    $base_sub  = $is_plugin ? 'plugins' : 'themes';

    if ( 'install' === ( $hook_extra['action'] ?? '' ) ) {
        // Instalasi baru: nama folder tujuan ada di hasil upgrader.
        $slug = '';
        if ( is_object( $upgrader ) && isset( $upgrader->result['destination_name'] ) ) {
            $slug = $upgrader->result['destination_name'];
        }
        if ( '' !== $slug ) {
            wscanom_scan_changed_subdir( $base_sub . '/' . $slug );
        }
        return;
    }

    // Update (satu atau beberapa sekaligus, "bulk update").
    $items = array();
    if ( $is_plugin ) {
        if ( ! empty( $hook_extra['plugins'] ) ) {
            $items = (array) $hook_extra['plugins'];
        } elseif ( ! empty( $hook_extra['plugin'] ) ) {
            $items = array( $hook_extra['plugin'] );
        }
        foreach ( $items as $plugin_file ) {
            $slug = dirname( $plugin_file );
            if ( '.' === $slug ) {
                // Plugin satu-file tanpa subfolder sendiri.
                wscanom_scan_changed_subdir( $base_sub . '/' . basename( $plugin_file, '.php' ) );
            } else {
                wscanom_scan_changed_subdir( $base_sub . '/' . $slug );
            }
        }
    } else {
        if ( ! empty( $hook_extra['themes'] ) ) {
            $items = (array) $hook_extra['themes'];
        } elseif ( ! empty( $hook_extra['theme'] ) ) {
            $items = array( $hook_extra['theme'] );
        }
        foreach ( $items as $stylesheet ) {
            wscanom_scan_changed_subdir( $base_sub . '/' . $stylesheet );
        }
    }
}
add_action( 'upgrader_process_complete', 'wscanom_on_upgrader_process_complete', 10, 2 );

/**
 * Tangani aktivasi plugin. Perlu dicek terpisah dari 'upgrader_process_complete'
 * karena plugin bisa saja sampai di disk BUKAN lewat proses install/update
 * WordPress sama sekali (mis. diunggah manual lewat FTP/file manager lalu
 * diaktifkan dari dashboard) — jalur itu tidak pernah memicu event upgrader.
 *
 * @param string $plugin       Path plugin relatif terhadap folder plugins, "folder/file.php".
 * @param bool   $network_wide Diabaikan, demi kompatibilitas signature hook.
 * @return void
 */
function wscanom_on_plugin_activated( $plugin, $network_wide = false ) {
    unset( $network_wide );
    $slug = dirname( $plugin );
    if ( '.' === $slug ) {
        wscanom_scan_changed_subdir( 'plugins/' . basename( $plugin, '.php' ) );
    } else {
        wscanom_scan_changed_subdir( 'plugins/' . $slug );
    }
}
add_action( 'activated_plugin', 'wscanom_on_plugin_activated', 10, 2 );

/**
 * Tangani pergantian tema aktif — alasan sama seperti aktivasi plugin:
 * tema bisa sampai di disk lewat jalur di luar upgrader WordPress.
 *
 * @param string   $new_name  Nama tema baru (tidak dipakai langsung).
 * @param WP_Theme $new_theme Objek tema baru.
 * @return void
 */
function wscanom_on_theme_switched( $new_name, $new_theme ) {
    unset( $new_name );
    if ( is_object( $new_theme ) && method_exists( $new_theme, 'get_stylesheet' ) ) {
        wscanom_scan_changed_subdir( 'themes/' . $new_theme->get_stylesheet() );
    }
}
add_action( 'switch_theme', 'wscanom_on_theme_switched', 10, 2 );
