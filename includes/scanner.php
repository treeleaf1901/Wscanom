<?php
/**
 * WScanom — Mesin pemindaian file dan pengelolaan whitelist.
 *
 * @package WScanom
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Direktori dasar yang dipindai untuk situs saat ini.
 * Dipisah dari WP_CONTENT_DIR supaya mudah diuji dan di-override saat perlu.
 *
 * @return string
 */
function wscanom_scan_base_dir() {
    return apply_filters( 'wscanom_scan_base_dir', WP_CONTENT_DIR );
}

/**
 * Folder plugin ini sendiri (dilewati saat scan supaya tidak mendeteksi
 * dirinya sendiri — kode sumbernya memang berisi teks pola seperti nama
 * fungsi malware yang dicari).
 *
 * @return string Path absolut dengan trailing slash, atau '' jika gagal resolve.
 */
function wscanom_self_dir() {
    $real = realpath( dirname( __DIR__ ) );
    return $real ? str_replace( '\\', '/', $real ) . '/' : '';
}

/**
 * Daftar semua path file .php (relatif terhadap base dir) di bawah base dir.
 * Dipakai untuk membangun antrian scan bertahap (AJAX, biar tidak timeout
 * di situs dengan banyak file).
 *
 * @param string $base_dir Direktori dasar absolut.
 * Daftar ekstensi yang dianggap "kode PHP" untuk tujuan scan DAN exec-deny
 * (satu sumber kebenaran dipakai bersama oleh wscanom_list_php_files() di
 * file ini dan aturan .htaccess di includes/hardening.php, supaya dua
 * lapisan itu tidak pernah "menyimpang" satu sama lain lagi).
 *
 * Mencakup bukan cuma ".php", tapi juga varian historis/alternatif yang
 * sampai sekarang masih dikenali sebagai handler PHP oleh sebagian
 * konfigurasi Apache/LiteSpeed (AddHandler/AddType yang longgar) — webshell
 * yang di-upload dengan ekstensi ini akan tetap BISA DIEKSEKUSI di server
 * semacam itu walau WordPress sendiri tidak pernah menganggapnya ".php".
 * Scanner yang cuma mencari literal ".php" akan melewatkan semuanya ini
 * total, tidak peduli seberapa jelas pola backdoor di isinya.
 *
 * @return string[] Daftar ekstensi huruf kecil, tanpa titik di depan.
 */
function wscanom_scannable_extensions() {
    return apply_filters(
        'wscanom_scannable_extensions',
        array( 'php', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8', 'phtml', 'pht', 'phar', 'phps', 'inc' )
    );
}

/**
 * @return string[] Daftar path relatif, menggunakan '/' sebagai pemisah.
 */
function wscanom_list_php_files( $base_dir ) {
    $base_dir      = rtrim( str_replace( '\\', '/', $base_dir ), '/' );
    $self_dir      = wscanom_self_dir();
    $quarantine_dir = str_replace( '\\', '/', $base_dir . '/wscanom-quarantine/' );
    $files         = array();

    if ( ! is_dir( $base_dir ) ) {
        return $files;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator( $base_dir, FilesystemIterator::SKIP_DOTS ),
        RecursiveIteratorIterator::LEAVES_ONLY
    );

    $extensions = wscanom_scannable_extensions();

    foreach ( $iterator as $file ) {
        if ( ! $file->isFile() || ! in_array( strtolower( $file->getExtension() ), $extensions, true ) ) {
            continue;
        }

        $real = $file->getRealPath();
        $path = $real ? str_replace( '\\', '/', $real ) : str_replace( '\\', '/', $file->getPathname() );

        if ( $self_dir && 0 === strpos( $path, $self_dir ) ) {
            continue; // lewati folder plugin ini sendiri.
        }

        if ( 0 === strpos( $path, $quarantine_dir ) ) {
            continue; // lewati folder karantina milik plugin ini sendiri (mis. index.php penjaganya).
        }

        $relative = ltrim( str_replace( $base_dir, '', $path ), '/' );
        if ( '' !== $relative ) {
            $files[] = $relative;
        }
    }

    return $files;
}

/**
 * Baca isi file lewat WP_Filesystem bila tersedia, jatuh ke file_get_contents
 * sebagai cadangan (mis. saat dipanggil dari konteks WP-Cron yang belum
 * tentu menginisialisasi WP_Filesystem).
 *
 * @param string $path Path absolut.
 * @return string|false
 */
function wscanom_read_file( $path ) {
    global $wp_filesystem;

    if ( $wp_filesystem instanceof WP_Filesystem_Base ) {
        $content = $wp_filesystem->get_contents( $path );
        if ( false !== $content ) {
            return $content;
        }
    }

    return @file_get_contents( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
}

/**
 * Hash SHA-256 isi file, dipakai untuk whitelist dan riwayat scan.
 *
 * @param string $content Isi file.
 * @return string
 */
function wscanom_hash_content( $content ) {
    return hash( 'sha256', $content );
}

/**
 * Memindai satu file terhadap seluruh pola yang terdaftar.
 *
 * @param string $full_path     Path absolut file.
 * @param string $relative_path Path relatif terhadap base dir (untuk pelaporan & whitelist).
 * @return array{score:int,findings:array<int,array{name:string,bobot:int,catatan:string}>,hash:string|null,whitelisted:bool}
 */
function wscanom_scan_file( $full_path, $relative_path ) {
    $content = wscanom_read_file( $full_path );

    if ( false === $content || null === $content ) {
        return array(
            'score'       => 0,
            'findings'    => array(),
            'hash'        => null,
            'whitelisted' => false,
        );
    }

    $hash = wscanom_hash_content( $content );

    if ( wscanom_is_whitelisted( $relative_path, $hash ) ) {
        return array(
            'score'       => 0,
            'findings'    => array(),
            'hash'        => $hash,
            'whitelisted' => true,
        );
    }

    $score    = 0;
    $findings = array();

    foreach ( wscanom_get_patterns() as $name => $info ) {
        if ( '' === $info['regex'] ) {
            continue;
        }
        if ( @preg_match( $info['regex'], $content ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
            $score     += $info['bobot'];
            $findings[] = array(
                'name'    => $name,
                'bobot'   => $info['bobot'],
                'catatan' => $info['catatan'],
            );
        }
    }

    $basename = basename( $relative_path );
    foreach ( wscanom_suspicious_filenames() as $pattern ) {
        if ( preg_match( $pattern, $basename ) ) {
            $score     += 7;
            $findings[] = array(
                'name'    => 'nama_file_mencurigakan',
                'bobot'   => 7,
                /* translators: %s: nama file */
                'catatan' => sprintf( __( 'nama file mencurigakan: %s', 'wscanom' ), $basename ),
            );
            break;
        }
    }

    if ( 0 === strpos( $relative_path, 'uploads/' ) ) {
        $score     += 8;
        $findings[] = array(
            'name'    => 'php_di_folder_upload',
            'bobot'   => 8,
            'catatan' => __( 'file .php ditemukan di folder uploads, seharusnya hanya berisi media', 'wscanom' ),
        );
    }

    return array(
        'score'       => $score,
        'findings'    => $findings,
        'hash'        => $hash,
        'whitelisted' => false,
    );
}

// ============================================================
// WHITELIST
// Disimpan per-situs (option biasa, otomatis per-blog di multisite
// karena switch_to_blog() mengganti konteks options).
// Entri disimpan sebagai [ relative_path => sha256_hash ], sehingga
// kalau file yang sama diubah isinya, whitelist lama tidak lagi berlaku
// (mencegah file whitelist "ditumpangi" backdoor baru).
// ============================================================

define( 'WSCANOM_WHITELIST_OPTION', 'wscanom_whitelist' );

/**
 * Ambil seluruh entri whitelist situs saat ini.
 *
 * @return array<string,string> relative_path => hash
 */
function wscanom_get_whitelist() {
    $list = get_option( WSCANOM_WHITELIST_OPTION, array() );
    return is_array( $list ) ? $list : array();
}

/**
 * Apakah file (berdasarkan path relatif + hash isi) ada di whitelist.
 *
 * @param string $relative_path Path relatif.
 * @param string $hash          Hash SHA-256 isi file saat ini.
 * @return bool
 */
function wscanom_is_whitelisted( $relative_path, $hash ) {
    $list = wscanom_get_whitelist();
    return isset( $list[ $relative_path ] ) && hash_equals( $list[ $relative_path ], $hash );
}

/**
 * Tambahkan file ke whitelist situs saat ini.
 *
 * @param string $relative_path Path relatif.
 * @param string $hash          Hash SHA-256 isi file saat ini.
 * @return void
 */
function wscanom_add_to_whitelist( $relative_path, $hash ) {
    $list                   = wscanom_get_whitelist();
    $list[ $relative_path ] = $hash;
    update_option( WSCANOM_WHITELIST_OPTION, $list, false );
}

/**
 * Hapus file dari whitelist situs saat ini.
 *
 * @param string $relative_path Path relatif.
 * @return void
 */
function wscanom_remove_from_whitelist( $relative_path ) {
    $list = wscanom_get_whitelist();
    unset( $list[ $relative_path ] );
    update_option( WSCANOM_WHITELIST_OPTION, $list, false );
}

// ============================================================
// KARANTINA
// File yang dikarantina DIPINDAH (bukan dihapus permanen) ke folder
// wp-content/wscanom-quarantine/, diganti ekstensinya jadi .suspected
// supaya tidak bisa dieksekusi PHP walau ada misconfig server, dan
// dicatat di log supaya bisa dipulihkan kalau ternyata salah tuduh.
// ============================================================

define( 'WSCANOM_QUARANTINE_LOG_OPTION', 'wscanom_quarantine_log' );

/**
 * Path folder karantina untuk situs saat ini. Dibuat otomatis (beserta
 * perlindungan dari eksekusi web) saat pertama kali dipakai.
 *
 * @return string|false Path absolut, atau false kalau gagal dibuat.
 */
function wscanom_quarantine_dir() {
    $dir = rtrim( wscanom_scan_base_dir(), '/' ) . '/wscanom-quarantine';

    if ( ! is_dir( $dir ) ) {
        if ( ! wp_mkdir_p( $dir ) ) {
            return false;
        }
    }

    // Index kosong supaya directory listing tidak membocorkan nama file asli.
    $index = $dir . '/index.php';
    if ( ! file_exists( $index ) ) {
        @file_put_contents( $index, "<?php\n// Silence is golden.\n" ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_put_contents
    }

    // Tolak akses langsung lewat web di server Apache. Ini lapis tambahan;
    // lapis utama tetap ekstensi .suspected (bukan .php) pada tiap file.
    $htaccess = $dir . '/.htaccess';
    if ( ! file_exists( $htaccess ) ) {
        @file_put_contents( $htaccess, "Require all denied\nDeny from all\n" ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_put_contents
    }

    return $dir;
}

/**
 * Ambil seluruh log karantina situs saat ini.
 *
 * @return array<string,array> id => entry
 */
function wscanom_get_quarantine_log() {
    $log = get_option( WSCANOM_QUARANTINE_LOG_OPTION, array() );
    return is_array( $log ) ? $log : array();
}

/**
 * Pindahkan satu file ke karantina.
 *
 * @param string $full_path     Path absolut file (sudah divalidasi berada di dalam base dir oleh pemanggil).
 * @param string $relative_path Path relatif terhadap base dir, dipakai untuk memulihkan nanti.
 * @return string|WP_Error ID entri karantina jika berhasil, WP_Error jika gagal.
 */
function wscanom_quarantine_file( $full_path, $relative_path ) {
    if ( ! file_exists( $full_path ) ) {
        return new WP_Error( 'wscanom_not_found', __( 'File tidak ditemukan, mungkin sudah dipindahkan sebelumnya.', 'wscanom' ) );
    }

    $content = wscanom_read_file( $full_path );
    if ( false === $content || null === $content ) {
        return new WP_Error( 'wscanom_read_failed', __( 'Gagal membaca isi file.', 'wscanom' ) );
    }

    $dir = wscanom_quarantine_dir();
    if ( ! $dir ) {
        return new WP_Error( 'wscanom_quarantine_dir_failed', __( 'Gagal membuat folder karantina. Cek izin tulis pada wp-content.', 'wscanom' ) );
    }

    $id     = wp_generate_password( 20, false, false );
    $target = $dir . '/' . $id . '.suspected';

    global $wp_filesystem;
    $written = ( $wp_filesystem instanceof WP_Filesystem_Base )
        ? $wp_filesystem->put_contents( $target, $content, FS_CHMOD_FILE )
        : ( false !== @file_put_contents( $target, $content ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_put_contents

    if ( ! $written ) {
        return new WP_Error( 'wscanom_write_failed', __( 'Gagal menulis file ke folder karantina.', 'wscanom' ) );
    }

    $deleted = ( $wp_filesystem instanceof WP_Filesystem_Base )
        ? $wp_filesystem->delete( $full_path )
        : @unlink( $full_path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

    if ( ! $deleted ) {
        // Tulisan ke karantina berhasil, tapi file asli gagal dihapus.
        // Hapus salinan karantina supaya tidak ada file dobel yang membingungkan.
        @unlink( $target ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
        return new WP_Error( 'wscanom_delete_failed', __( 'Gagal menghapus file asli (periksa izin tulis), karantina dibatalkan.', 'wscanom' ) );
    }

    $log         = wscanom_get_quarantine_log();
    $log[ $id ]  = array(
        'original_path' => $relative_path,
        'time'          => time(),
        'hash'          => wscanom_hash_content( $content ),
    );
    update_option( WSCANOM_QUARANTINE_LOG_OPTION, $log, false );

    return $id;
}

/**
 * Pulihkan file dari karantina ke lokasi aslinya.
 *
 * @param string $id ID entri karantina.
 * @return true|WP_Error
 */
function wscanom_restore_quarantined( $id ) {
    $log = wscanom_get_quarantine_log();

    if ( ! isset( $log[ $id ] ) ) {
        return new WP_Error( 'wscanom_not_found', __( 'Entri karantina tidak ditemukan.', 'wscanom' ) );
    }

    $dir    = wscanom_quarantine_dir();
    $source = $dir . '/' . $id . '.suspected';

    if ( ! file_exists( $source ) ) {
        unset( $log[ $id ] );
        update_option( WSCANOM_QUARANTINE_LOG_OPTION, $log, false );
        return new WP_Error( 'wscanom_source_missing', __( 'File karantina tidak ditemukan di disk (mungkin sudah dipindahkan manual).', 'wscanom' ) );
    }

    $is_root_backup = isset( $log[ $id ]['type'] ) && 'root_backup' === $log[ $id ]['type'];

    if ( $is_root_backup ) {
        // Backup file sentinel root: pulihkan ke path aslinya di ABSPATH,
        // bukan ke wp-content, dan ini MENIMPA file yang sudah dibersihkan
        // dengan isi lengkap sebelum dibersihkan (termasuk blok yang dibuang).
        $target = wscanom_resolve_root_sentinel( $log[ $id ]['original_path'] );
        if ( ! $target ) {
            // File sentinel aslinya sudah tidak ada/berubah nama; tetap coba
            // tulis ke lokasi yang diharapkan berdasarkan nama filenya.
            $name   = substr( $log[ $id ]['original_path'], strlen( '(root)/' ) );
            $target = wscanom_abspath() . '/' . $name;
        }
    } else {
        $base   = wscanom_scan_base_dir();
        $target = $base . '/' . $log[ $id ]['original_path'];
    }

    global $wp_filesystem;
    $content = wscanom_read_file( $source );
    if ( false === $content || null === $content ) {
        return new WP_Error( 'wscanom_read_failed', __( 'Gagal membaca file karantina.', 'wscanom' ) );
    }

    wp_mkdir_p( dirname( $target ) );

    $written = ( $wp_filesystem instanceof WP_Filesystem_Base )
        ? $wp_filesystem->put_contents( $target, $content, FS_CHMOD_FILE )
        : ( false !== @file_put_contents( $target, $content ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_put_contents

    if ( ! $written ) {
        return new WP_Error( 'wscanom_write_failed', __( 'Gagal menulis file ke lokasi asal.', 'wscanom' ) );
    }

    @unlink( $source ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
    unset( $log[ $id ] );
    update_option( WSCANOM_QUARANTINE_LOG_OPTION, $log, false );

    return true;
}

// ============================================================
// FILE SENTINEL DI ROOT
// Backdoor yang menyebar sendiri (self-replicating) sering menyuntik
// wp-config.php, index.php, dan file bootstrap lain di root WordPress,
// bukan cuma wp-content. File-file ini TIDAK BISA dikarantina (situs
// butuh file itu buat jalan), jadi ditangani beda: cuma blok yang
// disuntikkan yang dibuang, sisanya dibiarkan utuh.
// ============================================================

define( 'WSCANOM_ROOT_CLEANUP_LOG_OPTION', 'wscanom_root_cleanup_log' );

/**
 * Daftar nama file sentinel di root WordPress yang diperiksa.
 * Sengaja daftar pendek dan tetap (bukan scan seluruh core WordPress,
 * yang isinya ribuan file dan mayoritas resmi).
 *
 * @return string[]
 */
function wscanom_root_sentinel_filenames() {
    return array( 'index.php', 'wp-config.php', 'wp-load.php', 'wp-settings.php', 'wp-blog-header.php' );
}

/**
 * Path absolut root WordPress (induk dari wp-content).
 *
 * @return string
 */
function wscanom_abspath() {
    return defined( 'ABSPATH' ) ? rtrim( ABSPATH, '/' ) : dirname( wscanom_scan_base_dir() );
}

/**
 * Pindai file sentinel di root yang benar-benar ada.
 *
 * @return array<int,array{relative:string,full:string}>
 */
function wscanom_list_root_sentinel_files() {
    $root  = wscanom_abspath();
    $found = array();

    foreach ( wscanom_root_sentinel_filenames() as $name ) {
        $full = $root . '/' . $name;
        if ( file_exists( $full ) ) {
            $found[] = array(
                // Prefiks "(root)/" membedakan dari path relatif wp-content
                // di tabel hasil, dan dipakai sebagai penanda saat divalidasi lagi.
                'relative' => '(root)/' . $name,
                'full'     => $full,
            );
        }
    }

    return $found;
}

/**
 * Apakah path relatif menunjuk ke salah satu file sentinel root.
 *
 * @param string $relative_path Path relatif, format "(root)/nama-file".
 * @return string|false Path absolut jika valid & dikenal, false jika bukan.
 */
function wscanom_resolve_root_sentinel( $relative_path ) {
    if ( 0 !== strpos( $relative_path, '(root)/' ) ) {
        return false;
    }

    $name = substr( $relative_path, strlen( '(root)/' ) );
    if ( ! in_array( $name, wscanom_root_sentinel_filenames(), true ) ) {
        return false; // hanya nama yang terdaftar eksplisit yang diterima.
    }

    $full = wscanom_abspath() . '/' . $name;
    return file_exists( $full ) ? $full : false;
}

/**
 * Regex generik untuk blok "penanda" yang dipakai backdoor self-replicating
 * (format diamati pertama kali dari keluarga "WDG-CORE", tapi dibuat umum
 * lewat backreference supaya menangkap marker dengan nama lain juga).
 * Menyertakan pembungkus "?>\n<?php\n" yang umum ditambahkan backdoor saat
 * menyisipkan diri ke file yang sudah ditutup tag PHP-nya.
 *
 * @return string
 */
function wscanom_marker_block_regex() {
    return '/(?:\?>\s*\n<\?php\s*\n)?\/\*([A-Z0-9_-]{2,20})-CORE-START\*\/.*?\/\*\1-CORE-END\*\/\s*/s';
}

/**
 * Bersihkan blok tersuntik dari satu file sentinel, in-place (file tetap
 * di lokasi yang sama, hanya blok yang cocok pola marker yang dibuang).
 * Isi asli sebelum dibersihkan disimpan ke folder karantina dulu supaya
 * bisa dipulihkan penuh kalau ternyata keliru.
 *
 * @param string $full_path     Path absolut file (sudah divalidasi oleh pemanggil).
 * @param string $relative_path Path relatif format "(root)/nama-file", untuk log.
 * @return array{id:string,removed:int}|WP_Error
 */
function wscanom_strip_marker_blocks( $full_path, $relative_path ) {
    $content = wscanom_read_file( $full_path );
    if ( false === $content || null === $content ) {
        return new WP_Error( 'wscanom_read_failed', __( 'Gagal membaca isi file.', 'wscanom' ) );
    }

    $cleaned = preg_replace( wscanom_marker_block_regex(), '', $content, -1, $removed_count );

    if ( null === $cleaned ) {
        return new WP_Error( 'wscanom_regex_failed', __( 'Gagal memproses pola pembersihan.', 'wscanom' ) );
    }

    if ( 0 === $removed_count ) {
        return new WP_Error( 'wscanom_nothing_to_clean', __( 'Tidak ditemukan blok tersuntik yang cocok pola pada file ini.', 'wscanom' ) );
    }

    // Simpan isi ASLI (sebelum dibersihkan) ke karantina sebagai backup penuh,
    // supaya seluruh file (bukan cuma blok yang dibuang) bisa dipulihkan.
    $dir = wscanom_quarantine_dir();
    if ( ! $dir ) {
        return new WP_Error( 'wscanom_quarantine_dir_failed', __( 'Gagal membuat folder karantina untuk backup.', 'wscanom' ) );
    }

    $id          = wp_generate_password( 20, false, false );
    $backup_path = $dir . '/' . $id . '.suspected';

    global $wp_filesystem;
    $backed_up = ( $wp_filesystem instanceof WP_Filesystem_Base )
        ? $wp_filesystem->put_contents( $backup_path, $content, FS_CHMOD_FILE )
        : ( false !== @file_put_contents( $backup_path, $content ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_put_contents

    if ( ! $backed_up ) {
        return new WP_Error( 'wscanom_backup_failed', __( 'Gagal membuat backup sebelum membersihkan, dibatalkan demi keamanan.', 'wscanom' ) );
    }

    $written = ( $wp_filesystem instanceof WP_Filesystem_Base )
        ? $wp_filesystem->put_contents( $full_path, $cleaned, FS_CHMOD_FILE )
        : ( false !== @file_put_contents( $full_path, $cleaned ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_put_contents

    if ( ! $written ) {
        @unlink( $backup_path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
        return new WP_Error( 'wscanom_write_failed', __( 'Gagal menulis file yang sudah dibersihkan.', 'wscanom' ) );
    }

    $log        = wscanom_get_quarantine_log();
    $log[ $id ] = array(
        'original_path' => $relative_path,
        'time'           => time(),
        'hash'           => wscanom_hash_content( $content ),
        'type'           => 'root_backup', // beda dari entri karantina biasa: ini backup file utuh, bukan file yang dipindah.
    );
    update_option( WSCANOM_QUARANTINE_LOG_OPTION, $log, false );

    return array(
        'id'      => $id,
        'removed' => $removed_count,
    );
}
