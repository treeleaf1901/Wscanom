<?php
/**
 * WScanom — Proteksi login: pembatas percobaan brute-force, pengerasan
 * XML-RPC, dan aksi darurat (paksa reset password, logout semua user).
 *
 * Filosofi sama seperti includes/hardening.php: yang AMAN untuk semua situs
 * aktif otomatis (default ON), yang berisiko mematahkan fungsi situs kalau
 * salah pakai (mis. mematikan XML-RPC total bisa memutus Jetpack) masuk ke
 * tabel "Pengerasan Lanjutan" dan HARUS diaktifkan manual oleh admin — tidak
 * pernah otomatis, sesuai permintaan eksplisit: fitur berisiko dikustomisasi
 * sendiri oleh penggunanya, bukan ditebak oleh plugin.
 *
 * @package WScanom
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'WSCANOM_LOGIN_ATTEMPTS_PREFIX', 'wscanom_la_' );

// Lockout progresif: siklus lockout yang "diingat" paling lama 7 hari —
// serangan brute-force lama yang sudah berhenti tidak akan menghantui
// eskalasi lockout selamanya, tapi penyerang yang terus mencoba ulang dalam
// seminggu tetap kena durasi yang makin lama.
define( 'WSCANOM_PROGRESSIVE_LOCKOUT_CYCLE_WINDOW', 7 * DAY_IN_SECONDS );

// Pengganda durasi lockout maksimal (8x dari durasi dasar) DAN batas
// mutlak dalam menit (24 jam) — dua pengaman independen supaya kesalahan
// hitung atau setting dasar yang besar tidak pernah menghasilkan lockout
// yang "selamanya" secara tidak sengaja.
define( 'WSCANOM_PROGRESSIVE_LOCKOUT_MAX_MULTIPLIER', 8 );
define( 'WSCANOM_PROGRESSIVE_LOCKOUT_CAP_MINUTES', 1440 );

// ============================================================
// PEMBATAS PERCOBAAN LOGIN (BRUTE-FORCE)
// Default AKTIF — aman karena cuma menunda, bukan mengunci permanen, dan
// ambang defaultnya longgar (5x percobaan) supaya admin yang salah ketik
// password sendiri tidak langsung terkunci.
// ============================================================

/**
 * Kunci unik transient untuk satu kombinasi (IP, username yang dicoba).
 * Dipisah per-username (bukan cuma per-IP) supaya brute-force yang mencoba
 * banyak username dari satu IP tetap kena batas per akun yang diincar, dan
 * brute-force terdistribusi (banyak IP, satu username) tetap kena batas per
 * akun juga lewat kunci kedua di bawah.
 *
 * @param string $ip       Alamat IP.
 * @param string $username Username yang dicoba.
 * @return string
 */
function wscanom_login_attempt_key( $ip, $username ) {
    return WSCANOM_LOGIN_ATTEMPTS_PREFIX . md5( $ip . '|' . strtolower( $username ) );
}

/**
 * Kunci transient untuk melacak total percobaan ke SATU username, lintas IP
 * (melengkapi pembatas per-IP di atas — brute-force modern sering memakai
 * banyak IP/proxy berbeda untuk satu akun target).
 *
 * @param string $username Username yang dicoba.
 * @return string
 */
function wscanom_login_attempt_user_key( $username ) {
    return WSCANOM_LOGIN_ATTEMPTS_PREFIX . 'u_' . md5( strtolower( $username ) );
}

/**
 * Kunci transient yang menyimpan TIMESTAMP kapan lockout untuk kombinasi
 * (IP, username) ini berakhir — sumber kebenaran TUNGGAL untuk "apakah
 * sedang terkunci", terpisah sengaja dari penghitung percobaan di atas.
 * Pemisahan ini penting: penghitung percobaan punya masa hidup transient-nya
 * sendiri (bisa kadaluarsa duluan kalau lockout progresif membuat durasi
 * kunci lebih panjang dari jendela penghitung), jadi kalau status terkunci
 * ikut disimpulkan dari penghitung itu, lockout yang sudah diperpanjang bisa
 * "bocor" begitu penghitungnya kadaluarsa padahal seharusnya masih terkunci.
 *
 * @param string $ip       Alamat IP.
 * @param string $username Username yang dicoba.
 * @return string
 */
function wscanom_login_lockout_until_key( $ip, $username ) {
    return WSCANOM_LOGIN_ATTEMPTS_PREFIX . 'until_' . md5( $ip . '|' . strtolower( $username ) );
}

/**
 * Versi lintas-IP dari kunci timestamp lockout di atas, melengkapi
 * wscanom_login_attempt_user_key() dengan cara yang sama.
 *
 * @param string $username Username yang dicoba.
 * @return string
 */
function wscanom_login_lockout_until_user_key( $username ) {
    return WSCANOM_LOGIN_ATTEMPTS_PREFIX . 'until_u_' . md5( strtolower( $username ) );
}

/**
 * Kunci transient yang menghitung berapa KALI kombinasi (IP, username) ini
 * sudah kena siklus lockout penuh (bukan berapa kali salah password) —
 * dipakai HANYA kalau lockout progresif diaktifkan admin. Nilainya sengaja
 * disimpan terpisah dari penghitung percobaan biasa supaya bisa punya masa
 * hidup transient yang jauh lebih panjang (lihat
 * WSCANOM_PROGRESSIVE_LOCKOUT_CYCLE_WINDOW) tanpa ikut memperpanjang/
 * mereset jendela penghitung percobaan itu sendiri.
 *
 * @param string $ip       Alamat IP.
 * @param string $username Username yang dicoba.
 * @return string
 */
function wscanom_login_cycle_key( $ip, $username ) {
    return WSCANOM_LOGIN_ATTEMPTS_PREFIX . 'cycle_' . md5( $ip . '|' . strtolower( $username ) );
}

/**
 * Versi lintas-IP dari penghitung siklus lockout di atas.
 *
 * @param string $username Username yang dicoba.
 * @return string
 */
function wscanom_login_cycle_user_key( $username ) {
    return WSCANOM_LOGIN_ATTEMPTS_PREFIX . 'cycle_u_' . md5( strtolower( $username ) );
}

/**
 * Hitung durasi lockout (dalam menit) untuk siklus lockout ke-$cycle_count,
 * dengan DUA pengaman independen supaya eskalasi tidak pernah lepas kendali:
 * pengganda maksimal 8x dari durasi dasar, DAN batas mutlak 24 jam apa pun
 * nilai durasi dasar/siklusnya. Siklus ke-1 = lockout pertama = TIDAK ada
 * eskalasi (durasi dasar apa adanya), siklus ke-2 = 2x, ke-3 = 4x, ke-4
 * dan seterusnya = 8x (mentok di pengganda maksimal).
 *
 * @param int $base_minutes Durasi lockout dasar dari pengaturan (menit).
 * @param int $cycle_count  Siklus lockout keberapa (1 = pertama kali).
 * @return int Durasi lockout final (menit), sudah dibatasi dua lapis.
 */
function wscanom_progressive_lockout_minutes( $base_minutes, $cycle_count ) {
    $base_minutes = max( 1, (int) $base_minutes );
    $cycle_count  = max( 1, (int) $cycle_count );
    $multiplier   = min( WSCANOM_PROGRESSIVE_LOCKOUT_MAX_MULTIPLIER, 2 ** ( $cycle_count - 1 ) );
    $minutes      = $base_minutes * $multiplier;

    return min( WSCANOM_PROGRESSIVE_LOCKOUT_CAP_MINUTES, $minutes );
}

/**
 * Daftar header proxy yang bisa dipilih admin sebagai sumber IP asli
 * pengunjung, dipakai baik untuk deteksi dini (preview nilai saat ini di
 * tabel Pengerasan Lanjutan) maupun resolusi IP sungguhan. Key kosong ('')
 * selalu berarti "cuma REMOTE_ADDR" dan TIDAK ada di daftar ini.
 *
 * @return array<string,string> key setting => nama header $_SERVER.
 */
function wscanom_trusted_ip_header_options() {
    return array(
        'cf_connecting_ip' => 'HTTP_CF_CONNECTING_IP',   // Cloudflare.
        'true_client_ip'   => 'HTTP_TRUE_CLIENT_IP',      // Cloudflare Enterprise / Akamai.
        'x_real_ip'        => 'HTTP_X_REAL_IP',           // nginx reverse proxy umum.
        'x_forwarded_for'  => 'HTTP_X_FORWARDED_FOR',     // load balancer/CDN umum (ambil IP pertama).
    );
}

/**
 * Baca nilai mentah satu header proxy dari request saat ini, TANPA
 * mempedulikan apakah header itu sedang dipercaya di pengaturan atau tidak
 * — dipakai murni untuk preview "deteksi dini" di UI, supaya admin bisa
 * membandingkan REMOTE_ADDR dengan isi header SEBELUM memutuskan
 * mempercayainya.
 *
 * @param string $header_key Salah satu key dari wscanom_trusted_ip_header_options().
 * @return string Nilai IP pertama yang valid dari header tsb, atau '' kalau tidak ada/tidak valid.
 */
function wscanom_peek_ip_header( $header_key ) {
    $map = wscanom_trusted_ip_header_options();
    if ( ! isset( $map[ $header_key ] ) ) {
        return '';
    }
    $server_key = $map[ $header_key ];
    if ( empty( $_SERVER[ $server_key ] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.NonceVerification.Recommended
        return '';
    }
    $raw = sanitize_text_field( wp_unslash( $_SERVER[ $server_key ] ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.NonceVerification.Recommended

    // X-Forwarded-For bisa berisi daftar "client, proxy1, proxy2" — ambil
    // entri PALING KIRI (klien asli dalam konvensi standar satu-hop CDN).
    // Header lain (CF-Connecting-IP, True-Client-IP, X-Real-IP) selalu
    // berisi satu nilai tunggal, tidak perlu dipecah.
    $first = trim( explode( ',', $raw )[0] );

    return filter_var( $first, FILTER_VALIDATE_IP ) ? $first : '';
}

/**
 * Alamat IP pengunjung saat ini, untuk pembatas brute-force dan log
 * aktivitas. Defaultnya HANYA REMOTE_ADDR — header proxy seperti
 * X-Forwarded-For bisa dipalsukan bebas oleh pengunjung kalau situs TIDAK
 * benar-benar selalu diakses lewat proxy tersebut, jadi header lain hanya
 * dipakai kalau admin MEMILIH SENDIRI secara eksplisit lewat pengaturan
 * "Header IP Tepercaya" di tabel Pengerasan Lanjutan — bukan ditebak atau
 * dinyalakan otomatis oleh plugin.
 *
 * @return string
 */
function wscanom_get_visitor_ip() {
    $ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '0.0.0.0'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.NonceVerification.Recommended

    $settings   = wscanom_get_settings();
    $header_key = isset( $settings['trusted_ip_header'] ) ? $settings['trusted_ip_header'] : '';
    if ( '' !== $header_key ) {
        $from_header = wscanom_peek_ip_header( $header_key );
        if ( '' !== $from_header ) {
            $ip = $from_header;
        }
    }

    /**
     * Jalan keluar untuk setup proxy yang tidak tercakup daftar bawaan di
     * atas (mis. load balancer internal kustom) — developer tetap bisa
     * override penuh lewat kode kalau benar-benar perlu.
     */
    return (string) apply_filters( 'wscanom_visitor_ip', $ip );
}

/**
 * Berapa menit sebelum percobaan login berikutnya diizinkan lagi, atau 0
 * kalau belum kena batas.
 *
 * @param string $ip       Alamat IP.
 * @param string $username Username yang dicoba.
 * @return int
 */
function wscanom_login_lockout_remaining( $ip, $username ) {
    $settings = wscanom_get_settings();
    if ( empty( $settings['bruteforce_protection'] ) ) {
        return 0;
    }

    $until_ip   = (int) get_transient( wscanom_login_lockout_until_key( $ip, $username ) );
    $until_user = (int) get_transient( wscanom_login_lockout_until_user_key( $username ) );
    $until      = max( $until_ip, $until_user );

    if ( $until <= time() ) {
        return 0;
    }

    return max( 1, (int) ceil( ( $until - time() ) / MINUTE_IN_SECONDS ) );
}

/**
 * Cegah login diproses kalau IP/username ini sedang kena lockout —
 * dicek SEBELUM WordPress memvalidasi password, supaya percobaan yang
 * dikunci tidak ikut membebani proses hash password (pertahanan ringan
 * terhadap DoS lewat spam percobaan login juga).
 *
 * @param null|WP_User|WP_Error $user     Hasil autentikasi sejauh ini.
 * @param string                $username Username yang dicoba.
 * @return null|WP_User|WP_Error
 */
function wscanom_block_locked_out_login( $user, $username ) {
    if ( '' === $username ) {
        return $user;
    }

    $ip        = wscanom_get_visitor_ip();
    $remaining = wscanom_login_lockout_remaining( $ip, $username );

    if ( $remaining > 0 ) {
        return new WP_Error(
            'wscanom_locked_out',
            sprintf(
                /* translators: %d: sisa menit */
                __( '<strong>Error:</strong> Terlalu banyak percobaan login gagal. Coba lagi dalam %d menit.', 'wscanom' ),
                $remaining
            )
        );
    }

    return $user;
}
add_filter( 'authenticate', 'wscanom_block_locked_out_login', 30, 2 );

/**
 * Catat satu percobaan login yang GAGAL, dan tambahkan ke log aktivitas
 * kalau modul itu aktif.
 *
 * @param string $username Username yang dicoba.
 * @return void
 */
function wscanom_record_failed_login( $username ) {
    $settings = wscanom_get_settings();
    if ( empty( $settings['bruteforce_protection'] ) || '' === $username ) {
        return;
    }

    $ip           = wscanom_get_visitor_ip();
    $max_attempts = max( 1, (int) $settings['bruteforce_max_attempts'] );
    $base_minutes = max( 1, (int) $settings['bruteforce_lockout_minutes'] );
    $window       = $base_minutes * MINUTE_IN_SECONDS;

    // Status terkunci SEBELUM percobaan ini dicatat — dipakai di bawah
    // untuk mencegah lockout baru/eskalasi dipicu berulang-ulang oleh
    // percobaan yang terus masuk SELAMA sudah terkunci (wp_login_failed
    // tetap jalan meskipun ditolak lebih awal oleh filter lockout), dan
    // tetap benar kalau penghitung di bawah sudah lama lewat ambang karena
    // jendelanya belum kadaluarsa dari siklus lockout sebelumnya.
    $was_locked = wscanom_login_lockout_remaining( $ip, $username ) > 0;

    $ip_key   = wscanom_login_attempt_key( $ip, $username );
    $ip_count = (int) get_transient( $ip_key ) + 1;
    set_transient( $ip_key, $ip_count, $window );

    $user_key   = wscanom_login_attempt_user_key( $username );
    $user_count = (int) get_transient( $user_key ) + 1;
    set_transient( $user_key, $user_count, $window );

    $crossed_now = ( ! $was_locked ) && ( $ip_count >= $max_attempts || $user_count >= $max_attempts );

    if ( $crossed_now ) {
        $progressive = ! empty( $settings['bruteforce_progressive_lockout'] );
        $cycle_count = 1;

        if ( $progressive ) {
            $cycle_key      = wscanom_login_cycle_key( $ip, $username );
            $cycle_user_key = wscanom_login_cycle_user_key( $username );
            $cycle_count    = max( (int) get_transient( $cycle_key ), (int) get_transient( $cycle_user_key ) ) + 1;
            set_transient( $cycle_key, $cycle_count, WSCANOM_PROGRESSIVE_LOCKOUT_CYCLE_WINDOW );
            set_transient( $cycle_user_key, $cycle_count, WSCANOM_PROGRESSIVE_LOCKOUT_CYCLE_WINDOW );
        }

        $lockout_minutes = wscanom_progressive_lockout_minutes( $base_minutes, $cycle_count );
        $lockout_seconds = $lockout_minutes * MINUTE_IN_SECONDS;
        $until            = time() + $lockout_seconds;

        set_transient( wscanom_login_lockout_until_key( $ip, $username ), $until, $lockout_seconds );
        set_transient( wscanom_login_lockout_until_user_key( $username ), $until, $lockout_seconds );

        if ( $progressive && $cycle_count > 1 && function_exists( 'wscanom_log_event' ) ) {
            wscanom_log_event(
                'login_lockout_escalated',
                sprintf(
                    /* translators: 1: username, 2: siklus lockout ke-berapa, 3: durasi menit, 4: alamat IP */
                    __( 'Lockout login untuk "%1$s" meningkat ke siklus ke-%2$d (%3$d menit) karena percobaan brute-force berulang dari IP %4$s.', 'wscanom' ),
                    $username,
                    $cycle_count,
                    $lockout_minutes,
                    $ip
                )
            );
        }
    }

    if ( function_exists( 'wscanom_log_event' ) ) {
        wscanom_log_event(
            'login_failed',
            sprintf(
                /* translators: 1: username, 2: alamat IP */
                __( 'Percobaan login gagal untuk "%1$s" dari IP %2$s', 'wscanom' ),
                $username,
                $ip
            )
        );
    }
}
add_action( 'wp_login_failed', 'wscanom_record_failed_login' );

/**
 * Bersihkan hitungan percobaan begitu login BERHASIL, supaya admin/user
 * yang tadinya salah ketik beberapa kali tidak terus tersisa hitungannya
 * setelah akhirnya berhasil masuk dengan benar.
 *
 * @param string  $username Username yang berhasil login.
 * @param WP_User $user     Objek user.
 * @return void
 */
function wscanom_clear_login_attempts( $username, $user = null ) {
    unset( $user );
    $ip = wscanom_get_visitor_ip();
    delete_transient( wscanom_login_attempt_key( $ip, $username ) );
    delete_transient( wscanom_login_attempt_user_key( $username ) );
    delete_transient( wscanom_login_lockout_until_key( $ip, $username ) );
    delete_transient( wscanom_login_lockout_until_user_key( $username ) );
    delete_transient( wscanom_login_cycle_key( $ip, $username ) );
    delete_transient( wscanom_login_cycle_user_key( $username ) );

    if ( function_exists( 'wscanom_log_event' ) ) {
        wscanom_log_event(
            'login_success',
            sprintf(
                /* translators: 1: username, 2: alamat IP */
                __( 'Login berhasil untuk "%1$s" dari IP %2$s', 'wscanom' ),
                $username,
                $ip
            )
        );
    }
}
add_action( 'wp_login', 'wscanom_clear_login_attempts', 10, 2 );

// ============================================================
// PENGERASAN XML-RPC
// Bagian AMAN (hapus metode pingback) aktif default — pingback adalah
// vektor DDoS amplifikasi & pemindaian brute-force klasik yang HAMPIR
// TIDAK PERNAH dipakai situs modern secara sengaja. Mematikan XML-RPC
// TOTAL tetap manual (lihat wscanom_render_advanced_hardening_settings()
// di admin-page.php) karena bisa memutus Jetpack/aplikasi mobile WordPress.
// ============================================================

/**
 * Hapus metode pingback dari XML-RPC tanpa mematikan XML-RPC itu sendiri.
 * Ini satu-satunya bagian pengerasan XML-RPC yang aman diaktifkan otomatis
 * untuk semua situs tanpa syarat — tidak ada integrasi sah yang butuh
 * metode pingback.* ini pada 2026.
 *
 * @param array $methods Daftar metode XML-RPC yang terdaftar.
 * @return array
 */
function wscanom_disable_xmlrpc_pingback( $methods ) {
    unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
    return $methods;
}
add_filter( 'xmlrpc_methods', 'wscanom_disable_xmlrpc_pingback' );

/**
 * Hapus header/link pingback dari <head> dan dari header HTTP X-Pingback,
 * melengkapi penghapusan metode di atas (percuma metodenya dihapus tapi
 * linknya masih diiklankan ke seluruh dunia).
 *
 * @return void
 */
function wscanom_remove_pingback_header() {
    header_remove( 'X-Pingback' );
}
add_action( 'send_headers', 'wscanom_remove_pingback_header' );

/**
 * Deteksi dini: apakah ada plugin yang diketahui BERGANTUNG pada XML-RPC
 * (Jetpack dan turunannya yang paling umum). Dipakai untuk menampilkan
 * peringatan SEBELUM admin mengaktifkan "matikan XML-RPC total" di tabel
 * pengaturan lanjutan — bukan mencegah, tapi memberi tahu konsekuensinya
 * dulu, sesuai permintaan: deteksi otomatis sebelum pengaturan berdampak
 * diterapkan.
 *
 * @return string[] Nama plugin yang terdeteksi aktif dan bergantung XML-RPC.
 */
function wscanom_detect_xmlrpc_dependents() {
    $known = array(
        'jetpack/jetpack.php'               => 'Jetpack',
        'jetpack-boost/jetpack-boost.php'   => 'Jetpack Boost',
        'wp-time-capsule/wp-time-capsule.php' => 'WP Time Capsule',
    );

    $found = array();
    if ( ! function_exists( 'is_plugin_active' ) ) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    foreach ( $known as $plugin_file => $label ) {
        if ( is_plugin_active( $plugin_file ) ) {
            $found[] = $label;
        }
    }

    return $found;
}

/**
 * Matikan XML-RPC total. HANYA dipanggil kalau admin mengaktifkan secara
 * eksplisit lewat pengaturan lanjutan (default OFF) — lihat peringatan
 * deteksi dini di atas yang ditampilkan di UI-nya.
 *
 * @return bool
 */
function wscanom_filter_xmlrpc_enabled() {
    $settings = wscanom_get_settings();
    if ( ! empty( $settings['disable_xmlrpc_entirely'] ) ) {
        return false;
    }
    return true;
}
add_filter( 'xmlrpc_enabled', 'wscanom_filter_xmlrpc_enabled' );

// ============================================================
// AKSI DARURAT
// Tombol sekali-klik, bukan pengaturan yang "menyala terus" — dipakai
// SETELAH admin curiga/yakin situsnya kena kompromi, untuk langsung
// memutus akses penyerang yang mungkin sudah mencuri sesi/password,
// alih-alih menunggu temuan scan ditindaklanjuti satu per satu.
// ============================================================

/**
 * Paksa SEMUA user (atau satu user tertentu) me-reset password di login
 * berikutnya, dan putuskan semua sesi login yang sedang aktif saat ini
 * juga (supaya sesi yang mungkin sudah dibajak langsung tidak valid lagi,
 * bukan cuma menunggu password diganti).
 *
 * @param int $user_id 0 untuk SEMUA user, atau ID user tertentu.
 * @return int Jumlah user yang terdampak.
 */
function wscanom_force_password_reset( $user_id = 0 ) {
    $affected = 0;

    if ( $user_id > 0 ) {
        $users = array( get_userdata( $user_id ) );
    } else {
        $users = get_users( array( 'fields' => 'all' ) );
    }

    foreach ( $users as $user ) {
        if ( ! $user ) {
            continue;
        }
        update_user_meta( $user->ID, 'wscanom_force_reset', time() );
        if ( class_exists( 'WP_Session_Tokens' ) ) {
            WP_Session_Tokens::get_instance( $user->ID )->destroy_all();
        }
        ++$affected;
    }

    if ( function_exists( 'wscanom_log_event' ) ) {
        wscanom_log_event(
            'emergency_action',
            sprintf(
                /* translators: %d: jumlah user */
                __( 'Admin memaksa reset password + logout untuk %d akun (aksi darurat).', 'wscanom' ),
                $affected
            )
        );
    }

    return $affected;
}

/**
 * Cegah user yang ditandai wscanom_force_reset login tanpa mengganti
 * password dulu — dicek di 'authenticate' setelah password tervalidasi
 * benar (prioritas rendah), supaya penyerang yang masih tahu password lama
 * tetap tidak bisa masuk sampai password diganti lewat alur "lupa password"
 * resmi WordPress.
 *
 * @param null|WP_User|WP_Error $user WP_User kalau autentikasi password berhasil.
 * @return null|WP_User|WP_Error
 */
function wscanom_enforce_forced_reset( $user ) {
    if ( ! ( $user instanceof WP_User ) ) {
        return $user;
    }

    if ( get_user_meta( $user->ID, 'wscanom_force_reset', true ) ) {
        return new WP_Error(
            'wscanom_force_reset',
            __( '<strong>Error:</strong> Demi keamanan, password akun ini harus direset. Gunakan tautan "Lupa password?" untuk membuat password baru.', 'wscanom' )
        );
    }

    return $user;
}
add_filter( 'authenticate', 'wscanom_enforce_forced_reset', 35, 1 );

/**
 * Hapus tanda "wajib reset" begitu user benar-benar sudah mengganti
 * password lewat alur resmi WordPress (termasuk lewat link reset email).
 *
 * @param WP_User $user User yang passwordnya baru saja diganti.
 * @return void
 */
function wscanom_clear_forced_reset_flag( $user ) {
    if ( $user instanceof WP_User ) {
        delete_user_meta( $user->ID, 'wscanom_force_reset' );
    }
}
add_action( 'after_password_reset', 'wscanom_clear_forced_reset_flag' );
add_action( 'password_reset', 'wscanom_clear_forced_reset_flag' );

/**
 * Putuskan SEMUA sesi login yang sedang aktif, untuk SEMUA user, TANPA
 * memaksa reset password (beda dari wscanom_force_password_reset() —
 * dipakai kalau admin cuma mau "usir semua orang keluar sekarang" tanpa
 * perlu setiap orang ganti password, mis. setelah yakin tidak ada akun
 * yang benar-benar dibobol, cuma mau bersih-bersih sesi).
 *
 * @return int Jumlah user yang sesinya diputus.
 */
function wscanom_logout_all_users() {
    $affected = 0;
    foreach ( get_users( array( 'fields' => 'ID' ) ) as $user_id ) {
        if ( class_exists( 'WP_Session_Tokens' ) ) {
            WP_Session_Tokens::get_instance( $user_id )->destroy_all();
            ++$affected;
        }
    }

    if ( function_exists( 'wscanom_log_event' ) ) {
        wscanom_log_event(
            'emergency_action',
            sprintf(
                /* translators: %d: jumlah user */
                __( 'Admin memutus semua sesi login untuk %d akun (aksi darurat).', 'wscanom' ),
                $affected
            )
        );
    }

    return $affected;
}
