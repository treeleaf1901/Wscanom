<?php
/**
 * WScanom — Pengerasan privasi/info-disclosure: sembunyikan versi
 * WordPress, cegah penebakan username, blokir akses langsung ke
 * readme.html/license.txt, header HTTP protektif, cookie aman, dan dua
 * pengaturan manual (paksa HTTPS, matikan feed RSS/Atom).
 *
 * Semua yang di file ini aman diaktifkan otomatis KECUALI yang eksplisit
 * ditandai "manual" di komentarnya — mengikuti aturan yang sama seperti
 * includes/hardening.php dan includes/login-protection.php.
 *
 * @package WScanom
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// ============================================================
// SEMBUNYIKAN VERSI WORDPRESS
// Default AKTIF — versi WordPress yang terekspos mempermudah penyerang
// mencocokkan situsmu dengan daftar kerentanan versi tertentu yang sudah
// diketahui publik. Tidak ada downside fungsional sama sekali.
// ============================================================

remove_action( 'wp_head', 'wp_generator' );
add_filter( 'the_generator', '__return_empty_string' );

define( 'WSCANOM_FAKE_VERSION_TOKEN_OPTION', 'wscanom_fake_version_token' );

/**
 * Hasilkan satu token versi PALSU TAPI MASUK AKAL (format X.Y.Z seperti
 * nomor versi WordPress sungguhan), memakai wp_rand() — yang di baliknya
 * memakai sumber acak kriptografis WordPress sendiri (random_bytes() kalau
 * tersedia) — BUKAN pendekatan str_shuffle(time()) yang kami temukan saat
 * membandingkan dengan plugin keamanan populer lain: str_shuffle(time())
 * cuma mengacak URUTAN digit dari timestamp SAAT TOKEN DIBUAT, yang berarti
 * nilainya bisa ditebak/dipersempit drastis kalau penyerang tahu kira-kira
 * kapan situs dipasang (ruang kemungkinannya jauh lebih kecil daripada
 * angka acak sungguhan) — pendekatan "pensil dan penghapus" di sini memakai
 * sumber acak yang benar-benar tidak bisa ditebak dari informasi luar.
 *
 * @return string
 */
function wscanom_generate_fake_version_token() {
    return sprintf( '%d.%d.%d', wp_rand( 5, 6 ), wp_rand( 0, 9 ), wp_rand( 0, 9 ) );
}

/**
 * Ambil token versi palsu untuk situs ini, membuat dan menyimpannya kalau
 * belum ada. Token ini sengaja STABIL (sama di setiap request) begitu
 * dibuat — token yang berubah-ubah di setiap page load akan membuat browser
 * menganggap aset berubah terus-menerus dan tidak pernah memakai cache-nya
 * (membuat situs terasa lebih lambat), padahal tujuannya cuma MENYAMARKAN
 * nilai asli, bukan menggantinya dengan sesuatu yang berubah tiap saat.
 * Diperbarui otomatis hanya saat WordPress core benar-benar diupdate, lihat
 * wscanom_maybe_rotate_fake_version_token().
 *
 * @return string
 */
function wscanom_get_fake_version_token() {
    $token = get_option( WSCANOM_FAKE_VERSION_TOKEN_OPTION, '' );
    if ( ! is_string( $token ) || '' === $token ) {
        $token = wscanom_generate_fake_version_token();
        update_option( WSCANOM_FAKE_VERSION_TOKEN_OPTION, $token, false );
    }
    return $token;
}

/**
 * Perbarui token versi palsu setiap kali WordPress CORE (bukan sembarang
 * plugin/tema) selesai diupdate — meniru manfaat SATU-SATUNYA yang hilang
 * kalau token dibuat statis selamanya: saat versi inti berubah, aset
 * JS/CSS yang berubah isinya butuh "cache busting" supaya browser pengunjung
 * yang masih menyimpan cache versi lama mengambil ulang versi baru. Dengan
 * merotasi token TEPAT pada momen itu (bukan tiap request), manfaat cache
 * busting tetap didapat tanpa token itu sendiri pernah membocorkan nomor
 * versi sungguhan yang baru.
 *
 * @param WP_Upgrader $upgrader   Diabaikan, demi kompatibilitas signature hook upgrader_process_complete.
 * @param array       $hook_extra Detail proses upgrader: berisi 'type' => 'core'|'plugin'|'theme'.
 * @return void
 */
function wscanom_maybe_rotate_fake_version_token( $upgrader, $hook_extra ) {
    unset( $upgrader );
    if ( empty( $hook_extra['type'] ) || 'core' !== $hook_extra['type'] ) {
        return;
    }
    update_option( WSCANOM_FAKE_VERSION_TOKEN_OPTION, wscanom_generate_fake_version_token(), false );
}
add_action( 'upgrader_process_complete', 'wscanom_maybe_rotate_fake_version_token', 10, 2 );

/**
 * Ganti (bukan sekadar buang) parameter "?ver=X.Y.Z" di URL script/style
 * bawaan WordPress dengan token palsu di atas. Membuang parameter itu sama
 * sekali (pendekatan lama) sebenarnya meninggalkan jejak lain: pemindai bisa
 * melihat SEMUA aset WordPress tidak punya "ver" sama sekali, yang justru
 * jadi sidik jari tersendiri ("situs ini pakai plugin yang membuang versi")
 * dan masih kehilangan manfaat cache-busting untuk update tema/plugin lain
 * yang justru membutuhkannya. Mengganti dengan nilai yang TERLIHAT seperti
 * nomor versi asli (tapi palsu dan stabil) lebih menyatu secara alami.
 *
 * Hanya mengganti nilai yang BENTUKNYA memang terlihat seperti nomor versi
 * (angka dan titik, mis. "6.4.2" atau "1.2") — "ver" milik plugin lain yang
 * kebetulan memakai nama parameter sama tapi isinya bukan pola versi (mis.
 * hash cache-busting mereka sendiri) sengaja TIDAK disentuh, supaya fungsi
 * ini tidak pernah merusak mekanisme cache-busting pihak lain yang valid.
 *
 * @param string $src URL asli.
 * @return string
 */
function wscanom_strip_version_query( $src ) {
    if ( ! is_string( $src ) || false === strpos( $src, 'ver=' ) ) {
        return $src;
    }

    $query = wp_parse_url( $src, PHP_URL_QUERY );
    if ( ! $query ) {
        return $src;
    }

    parse_str( $query, $params );
    if ( ! isset( $params['ver'] ) || ! preg_match( '/^\d+(?:\.\d+){0,3}(?:-[a-zA-Z0-9]+)?$/', (string) $params['ver'] ) ) {
        return $src;
    }

    return add_query_arg( 'ver', wscanom_get_fake_version_token(), $src );
}
add_filter( 'script_loader_src', 'wscanom_strip_version_query' );
add_filter( 'style_loader_src', 'wscanom_strip_version_query' );

// ============================================================
// CEGAH PENEBAKAN USERNAME
// Default AKTIF — endpoint ?author=1, ?author=2, dst. dan REST API users
// adalah cara paling umum penyerang menebak username admin sebelum mencoba
// brute-force password. Menutup ini tidak menghilangkan fungsi apa pun bagi
// pengunjung biasa (arsip penulis tetap bisa diakses lewat slug/permalink
// normal, cuma penebakan lewat ID numerik mentah yang diblokir).
// ============================================================

/**
 * Redirect permintaan "?author=N" ke beranda alih-alih membiarkan
 * WordPress menampilkan (dan membocorkan lewat redirect permalink) slug
 * username asli si penulis.
 *
 * @return void
 */
function wscanom_block_author_enumeration() {
    if ( is_admin() ) {
        return;
    }
    if ( isset( $_GET['author'] ) && preg_match( '/^\d+$/', wp_unslash( $_GET['author'] ) ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        wp_safe_redirect( home_url( '/' ), 301 );
        exit;
    }
}
add_action( 'template_redirect', 'wscanom_block_author_enumeration' );

/**
 * Sembunyikan daftar nama/username user dari endpoint REST API publik
 * (/wp-json/wp/v2/users) untuk pengunjung yang belum login — endpoint ini
 * oleh default WordPress membocorkan slug (biasanya = username) semua user
 * yang pernah menulis post, tanpa autentikasi apa pun.
 *
 * @param WP_REST_Response $response Respons REST API.
 * @param mixed             $item     Objek data (diabaikan di sini).
 * @param WP_REST_Request   $request  Request REST API.
 * @return WP_REST_Response|WP_Error
 */
function wscanom_restrict_rest_users_endpoint( $response, $item, $request ) {
    unset( $item );
    if ( is_user_logged_in() ) {
        return $response;
    }
    $route = $request->get_route();
    if ( 0 === strpos( $route, '/wp/v2/users' ) ) {
        return new WP_Error(
            'wscanom_rest_forbidden',
            __( 'Tidak diizinkan.', 'wscanom' ),
            array( 'status' => 401 )
        );
    }
    return $response;
}
add_filter( 'rest_prepare_user', 'wscanom_restrict_rest_users_endpoint', 10, 3 );

// ============================================================
// BLOKIR AKSES LANGSUNG KE readme.html / license.txt
// Default AKTIF — readme.html bawaan WordPress mencantumkan nomor versi
// persis, dan sering jadi langkah pertama pemindai otomatis penyerang
// untuk sidik jari (fingerprint) versi situs. Tidak bisa dihapus filenya
// (ditimpa lagi tiap update core), jadi diblokir aksesnya saja.
// ============================================================

/**
 * Tolak akses HTTP langsung ke beberapa file statis bawaan WordPress yang
 * cuma berguna untuk fingerprinting, tidak untuk pengunjung biasa.
 *
 * @return void
 */
function wscanom_block_fingerprint_files() {
    if ( is_admin() || ( defined( 'DOING_AJAX' ) && DOING_AJAX ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
        return;
    }

    $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? wp_parse_url( wp_unslash( $_SERVER['REQUEST_URI'] ), PHP_URL_PATH ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash
    if ( ! $request_uri ) {
        return;
    }

    $blocked = array( '/readme.html', '/license.txt', '/wp-config-sample.php' );
    foreach ( $blocked as $path ) {
        if ( '/' . ltrim( $request_uri, '/' ) === $path || $request_uri === $path ) {
            wp_die( esc_html__( 'Akses ditolak.', 'wscanom' ), 403, array( 'response' => 403 ) );
        }
    }
}
add_action( 'template_redirect', 'wscanom_block_fingerprint_files', 1 );
// template_redirect tidak tereksekusi untuk file statis yang disajikan
// LANGSUNG oleh web server (bukan lewat WordPress) seperti Apache/nginx —
// untuk itu perlu aturan server sendiri. Blokir lewat PHP ini tetap
// berguna di banyak setup (termasuk ketika readme.html diakses lewat
// permalink yang diproses WordPress) tapi bukan jaminan mutlak di semua
// konfigurasi server; lihat catatan di halaman Pengerasan Lanjutan.

// ============================================================
// HEADER HTTP PROTEKTIF
// Default AKTIF — header standar yang hampir tidak pernah mematahkan situs
// (beda dari Content-Security-Policy penuh yang sangat mudah mematahkan
// tema/plugin lain kalau dipasang sembarangan, jadi SENGAJA TIDAK disertakan
// di sini).
// ============================================================

/**
 * Tambahkan beberapa header HTTP protektif standar.
 *
 * @return void
 */
function wscanom_send_security_headers() {
    if ( headers_sent() ) {
        return;
    }
    header( 'X-Content-Type-Options: nosniff' );
    header( 'X-Frame-Options: SAMEORIGIN' );
    header( 'Referrer-Policy: strict-origin-when-cross-origin' );
}
add_action( 'send_headers', 'wscanom_send_security_headers' );

// ============================================================
// COOKIE AMAN
// Default AKTIF, TAPI dengan pengecekan HTTPS otomatis dulu — ini contoh
// konkret "deteksi dini sebelum pengaturan berdampak diterapkan": memaksa
// flag "Secure" pada cookie di situs yang BELUM HTTPS akan membuat browser
// MENOLAK cookie itu sama sekali, yang berarti TIDAK ADA YANG BISA LOGIN.
// Makanya flag Secure hanya ditambahkan kalau is_ssl() benar-benar true.
// ============================================================

add_filter( 'secure_auth_cookie', 'wscanom_force_secure_cookie_if_https' );
add_filter( 'secure_logged_in_cookie', 'wscanom_force_secure_cookie_if_https' );
/**
 * @param bool $secure Nilai default dari WordPress.
 * @return bool
 */
function wscanom_force_secure_cookie_if_https( $secure ) {
    // is_ssl() SENDIRI sudah jadi "deteksi dini" di sini: kalau situs tidak
    // diakses lewat HTTPS saat ini, jangan pernah paksa flag Secure, apa
    // pun pengaturannya — menghindari skenario "semua orang terkunci dari
    // login" yang disebut eksplisit sebagai risiko yang harus dicegah.
    return $secure || is_ssl();
}

// ============================================================
// DETEKSI DINI: SITUS BELUM HTTPS
// Plugin WordPress TIDAK BISA memasang sertifikat SSL (itu butuh akses
// server, di luar jangkauan PHP sepenuhnya) — jadi di sini HANYA memberi
// tahu dan mengarahkan, tidak berpura-pura bisa "memasangkan" apa pun.
// ============================================================

/**
 * @return bool
 */
function wscanom_site_uses_https() {
    return is_ssl() || 0 === strpos( home_url(), 'https://' );
}

/**
 * Tampilkan notice sekali (tidak mengganggu di semua halaman admin,
 * cuma di halaman WScanom sendiri) kalau situs belum HTTPS.
 *
 * @return void
 */
function wscanom_maybe_show_https_notice() {
    $screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
    if ( ! $screen || false === strpos( (string) $screen->id, 'wscanom' ) ) {
        return;
    }
    if ( wscanom_site_uses_https() ) {
        return;
    }
    ?>
    <div class="notice notice-warning">
        <p>
            <strong><?php esc_html_e( 'Situs ini belum menggunakan HTTPS.', 'wscanom' ); ?></strong>
            <?php esc_html_e( 'WScanom tidak bisa memasang sertifikat SSL (itu butuh akses di level server/hosting, di luar jangkauan plugin WordPress mana pun). Tanpa HTTPS, password dan cookie login bisa disadap di jaringan yang tidak aman. Hubungi penyedia hosting untuk mengaktifkan SSL/Let\'s Encrypt — biasanya tersedia gratis dan bisa dipasang lewat panel kontrol hosting (cPanel/Plesk) tanpa biaya tambahan.', 'wscanom' ); ?>
        </p>
    </div>
    <?php
}
add_action( 'admin_notices', 'wscanom_maybe_show_https_notice' );

// ============================================================
// PENGATURAN MANUAL (default OFF, tabel "Pengerasan Lanjutan")
// ============================================================

/**
 * Paksa redirect HTTP ke HTTPS. MANUAL — kalau situs ternyata belum
 * benar-benar bisa melayani HTTPS dengan baik (sertifikat belum valid,
 * mixed content parah), mengaktifkan ini bisa membuat situs tidak bisa
 * diakses sama sekali. Makanya tidak pernah otomatis, dan UI-nya
 * menampilkan status is_ssl() saat ini sebagai deteksi dini sebelum admin
 * menyalakannya.
 *
 * @return void
 */
function wscanom_maybe_force_https_redirect() {
    $settings = wscanom_get_settings();
    if ( empty( $settings['force_https'] ) || is_admin() ) {
        return;
    }
    if ( is_ssl() ) {
        return;
    }
    $redirect_url = 'https://' . ( isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) : '' ) . ( isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '/' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.NonceVerification.Recommended
    wp_safe_redirect( $redirect_url, 301 );
    exit;
}
add_action( 'template_redirect', 'wscanom_maybe_force_https_redirect', 0 );

/**
 * Matikan feed RSS/Atom. MANUAL — banyak situs memang sengaja memakai feed
 * untuk sindikasi konten, newsletter, atau pembaca RSS pengunjung; ini
 * bukan risiko keamanan besar, cuma mempersempit permukaan informasi
 * (tanggal publish, daftar post terbaru) untuk pemindai otomatis. Tidak
 * pantas jadi default karena bisa mematahkan fungsi yang memang diinginkan
 * banyak situs.
 *
 * @return void
 */
function wscanom_maybe_disable_feeds() {
    $settings = wscanom_get_settings();
    if ( empty( $settings['disable_feeds'] ) ) {
        return;
    }
    wp_die(
        esc_html__( 'Feed dimatikan di situs ini. Kunjungi beranda situs untuk konten terbaru.', 'wscanom' ),
        '',
        array( 'response' => 410 )
    );
}
add_action( 'do_feed', 'wscanom_maybe_disable_feeds', 1 );
add_action( 'do_feed_rdf', 'wscanom_maybe_disable_feeds', 1 );
add_action( 'do_feed_rss', 'wscanom_maybe_disable_feeds', 1 );
add_action( 'do_feed_rss2', 'wscanom_maybe_disable_feeds', 1 );
add_action( 'do_feed_atom', 'wscanom_maybe_disable_feeds', 1 );
