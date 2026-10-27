<?php
/**
 * WScanom — CAPTCHA aritmatika sederhana di form login, tanpa layanan
 * pihak ketiga apa pun (tidak ada kunci API, tidak ada request keluar ke
 * reCAPTCHA/hCaptcha/dsb) — konsisten dengan prinsip "tidak ada data situs
 * yang dikirim ke luar" dan "gratis selamanya, tanpa kunci berbayar".
 *
 * Didesain TANPA PENYIMPANAN SESI DI SERVER: jawaban yang benar tidak
 * disimpan di database atau transient, tapi "ditandatangani" (HMAC) memakai
 * AUTH_KEY situs sendiri dan disisipkan sebagai field tersembunyi. Saat form
 * disubmit, tanda tangan dihitung ulang dan dicocokkan — kalau cocok DAN
 * belum kedaluwarsa (default 10 menit), berarti soal itu memang berasal
 * dari situs ini dan belum pernah "dipakai ulang" di luar jendela waktunya.
 * Pendekatan ini ringan (tidak menambah baris di database tiap percobaan
 * login) dan cocok dipasang bersama pembatas brute-force di login-protection.php.
 *
 * Default AKTIF — risiko mematahkan fungsi situs sangat rendah (soal
 * matematika sederhana, bisa dikerjakan siapa pun termasuk lewat pembaca
 * layar karena disajikan sebagai teks biasa), jadi tidak perlu masuk tabel
 * "Pengerasan Lanjutan". Tetap bisa dimatikan lewat Pengaturan Proteksi.
 *
 * @package WScanom
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'WSCANOM_CAPTCHA_FIELD', 'wscanom_captcha_answer' );
define( 'WSCANOM_CAPTCHA_TOKEN_FIELD', 'wscanom_captcha_token' );
define( 'WSCANOM_CAPTCHA_TTL', 10 * MINUTE_IN_SECONDS );

/**
 * Kunci rahasia dipakai untuk menandatangani soal CAPTCHA. Memakai AUTH_KEY
 * bawaan WordPress (unik per situs, sudah ada di wp-config.php) supaya tidak
 * perlu menyimpan rahasia baru di mana pun.
 *
 * @return string
 */
function wscanom_captcha_secret() {
    if ( defined( 'AUTH_KEY' ) && AUTH_KEY && 'put your unique phrase here' !== AUTH_KEY ) {
        return AUTH_KEY;
    }
    // Fallback kalau AUTH_KEY belum diset situs (jarang, biasanya hosting
    // sudah mengisi otomatis saat instalasi) — tetap unik per situs lewat
    // combine dengan nama database, supaya CAPTCHA tidak pernah sama sekali
    // tanpa tanda tangan yang bisa ditebak.
    return 'wscanom-captcha-' . DB_NAME;
}

/**
 * Buat satu soal CAPTCHA baru beserta tanda tangannya.
 *
 * @return array{a:int,b:int,token:string}
 */
function wscanom_captcha_generate() {
    $a       = wp_rand( 1, 10 );
    $b       = wp_rand( 1, 10 );
    $expires = time() + WSCANOM_CAPTCHA_TTL;
    $answer  = $a + $b;

    $payload   = $a . '|' . $b . '|' . $expires;
    $signature = hash_hmac( 'sha256', $payload, wscanom_captcha_secret() );
    $token     = base64_encode( $payload . '|' . $signature ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode

    return array(
        'a'     => $a,
        'b'     => $b,
        'token' => $token,
    );
}

/**
 * Validasi jawaban CAPTCHA yang disubmit terhadap token yang menyertainya.
 *
 * @param string $token  Token dari field tersembunyi.
 * @param string $answer Jawaban yang diisi pengguna.
 * @return bool
 */
function wscanom_captcha_verify( $token, $answer ) {
    $decoded = base64_decode( (string) $token, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
    if ( ! $decoded ) {
        return false;
    }

    $parts = explode( '|', $decoded );
    if ( 4 !== count( $parts ) ) {
        return false;
    }

    list( $a, $b, $expires, $signature ) = $parts;

    if ( ! ctype_digit( $a ) || ! ctype_digit( $b ) || ! ctype_digit( $expires ) ) {
        return false;
    }

    $expires = (int) $expires;
    if ( $expires < time() ) {
        return false; // soal sudah kedaluwarsa — cegah replay token lama.
    }

    $payload   = $a . '|' . $b . '|' . $expires;
    $expected  = hash_hmac( 'sha256', $payload, wscanom_captcha_secret() );
    if ( ! hash_equals( $expected, $signature ) ) {
        return false; // token dipalsukan atau rusak.
    }

    return (int) $answer === ( (int) $a + (int) $b );
}

/**
 * Tampilkan field CAPTCHA di form login bawaan WordPress.
 *
 * @return void
 */
function wscanom_render_login_captcha() {
    $settings = wscanom_get_settings();
    if ( empty( $settings['login_captcha'] ) ) {
        return;
    }

    $captcha = wscanom_captcha_generate();
    ?>
    <p class="wscanom-captcha-row">
        <label for="wscanom_captcha_answer">
            <?php
            printf(
                /* translators: 1: angka pertama, 2: angka kedua */
                esc_html__( 'Verifikasi keamanan: berapa %1$d + %2$d?', 'wscanom' ),
                (int) $captcha['a'],
                (int) $captcha['b']
            );
            ?>
        </label>
        <input type="text" name="<?php echo esc_attr( WSCANOM_CAPTCHA_FIELD ); ?>" id="wscanom_captcha_answer" class="input" inputmode="numeric" autocomplete="off" required="required" />
        <input type="hidden" name="<?php echo esc_attr( WSCANOM_CAPTCHA_TOKEN_FIELD ); ?>" value="<?php echo esc_attr( $captcha['token'] ); ?>" />
    </p>
    <?php
}
add_action( 'login_form', 'wscanom_render_login_captcha' );

/**
 * Cegah login diproses kalau CAPTCHA aktif dan jawabannya salah/hilang.
 * Dicek SEBELUM pembatas brute-force (prioritas lebih rendah dari 30) agar
 * percobaan yang gagal CAPTCHA tidak ikut menghabiskan jatah percobaan login
 * yang sah di penghitung brute-force (bot yang gagal CAPTCHA berulang kali
 * tidak mempercepat admin asli terkunci).
 *
 * @param null|WP_User|WP_Error $user     Hasil autentikasi sejauh ini.
 * @param string                $username Username yang dicoba.
 * @return null|WP_User|WP_Error
 */
function wscanom_enforce_login_captcha( $user, $username ) {
    $settings = wscanom_get_settings();
    if ( empty( $settings['login_captcha'] ) ) {
        return $user;
    }

    // Hanya berlaku untuk submit form login sungguhan (ada username/password
    // terisi) — bukan untuk permintaan REST/XML-RPC/aplikasi lain yang juga
    // lewat 'authenticate' tapi tidak pernah menampilkan form ini.
    if ( '' === $username || ! isset( $_POST[ WSCANOM_CAPTCHA_TOKEN_FIELD ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
        return $user;
    }

    $token  = sanitize_text_field( wp_unslash( $_POST[ WSCANOM_CAPTCHA_TOKEN_FIELD ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
    $answer = isset( $_POST[ WSCANOM_CAPTCHA_FIELD ] ) ? sanitize_text_field( wp_unslash( $_POST[ WSCANOM_CAPTCHA_FIELD ] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing

    if ( ! wscanom_captcha_verify( $token, $answer ) ) {
        return new WP_Error(
            'wscanom_captcha_failed',
            __( '<strong>Error:</strong> Jawaban verifikasi keamanan salah atau sudah kedaluwarsa. Silakan coba lagi.', 'wscanom' )
        );
    }

    return $user;
}
add_filter( 'authenticate', 'wscanom_enforce_login_captcha', 25, 2 );
