<?php
/**
 * WScanom — Autentikasi dua faktor (2FA) berbasis TOTP (RFC 6238), kompatibel
 * dengan Google Authenticator, Authy, Microsoft Authenticator, dan aplikasi
 * authenticator lain yang mendukung standar yang sama. Diimplementasikan
 * murni dengan PHP bawaan (hash_hmac) — tidak ada library luar, tidak ada
 * permintaan ke layanan pihak ketiga mana pun.
 *
 * FILOSOFI KEAMANAN — WAJIB DIBACA SEBELUM MENGUBAH FILE INI:
 * Ini satu-satunya fitur di WScanom yang BENAR-BENAR bisa mengunci seseorang
 * dari akunnya sendiri kalau salah pakai. Karena itu:
 *   1. TIDAK PERNAH aktif otomatis untuk siapa pun. Tiap user mengaktifkan
 *      2FA miliknya SENDIRI, tidak bisa diaktifkan oleh admin lain untuknya.
 *   2. 2FA baru benar-benar menyala SETELAH user membuktikan aplikasi
 *      authenticator-nya sudah tersinkron dengan memasukkan kode yang
 *      sedang berjalan saat itu juga — persis "deteksi dini sebelum
 *      pengaturan berdampak diterapkan" yang jadi prinsip inti plugin ini.
 *      Tidak ada jalan untuk mengaktifkan 2FA tanpa melewati pembuktian ini.
 *   3. 8 kode cadangan sekali-pakai dibuat otomatis saat 2FA diaktifkan,
 *      untuk jalan masuk kalau ponsel/aplikasi authenticator hilang.
 *   4. Admin (manage_options) tetap bisa mematikan 2FA MILIK USER LAIN
 *      sebagai jalan pemulihan darurat (misal: kehilangan ponsel DAN semua
 *      kode cadangan) — tapi tidak pernah bisa MENGAKTIFKAN atau MELIHAT
 *      kunci rahasia 2FA milik user lain.
 *
 * @package WScanom
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'WSCANOM_2FA_SECRET_META', 'wscanom_2fa_secret' );
define( 'WSCANOM_2FA_PENDING_META', 'wscanom_2fa_pending_secret' );
define( 'WSCANOM_2FA_ENABLED_META', 'wscanom_2fa_enabled' );
define( 'WSCANOM_2FA_BACKUP_META', 'wscanom_2fa_backup_codes' );
define( 'WSCANOM_2FA_PENDING_TRANSIENT_PREFIX', 'wscanom_2fa_p_' );
define( 'WSCANOM_2FA_SHOW_CODES_TRANSIENT_PREFIX', 'wscanom_2fa_codes_' );

// ============================================================
// INTI TOTP (RFC 6238) + BASE32 (RFC 4648) — murni PHP, tanpa dependency.
// ============================================================

/**
 * Encode data biner ke Base32 (alfabet standar RFC 4648), dipakai untuk
 * menampilkan kunci rahasia dalam format yang lazim dipakai aplikasi
 * authenticator (huruf besar A-Z dan angka 2-7).
 *
 * @param string $data Data biner mentah.
 * @return string
 */
function wscanom_base32_encode( $data ) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    if ( '' === $data ) {
        return '';
    }

    $binary = '';
    foreach ( str_split( $data ) as $char ) {
        $binary .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
    }

    $output = '';
    foreach ( str_split( $binary, 5 ) as $chunk ) {
        $chunk   = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
        $output .= $alphabet[ bindec( $chunk ) ];
    }

    return $output;
}

/**
 * Decode string Base32 kembali ke data biner mentah.
 *
 * @param string $b32 String Base32.
 * @return string
 */
function wscanom_base32_decode( $b32 ) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $b32      = strtoupper( preg_replace( '/[^A-Za-z2-7]/', '', (string) $b32 ) );

    $binary = '';
    foreach ( str_split( $b32 ) as $char ) {
        $pos = strpos( $alphabet, $char );
        if ( false === $pos ) {
            continue;
        }
        $binary .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
    }

    $output = '';
    foreach ( str_split( $binary, 8 ) as $byte ) {
        if ( 8 !== strlen( $byte ) ) {
            continue; // sisa bit padding di akhir, bukan byte penuh.
        }
        $output .= chr( bindec( $byte ) );
    }

    return $output;
}

/**
 * Hitung HOTP (RFC 4226) mentah dari kunci biner dan counter — dipisah dari
 * pembungkus TOTP supaya bisa diuji langsung terhadap angka contoh resmi
 * RFC 6238 Appendix B tanpa ikut melibatkan encoding Base32.
 *
 * @param string $secret_bytes Kunci rahasia biner mentah (SUDAH di-decode dari Base32).
 * @param int    $counter      Nilai counter (untuk TOTP: waktu dibagi periode).
 * @param int    $digits       Jumlah digit kode (default 6).
 * @return string
 */
function wscanom_hotp_raw( $secret_bytes, $counter, $digits = 6 ) {
    $binary_counter = pack( 'N', 0 ) . pack( 'N', (int) $counter ); // 8 byte big-endian.
    $hash           = hash_hmac( 'sha1', $binary_counter, $secret_bytes, true );

    $offset    = ord( substr( $hash, -1 ) ) & 0x0F;
    $truncated = ( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 )
        | ( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 )
        | ( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 )
        | ( ord( $hash[ $offset + 3 ] ) & 0xFF );

    $otp = $truncated % ( 10 ** $digits );
    return str_pad( (string) $otp, $digits, '0', STR_PAD_LEFT );
}

/**
 * Hitung kode TOTP untuk satu titik waktu tertentu.
 *
 * @param string   $secret_base32 Kunci rahasia dalam format Base32.
 * @param int|null $timestamp     Unix timestamp (default: sekarang).
 * @param int      $digits        Jumlah digit (default 6).
 * @param int      $period        Panjang periode dalam detik (default 30, standar industri).
 * @return string
 */
function wscanom_totp_code( $secret_base32, $timestamp = null, $digits = 6, $period = 30 ) {
    $timestamp    = null === $timestamp ? time() : (int) $timestamp;
    $counter      = (int) floor( $timestamp / $period );
    $secret_bytes = wscanom_base32_decode( $secret_base32 );
    return wscanom_hotp_raw( $secret_bytes, $counter, $digits );
}

/**
 * Verifikasi kode TOTP yang diinput user, dengan toleransi pergeseran jam
 * ±1 periode (±30 detik) ke depan/belakang — jam ponsel dan jam server
 * jarang benar-benar sinkron sampai ke detik, toleransi ini standar di
 * hampir semua implementasi TOTP supaya kode yang baru saja berganti
 * (atau baru akan berganti sedetik lagi) tetap diterima.
 *
 * @param string $secret_base32 Kunci rahasia Base32.
 * @param string $code          Kode yang diinput user.
 * @param int    $window        Jumlah periode toleransi di tiap arah (default 1).
 * @return bool
 */
function wscanom_totp_verify( $secret_base32, $code, $window = 1 ) {
    $code = preg_replace( '/\s+/', '', (string) $code );
    if ( '' === $code || ! ctype_digit( $code ) ) {
        return false;
    }

    $now = time();
    for ( $i = -$window; $i <= $window; $i++ ) {
        $candidate = wscanom_totp_code( $secret_base32, $now + ( $i * 30 ) );
        if ( hash_equals( $candidate, str_pad( $code, 6, '0', STR_PAD_LEFT ) ) ) {
            return true;
        }
    }

    return false;
}

/**
 * URI "otpauth://" standar yang dipahami semua aplikasi authenticator utama
 * untuk pengisian otomatis lewat pindai QR. WScanom tidak membuat gambar
 * QR sendiri (menghindari ketergantungan library/layanan luar) — kunci
 * rahasia ditampilkan sebagai teks untuk dimasukkan manual, yang didukung
 * oleh semua aplikasi authenticator utama sebagai alternatif pindai QR.
 *
 * @param string $secret_base32 Kunci rahasia Base32.
 * @param string $user_login    Username, dipakai sebagai label akun.
 * @return string
 */
function wscanom_totp_otpauth_uri( $secret_base32, $user_login ) {
    $site  = wp_parse_url( home_url(), PHP_URL_HOST );
    $label = rawurlencode( $site . ':' . $user_login );
    $issuer = rawurlencode( $site );
    return "otpauth://totp/{$label}?secret={$secret_base32}&issuer={$issuer}&algorithm=SHA1&digits=6&period=30";
}

// ============================================================
// KODE CADANGAN SEKALI-PAKAI
// ============================================================

/**
 * Buat sekumpulan kode cadangan baru dalam format mudah dibaca ("XXXX-XXXX").
 *
 * @param int $count Jumlah kode.
 * @return string[] Kode dalam bentuk ASLI (hanya ditampilkan sekali, tidak disimpan plain).
 */
function wscanom_2fa_generate_backup_codes( $count = 8 ) {
    $codes = array();
    for ( $i = 0; $i < $count; $i++ ) {
        $raw     = strtoupper( substr( bin2hex( random_bytes( 5 ) ), 0, 8 ) );
        $codes[] = substr( $raw, 0, 4 ) . '-' . substr( $raw, 4, 4 );
    }
    return $codes;
}

/**
 * Hash satu kode cadangan untuk disimpan (bukan plaintext).
 *
 * @param string $code Kode cadangan (dengan atau tanpa tanda hubung).
 * @return string
 */
function wscanom_2fa_hash_backup_code( $code ) {
    $normalized = strtoupper( preg_replace( '/[^A-Z0-9]/i', '', (string) $code ) );
    return hash( 'sha256', $normalized );
}

/**
 * Coba cocokkan kode cadangan yang diinput user terhadap daftar tersimpan
 * milik user tersebut. Kalau cocok, kode itu LANGSUNG dibuang dari daftar
 * (sekali pakai) dan perubahan disimpan.
 *
 * @param int    $user_id ID user.
 * @param string $code    Kode yang diinput.
 * @return bool
 */
function wscanom_2fa_consume_backup_code( $user_id, $code ) {
    $hashed_input = wscanom_2fa_hash_backup_code( $code );
    $stored       = get_user_meta( $user_id, WSCANOM_2FA_BACKUP_META, true );
    if ( ! is_array( $stored ) || empty( $stored ) ) {
        return false;
    }

    $key = array_search( $hashed_input, $stored, true );
    if ( false === $key ) {
        return false;
    }

    unset( $stored[ $key ] );
    update_user_meta( $user_id, WSCANOM_2FA_BACKUP_META, array_values( $stored ) );
    return true;
}

// ============================================================
// STATUS 2FA PER USER
// ============================================================

/**
 * Apakah user ini sudah mengaktifkan dan MENGONFIRMASI 2FA (bukan sekadar
 * sedang dalam proses setup yang belum selesai).
 *
 * @param int $user_id ID user.
 * @return bool
 */
function wscanom_user_has_2fa( $user_id ) {
    return '1' === get_user_meta( $user_id, WSCANOM_2FA_ENABLED_META, true )
        && '' !== get_user_meta( $user_id, WSCANOM_2FA_SECRET_META, true );
}

// ============================================================
// ALUR SETUP — HALAMAN PROFIL USER (profile.php / user-edit.php)
// ============================================================

add_action( 'show_user_profile', 'wscanom_render_2fa_profile_section' );
add_action( 'edit_user_profile', 'wscanom_render_2fa_profile_section' );
/**
 * Tampilkan bagian pengaturan 2FA di halaman profil. Hanya user itu sendiri
 * yang bisa mengatur 2FA miliknya (membuat/membaca kunci rahasia, membuat
 * kode cadangan baru); admin yang melihat profil user LAIN hanya melihat
 * status dan tombol "matikan paksa" untuk pemulihan darurat.
 *
 * @param WP_User $user User yang profilnya sedang ditampilkan.
 * @return void
 */
function wscanom_render_2fa_profile_section( $user ) {
    $is_own_profile = ( get_current_user_id() === (int) $user->ID );
    $enabled        = wscanom_user_has_2fa( $user->ID );
    ?>
    <h2><?php esc_html_e( 'WScanom — Verifikasi Dua Langkah (2FA)', 'wscanom' ); ?></h2>
    <table class="form-table" role="presentation">
        <tr>
            <th scope="row"><?php esc_html_e( 'Status', 'wscanom' ); ?></th>
            <td>
                <?php if ( $enabled ) : ?>
                    <span class="wscanom-badge wscanom-badge-on"><?php esc_html_e( 'Aktif', 'wscanom' ); ?></span>
                <?php else : ?>
                    <span class="wscanom-badge wscanom-badge-off"><?php esc_html_e( 'Belum aktif', 'wscanom' ); ?></span>
                <?php endif; ?>
            </td>
        </tr>
    </table>

    <?php if ( ! $is_own_profile ) : ?>
        <?php if ( $enabled && current_user_can( 'manage_options' ) ) : ?>
            <p>
                <?php esc_html_e( 'Demi keamanan, hanya pemilik akun yang bisa mengatur 2FA miliknya sendiri. Kalau user ini kehilangan akses (ponsel & kode cadangan sama-sama hilang), kamu bisa matikan paksa 2FA-nya di sini sebagai jalan pemulihan darurat:', 'wscanom' ); ?>
            </p>
            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" onsubmit="return confirm('<?php echo esc_js( __( 'Matikan 2FA untuk user ini? Mereka akan bisa login hanya dengan password sampai mengaktifkan 2FA kembali sendiri.', 'wscanom' ) ); ?>');">
                <?php wp_nonce_field( 'wscanom_2fa_admin_disable_' . $user->ID ); ?>
                <input type="hidden" name="action" value="wscanom_2fa_admin_disable" />
                <input type="hidden" name="target_user" value="<?php echo esc_attr( $user->ID ); ?>" />
                <button type="submit" class="button wscanom-btn-danger"><?php esc_html_e( 'Matikan Paksa 2FA User Ini', 'wscanom' ); ?></button>
            </form>
        <?php endif; ?>
        <?php return; ?>
    <?php endif; ?>

    <?php
    // --- Dari sini, HANYA dirender untuk profil milik sendiri. ---
    $pending_secret = get_user_meta( $user->ID, WSCANOM_2FA_PENDING_META, true );

    $show_codes_key = WSCANOM_2FA_SHOW_CODES_TRANSIENT_PREFIX . $user->ID;
    $fresh_codes    = get_transient( $show_codes_key );
    if ( $fresh_codes ) {
        delete_transient( $show_codes_key ); // tampil SEKALI SAJA, lalu musnah.
        ?>
        <div class="notice notice-success inline" style="padding:12px;">
            <p><strong><?php esc_html_e( '2FA berhasil diaktifkan! Simpan 8 kode cadangan ini di tempat aman (password manager, dicetak, dsb).', 'wscanom' ); ?></strong></p>
            <p><?php esc_html_e( 'Tiap kode hanya bisa dipakai SATU KALI, sebagai jalan masuk kalau ponselmu hilang atau aplikasi authenticator tidak bisa diakses. Halaman ini TIDAK akan menampilkan kode ini lagi setelah kamu meninggalkan halaman ini.', 'wscanom' ); ?></p>
            <code style="display:block;background:#f6f7f7;padding:12px;font-size:14px;line-height:1.8;max-width:320px;">
                <?php echo esc_html( implode( "\n", $fresh_codes ) ); ?>
            </code>
        </div>
        <?php
    }

    if ( $enabled ) :
        ?>
        <p><?php esc_html_e( 'Akunmu dilindungi verifikasi dua langkah. Login akan meminta kode dari aplikasi authenticator-mu setelah password.', 'wscanom' ); ?></p>
        <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
            <?php wp_nonce_field( 'wscanom_2fa_disable' ); ?>
            <input type="hidden" name="action" value="wscanom_2fa_disable" />
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><label for="wscanom_2fa_disable_code"><?php esc_html_e( 'Matikan 2FA', 'wscanom' ); ?></label></th>
                    <td>
                        <input type="text" name="wscanom_2fa_disable_code" id="wscanom_2fa_disable_code" class="regular-text" inputmode="numeric" placeholder="<?php esc_attr_e( 'Kode 6 digit dari aplikasi authenticator', 'wscanom' ); ?>" />
                        <p class="description"><?php esc_html_e( 'Masukkan kode yang sedang berjalan di aplikasi authenticator-mu untuk mengonfirmasi penonaktifan.', 'wscanom' ); ?></p>
                        <p><button type="submit" class="button"><?php esc_html_e( 'Matikan 2FA', 'wscanom' ); ?></button></p>
                    </td>
                </tr>
            </table>
        </form>
    <?php elseif ( $pending_secret ) : ?>
        <p><?php esc_html_e( 'Setup belum selesai. Pindai atau masukkan kunci di bawah ke aplikasi authenticator-mu (Google Authenticator, Authy, Microsoft Authenticator, dll), lalu masukkan kode 6 digit yang muncul untuk menyelesaikan aktivasi.', 'wscanom' ); ?></p>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html_e( 'Kunci manual', 'wscanom' ); ?></th>
                <td><code style="font-size:15px;letter-spacing:1px;"><?php echo esc_html( chunk_split( $pending_secret, 4, ' ' ) ); ?></code>
                    <p class="description"><?php esc_html_e( 'Di aplikasi authenticator, pilih "Masukkan kunci setup secara manual" lalu tempel kunci ini (tanpa spasi).', 'wscanom' ); ?></p>
                </td>
            </tr>
        </table>
        <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
            <?php wp_nonce_field( 'wscanom_2fa_setup_confirm' ); ?>
            <input type="hidden" name="action" value="wscanom_2fa_setup_confirm" />
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><label for="wscanom_2fa_confirm_code"><?php esc_html_e( 'Kode konfirmasi', 'wscanom' ); ?></label></th>
                    <td>
                        <input type="text" name="wscanom_2fa_confirm_code" id="wscanom_2fa_confirm_code" class="regular-text" inputmode="numeric" autocomplete="off" required="required" />
                        <p><button type="submit" class="button button-primary"><?php esc_html_e( 'Konfirmasi & Aktifkan 2FA', 'wscanom' ); ?></button></p>
                    </td>
                </tr>
            </table>
        </form>
        <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:8px;">
            <?php wp_nonce_field( 'wscanom_2fa_setup_cancel' ); ?>
            <input type="hidden" name="action" value="wscanom_2fa_setup_cancel" />
            <button type="submit" class="button-link"><?php esc_html_e( 'Batalkan setup', 'wscanom' ); ?></button>
        </form>
    <?php else : ?>
        <p><?php esc_html_e( 'Tambahkan lapisan keamanan ekstra: setelah 2FA aktif, login butuh kode 6 digit dari aplikasi authenticator-mu selain password.', 'wscanom' ); ?></p>
        <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
            <?php wp_nonce_field( 'wscanom_2fa_setup_start' ); ?>
            <input type="hidden" name="action" value="wscanom_2fa_setup_start" />
            <button type="submit" class="button button-primary"><?php esc_html_e( 'Aktifkan Verifikasi Dua Langkah', 'wscanom' ); ?></button>
        </form>
    <?php endif; ?>
    <?php
}

add_action( 'admin_post_wscanom_2fa_setup_start', 'wscanom_handle_2fa_setup_start' );
/**
 * Mulai proses setup: buat kunci rahasia baru dan simpan sebagai "pending"
 * (BELUM aktif — 2FA baru benar-benar menyala di wscanom_handle_2fa_setup_confirm()
 * setelah kode dari aplikasi terbukti cocok).
 *
 * @return void
 */
function wscanom_handle_2fa_setup_start() {
    if ( ! is_user_logged_in() ) {
        wp_die( esc_html__( 'Kamu harus login.', 'wscanom' ) );
    }
    check_admin_referer( 'wscanom_2fa_setup_start' );

    $user_id = get_current_user_id();
    $secret  = wscanom_base32_encode( random_bytes( 20 ) );
    update_user_meta( $user_id, WSCANOM_2FA_PENDING_META, $secret );

    wp_safe_redirect( add_query_arg( array(), get_edit_user_link( $user_id ) ) . '#wscanom-2fa' );
    exit;
}

add_action( 'admin_post_wscanom_2fa_setup_cancel', 'wscanom_handle_2fa_setup_cancel' );
/**
 * Batalkan proses setup yang belum selesai.
 *
 * @return void
 */
function wscanom_handle_2fa_setup_cancel() {
    if ( ! is_user_logged_in() ) {
        wp_die( esc_html__( 'Kamu harus login.', 'wscanom' ) );
    }
    check_admin_referer( 'wscanom_2fa_setup_cancel' );

    $user_id = get_current_user_id();
    delete_user_meta( $user_id, WSCANOM_2FA_PENDING_META );

    wp_safe_redirect( get_edit_user_link( $user_id ) );
    exit;
}

add_action( 'admin_post_wscanom_2fa_setup_confirm', 'wscanom_handle_2fa_setup_confirm' );
/**
 * Selesaikan setup: HANYA kalau kode yang diinput user cocok dengan kunci
 * "pending" — ini pembuktian wajib bahwa aplikasi authenticator user sudah
 * benar-benar tersinkron, sebelum 2FA sungguhan diwajibkan saat login
 * berikutnya. Kalau tidak cocok, 2FA TIDAK aktif dan user tidak berisiko
 * terkunci dari situsnya sendiri.
 *
 * @return void
 */
function wscanom_handle_2fa_setup_confirm() {
    if ( ! is_user_logged_in() ) {
        wp_die( esc_html__( 'Kamu harus login.', 'wscanom' ) );
    }
    check_admin_referer( 'wscanom_2fa_setup_confirm' );

    $user_id = get_current_user_id();
    $pending = get_user_meta( $user_id, WSCANOM_2FA_PENDING_META, true );
    $code    = isset( $_POST['wscanom_2fa_confirm_code'] ) ? sanitize_text_field( wp_unslash( $_POST['wscanom_2fa_confirm_code'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing

    if ( ! $pending || ! wscanom_totp_verify( $pending, $code ) ) {
        wp_safe_redirect( add_query_arg( 'wscanom_2fa_notice', 'confirm_failed', get_edit_user_link( $user_id ) ) . '#wscanom-2fa' );
        exit;
    }

    update_user_meta( $user_id, WSCANOM_2FA_SECRET_META, $pending );
    update_user_meta( $user_id, WSCANOM_2FA_ENABLED_META, '1' );
    delete_user_meta( $user_id, WSCANOM_2FA_PENDING_META );

    $plain_codes = wscanom_2fa_generate_backup_codes( 8 );
    $hashed      = array_map( 'wscanom_2fa_hash_backup_code', $plain_codes );
    update_user_meta( $user_id, WSCANOM_2FA_BACKUP_META, $hashed );

    // Kode ASLI hanya disimpan sebentar (5 menit) semata untuk ditampilkan
    // SEKALI di reload halaman berikutnya — redirect menghapus data POST,
    // jadi tidak ada cara lain menampilkannya tanpa menyimpannya di DB
    // selamanya (yang justru kurang aman). Dihapus otomatis begitu tampil.
    set_transient( WSCANOM_2FA_SHOW_CODES_TRANSIENT_PREFIX . $user_id, $plain_codes, 5 * MINUTE_IN_SECONDS );

    if ( function_exists( 'wscanom_log_event' ) ) {
        $user = get_userdata( $user_id );
        wscanom_log_event(
            '2fa_enabled',
            sprintf(
                /* translators: %s: nama user */
                __( '2FA diaktifkan untuk akun "%s".', 'wscanom' ),
                $user ? $user->user_login : $user_id
            )
        );
    }

    wp_safe_redirect( get_edit_user_link( $user_id ) . '#wscanom-2fa' );
    exit;
}

add_action( 'admin_post_wscanom_2fa_disable', 'wscanom_handle_2fa_disable' );
/**
 * Matikan 2FA milik akun sendiri — butuh kode 2FA yang sedang valid sebagai
 * konfirmasi (mencegah seseorang yang hanya "menumpang" sesi browser yang
 * lupa logout mematikan 2FA orang lain dalam sekejap tanpa bukti apa pun).
 *
 * @return void
 */
function wscanom_handle_2fa_disable() {
    if ( ! is_user_logged_in() ) {
        wp_die( esc_html__( 'Kamu harus login.', 'wscanom' ) );
    }
    check_admin_referer( 'wscanom_2fa_disable' );

    $user_id = get_current_user_id();
    $secret  = get_user_meta( $user_id, WSCANOM_2FA_SECRET_META, true );
    $code    = isset( $_POST['wscanom_2fa_disable_code'] ) ? sanitize_text_field( wp_unslash( $_POST['wscanom_2fa_disable_code'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing

    if ( ! $secret || ! wscanom_totp_verify( $secret, $code ) ) {
        wp_safe_redirect( add_query_arg( 'wscanom_2fa_notice', 'disable_failed', get_edit_user_link( $user_id ) ) . '#wscanom-2fa' );
        exit;
    }

    delete_user_meta( $user_id, WSCANOM_2FA_SECRET_META );
    delete_user_meta( $user_id, WSCANOM_2FA_ENABLED_META );
    delete_user_meta( $user_id, WSCANOM_2FA_BACKUP_META );

    if ( function_exists( 'wscanom_log_event' ) ) {
        $user = get_userdata( $user_id );
        wscanom_log_event(
            '2fa_disabled',
            sprintf(
                /* translators: %s: nama user */
                __( '2FA dimatikan untuk akun "%s" (oleh pemilik akun).', 'wscanom' ),
                $user ? $user->user_login : $user_id
            )
        );
    }

    wp_safe_redirect( get_edit_user_link( $user_id ) );
    exit;
}

add_action( 'admin_post_wscanom_2fa_admin_disable', 'wscanom_handle_2fa_admin_disable' );
/**
 * Pemulihan darurat: admin mematikan 2FA milik USER LAIN yang kehilangan
 * akses (ponsel + semua kode cadangan hilang). Tidak bisa dipakai admin
 * untuk mengaktifkan atau melihat kunci rahasia user lain — hanya mematikan.
 *
 * @return void
 */
function wscanom_handle_2fa_admin_disable() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'Kamu tidak punya izin melakukan ini.', 'wscanom' ) );
    }

    $target_user = isset( $_POST['target_user'] ) ? (int) $_POST['target_user'] : 0; // phpcs:ignore WordPress.Security.NonceVerification.Missing
    check_admin_referer( 'wscanom_2fa_admin_disable_' . $target_user );

    if ( $target_user <= 0 ) {
        wp_die( esc_html__( 'User tidak valid.', 'wscanom' ) );
    }

    delete_user_meta( $target_user, WSCANOM_2FA_SECRET_META );
    delete_user_meta( $target_user, WSCANOM_2FA_ENABLED_META );
    delete_user_meta( $target_user, WSCANOM_2FA_BACKUP_META );
    delete_user_meta( $target_user, WSCANOM_2FA_PENDING_META );

    if ( function_exists( 'wscanom_log_event' ) ) {
        $target = get_userdata( $target_user );
        $admin  = wp_get_current_user();
        wscanom_log_event(
            '2fa_admin_disabled',
            sprintf(
                /* translators: 1: user yang di-reset, 2: admin yang melakukan */
                __( '2FA dimatikan paksa untuk akun "%1$s" oleh admin "%2$s" (pemulihan darurat).', 'wscanom' ),
                $target ? $target->user_login : $target_user,
                $admin->user_login
            )
        );
    }

    wp_safe_redirect( get_edit_user_link( $target_user ) );
    exit;
}

// ============================================================
// LANGKAH KEDUA SAAT LOGIN
// ============================================================

/**
 * Deteksi apakah permintaan saat ini benar-benar submit form login interaktif
 * di wp-login.php (bukan REST API, XML-RPC, atau Application Passwords) —
 * hanya konteks ini yang punya halaman untuk menampilkan layar verifikasi
 * kode 2FA. Mencegat jalur API lain di sini akan mematahkannya tanpa ada
 * cara bagi mereka untuk memasukkan kode sama sekali.
 *
 * @return bool
 */
function wscanom_is_interactive_login_request() {
    if ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || wp_doing_ajax() ) {
        return false;
    }
    $script = isset( $_SERVER['SCRIPT_NAME'] ) ? basename( sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash
    return 'wp-login.php' === $script;
}

add_filter( 'authenticate', 'wscanom_intercept_login_for_2fa', 40, 2 );
/**
 * Setelah password terbukti benar (dan lolos pembatas brute-force +
 * pemaksa-reset di prioritas sebelumnya), cek apakah akun ini punya 2FA
 * aktif. Kalau ya, JANGAN selesaikan login di sini — alihkan ke layar
 * verifikasi kode lewat redirect, dengan status "menunggu kode" disimpan
 * di transient sementara (kedaluwarsa 5 menit) yang ditautkan lewat token
 * acak di URL, bukan session PHP (supaya konsisten dengan sisa plugin yang
 * tidak bergantung session).
 *
 * @param null|WP_User|WP_Error $user     Hasil autentikasi sejauh ini.
 * @param string                $username Username yang dicoba (tidak dipakai langsung).
 * @return null|WP_User|WP_Error
 */
function wscanom_intercept_login_for_2fa( $user, $username ) {
    unset( $username );

    if ( ! ( $user instanceof WP_User ) ) {
        return $user; // password salah / sudah diblokir langkah sebelumnya — tidak relevan di sini.
    }

    if ( ! wscanom_user_has_2fa( $user->ID ) ) {
        return $user; // user ini tidak pakai 2FA — lanjutkan login seperti biasa.
    }

    if ( ! wscanom_is_interactive_login_request() ) {
        // Tidak ada halaman untuk menampilkan form kode (mis. REST/XML-RPC) —
        // demi keamanan TETAP TOLAK daripada diam-diam melewati 2FA.
        return new WP_Error(
            'wscanom_2fa_required',
            __( '<strong>Error:</strong> Akun ini memerlukan verifikasi dua langkah yang hanya bisa dilakukan lewat halaman login biasa.', 'wscanom' )
        );
    }

    $token   = wp_generate_password( 32, false, false );
    $remember = ! empty( $_POST['rememberme'] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
    set_transient(
        WSCANOM_2FA_PENDING_TRANSIENT_PREFIX . $token,
        array(
            'user_id'  => $user->ID,
            'remember' => $remember,
            'fails'    => 0,
        ),
        5 * MINUTE_IN_SECONDS
    );

    wp_safe_redirect(
        add_query_arg(
            array(
                'action'          => 'wscanom_2fa',
                'wscanom_token'   => $token,
            ),
            wp_login_url()
        )
    );
    exit;
}

add_action( 'login_init', 'wscanom_handle_2fa_verify_screen' );
/**
 * Tampilkan (dan proses submit) layar verifikasi kode 2FA, dipicu lewat
 * parameter `?action=wscanom_2fa&wscanom_token=...` yang dibuat oleh
 * wscanom_intercept_login_for_2fa(). Memakai login_header()/login_footer()
 * bawaan WordPress (sudah didefinisikan di titik ini dalam siklus muat
 * wp-login.php) supaya tampilannya konsisten dengan halaman login biasa.
 *
 * @return void
 */
function wscanom_handle_2fa_verify_screen() {
    if ( ! isset( $_GET['action'] ) || 'wscanom_2fa' !== $_GET['action'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        return;
    }

    $token = isset( $_GET['wscanom_token'] ) ? sanitize_text_field( wp_unslash( $_GET['wscanom_token'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    if ( isset( $_POST['wscanom_token'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $token = sanitize_text_field( wp_unslash( $_POST['wscanom_token'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
    }

    $transient_key = WSCANOM_2FA_PENDING_TRANSIENT_PREFIX . $token;
    $state         = get_transient( $transient_key );

    $error = '';

    if ( ! $token || ! is_array( $state ) || empty( $state['user_id'] ) ) {
        $error = __( 'Sesi verifikasi sudah kedaluwarsa atau tidak valid. Silakan login kembali.', 'wscanom' );
        $state = false;
    } elseif ( ! empty( $_POST['wscanom_2fa_submit'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $code = isset( $_POST['wscanom_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['wscanom_2fa_code'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $user_id = (int) $state['user_id'];
        $secret  = get_user_meta( $user_id, WSCANOM_2FA_SECRET_META, true );

        $ok = $secret && wscanom_totp_verify( $secret, $code );
        if ( ! $ok ) {
            $ok = wscanom_2fa_consume_backup_code( $user_id, $code );
        }

        if ( $ok ) {
            delete_transient( $transient_key );

            $user = get_userdata( $user_id );
            wp_set_auth_cookie( $user_id, ! empty( $state['remember'] ) );
            do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.ValidHookName.UseUnderscores

            if ( function_exists( 'wscanom_log_event' ) ) {
                wscanom_log_event(
                    '2fa_verified',
                    sprintf(
                        /* translators: %s: nama user */
                        __( 'Verifikasi 2FA berhasil untuk akun "%s".', 'wscanom' ),
                        $user->user_login
                    )
                );
            }

            $redirect_to = isset( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : admin_url(); // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
            wp_safe_redirect( $redirect_to );
            exit;
        }

        $state['fails'] = ( isset( $state['fails'] ) ? (int) $state['fails'] : 0 ) + 1;
        if ( $state['fails'] >= 5 ) {
            delete_transient( $transient_key );
            $error = __( 'Terlalu banyak percobaan kode yang gagal. Demi keamanan, silakan login ulang dari awal.', 'wscanom' );
            $state = false;
        } else {
            set_transient( $transient_key, $state, 5 * MINUTE_IN_SECONDS );
            $error = __( 'Kode salah atau sudah kedaluwarsa. Coba lagi.', 'wscanom' );
        }
    }

    login_header( __( 'Verifikasi Dua Langkah', 'wscanom' ), '', is_wp_error( $error ) ? $error : '' );
    ?>
    <?php if ( $error ) : ?>
        <div id="login_error"><?php echo esc_html( $error ); ?></div>
    <?php endif; ?>

    <?php if ( $state ) : ?>
        <form name="wscanomloginform" id="wscanomloginform" action="<?php echo esc_url( add_query_arg( array( 'action' => 'wscanom_2fa' ), wp_login_url() ) ); ?>" method="post">
            <p>
                <label for="wscanom_2fa_code"><?php esc_html_e( 'Kode verifikasi', 'wscanom' ); ?></label>
                <input type="text" name="wscanom_2fa_code" id="wscanom_2fa_code" class="input" size="20" autocomplete="one-time-code" autofocus="autofocus" inputmode="numeric" />
            </p>
            <p class="description"><?php esc_html_e( 'Masukkan kode 6 digit dari aplikasi authenticator-mu, atau salah satu kode cadangan (format XXXX-XXXX) kalau ponselmu tidak bisa diakses.', 'wscanom' ); ?></p>
            <input type="hidden" name="wscanom_token" value="<?php echo esc_attr( $token ); ?>" />
            <input type="hidden" name="wscanom_2fa_submit" value="1" />
            <p class="submit">
                <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verifikasi', 'wscanom' ); ?>" />
            </p>
        </form>
    <?php endif; ?>

    <p id="backtoblog"><a href="<?php echo esc_url( wp_login_url() ); ?>"><?php esc_html_e( '← Kembali ke halaman login', 'wscanom' ); ?></a></p>
    <?php
    login_footer();
    exit;
}
