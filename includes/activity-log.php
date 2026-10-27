<?php
/**
 * WScanom — Log aktivitas keamanan ringan: siapa login/gagal login kapan,
 * aksi darurat yang dijalankan, dan perubahan pengaturan proteksi.
 *
 * Sengaja disimpan sebagai SATU option (bukan tabel database terpisah) biar
 * tetap konsisten dengan sisa plugin ini (tidak ada dbDelta/migrasi skema
 * yang perlu dijaga), dengan jumlah entri dibatasi (dibuang yang paling
 * lama) supaya tidak tumbuh tanpa batas selamanya.
 *
 * @package WScanom
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'WSCANOM_LOG_OPTION', 'wscanom_activity_log' );
define( 'WSCANOM_LOG_MAX_ENTRIES', 300 );

/**
 * Catat satu kejadian ke log aktivitas.
 *
 * @param string $type    Jenis kejadian (mis. "login_failed", "emergency_action").
 * @param string $message Pesan sudah-jadi dalam bahasa yang ditampilkan ke admin.
 * @return void
 */
function wscanom_log_event( $type, $message ) {
    $log = get_option( WSCANOM_LOG_OPTION, array() );
    if ( ! is_array( $log ) ) {
        $log = array();
    }

    array_unshift(
        $log,
        array(
            'time'    => time(),
            'type'    => sanitize_key( $type ),
            'message' => wp_strip_all_tags( $message ),
        )
    );

    if ( count( $log ) > WSCANOM_LOG_MAX_ENTRIES ) {
        $log = array_slice( $log, 0, WSCANOM_LOG_MAX_ENTRIES );
    }

    update_option( WSCANOM_LOG_OPTION, $log, false );
}

/**
 * Ambil entri log aktivitas, terbaru dulu.
 *
 * @param int $limit Jumlah maksimum entri yang dikembalikan.
 * @return array
 */
function wscanom_get_log_entries( $limit = 50 ) {
    $log = get_option( WSCANOM_LOG_OPTION, array() );
    if ( ! is_array( $log ) ) {
        return array();
    }
    return array_slice( $log, 0, max( 1, (int) $limit ) );
}

/**
 * Label manusiawi untuk tiap jenis kejadian, dipakai di tampilan log.
 *
 * @param string $type Jenis kejadian.
 * @return string
 */
function wscanom_log_type_label( $type ) {
    $labels = array(
        'login_failed'     => __( 'Login gagal', 'wscanom' ),
        'login_success'    => __( 'Login berhasil', 'wscanom' ),
        'emergency_action' => __( 'Aksi darurat', 'wscanom' ),
        'settings_changed' => __( 'Pengaturan diubah', 'wscanom' ),
        'quarantine'       => __( 'Karantina', 'wscanom' ),
        'scan'             => __( 'Scan', 'wscanom' ),
        '2fa_enabled'      => __( '2FA diaktifkan', 'wscanom' ),
        '2fa_disabled'     => __( '2FA dimatikan', 'wscanom' ),
        '2fa_admin_disabled' => __( '2FA dimatikan paksa (admin)', 'wscanom' ),
        '2fa_verified'     => __( 'Verifikasi 2FA', 'wscanom' ),
    );

    return isset( $labels[ $type ] ) ? $labels[ $type ] : ucfirst( str_replace( '_', ' ', $type ) );
}

/**
 * Catat perubahan pengaturan proteksi ke log, supaya kalau terjadi sesuatu
 * admin bisa telusuri "pengaturan apa yang berubah dan kapan" — berguna
 * khusus untuk pengaturan berisiko (XML-RPC, dll) yang masuk tabel manual.
 *
 * @param array $old_settings Pengaturan sebelum diubah.
 * @param array $new_settings Pengaturan sesudah diubah.
 * @return void
 */
function wscanom_log_settings_diff( $old_settings, $new_settings ) {
    $changed = array();
    foreach ( $new_settings as $key => $value ) {
        $old = $old_settings[ $key ] ?? null;
        if ( $old !== $value ) {
            $changed[] = $key;
        }
    }

    if ( empty( $changed ) ) {
        return;
    }

    wscanom_log_event(
        'settings_changed',
        sprintf(
            /* translators: %s: daftar nama pengaturan yang berubah */
            __( 'Pengaturan berubah: %s', 'wscanom' ),
            implode( ', ', $changed )
        )
    );
}
