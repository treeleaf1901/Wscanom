<?php
/**
 * WScanom — Handler AJAX untuk scan bertahap (chunked) dan whitelist.
 *
 * @package WScanom
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Pastikan permintaan AJAX sah: nonce cocok dan user punya kapabilitas.
 *
 * @return void Keluar dengan wp_send_json_error() jika gagal.
 */
function wscanom_ajax_guard() {
    if ( ! check_ajax_referer( 'wscanom_ajax', 'nonce', false ) ) {
        wp_send_json_error( array( 'message' => __( 'Nonce tidak valid, muat ulang halaman.', 'wscanom' ) ), 403 );
    }
    if ( ! current_user_can( wscanom_required_cap() ) ) {
        wp_send_json_error( array( 'message' => __( 'Kamu tidak punya izin melakukan ini.', 'wscanom' ) ), 403 );
    }
}

/**
 * Langkah 1: kembalikan daftar path file .php yang akan dipindai.
 * Ini cepat (tidak membaca isi file), supaya browser bisa membangun
 * progress bar sebelum scan isi file dimulai.
 */
add_action( 'wp_ajax_wscanom_get_file_list', 'wscanom_ajax_get_file_list' );
function wscanom_ajax_get_file_list() {
    wscanom_ajax_guard();

    $base  = wscanom_scan_base_dir();
    $files = wscanom_list_php_files( $base );

    wp_send_json_success(
        array(
            'total' => count( $files ),
            'files' => $files,
        )
    );
}

/**
 * Langkah 2: pindai satu batch file (dipanggil berulang dari JS sampai habis).
 * Batch kecil per permintaan supaya tiap request PHP tetap ringan dan
 * tidak kena limit waktu eksekusi di situs dengan ribuan file.
 */
add_action( 'wp_ajax_wscanom_scan_batch', 'wscanom_ajax_scan_batch' );
function wscanom_ajax_scan_batch() {
    wscanom_ajax_guard();

    $base  = wscanom_scan_base_dir();
    $paths = isset( $_POST['paths'] ) ? (array) wp_unslash( $_POST['paths'] ) : array(); // phpcs:ignore WordPress.Security.NonceVerification.Missing

    $results = array();

    foreach ( $paths as $relative_path ) {
        $relative_path = wscanom_sanitize_relative_path( $relative_path );
        if ( '' === $relative_path ) {
            continue;
        }

        $full_path = $base . '/' . $relative_path;

        // Jaga-jaga: pastikan path hasil gabungan tetap di dalam base dir
        // (mencegah path traversal lewat input yang dimanipulasi).
        $real_full = realpath( $full_path );
        $real_base = realpath( $base );
        if ( ! $real_full || ! $real_base || 0 !== strpos( $real_full, $real_base ) ) {
            continue;
        }

        $scan = wscanom_scan_file( $real_full, $relative_path );

        if ( $scan['score'] > 0 || $scan['whitelisted'] ) {
            $results[] = array(
                'file'        => $relative_path,
                'score'       => $scan['score'],
                'findings'    => wp_list_pluck( $scan['findings'], 'catatan' ),
                'whitelisted' => $scan['whitelisted'],
                'hash'        => $scan['hash'],
            );
        }
    }

    wp_send_json_success( array( 'results' => $results ) );
}

/**
 * Tandai satu file sebagai aman (whitelist), dipanggil dari tombol di tabel hasil.
 */
add_action( 'wp_ajax_wscanom_whitelist_add', 'wscanom_ajax_whitelist_add' );
function wscanom_ajax_whitelist_add() {
    wscanom_ajax_guard();

    $relative_path = isset( $_POST['file'] ) ? wscanom_sanitize_relative_path( wp_unslash( $_POST['file'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
    $hash           = isset( $_POST['hash'] ) ? sanitize_text_field( wp_unslash( $_POST['hash'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing

    if ( '' === $relative_path || ! preg_match( '/^[0-9a-f]{64}$/', $hash ) ) {
        wp_send_json_error( array( 'message' => __( 'Data tidak valid.', 'wscanom' ) ) );
    }

    wscanom_add_to_whitelist( $relative_path, $hash );
    wp_send_json_success();
}

/**
 * Keluarkan file dari whitelist (batalkan "tandai aman").
 */
add_action( 'wp_ajax_wscanom_whitelist_remove', 'wscanom_ajax_whitelist_remove' );
function wscanom_ajax_whitelist_remove() {
    wscanom_ajax_guard();

    $relative_path = isset( $_POST['file'] ) ? wscanom_sanitize_relative_path( wp_unslash( $_POST['file'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing

    if ( '' === $relative_path ) {
        wp_send_json_error( array( 'message' => __( 'Data tidak valid.', 'wscanom' ) ) );
    }

    wscanom_remove_from_whitelist( $relative_path );
    wp_send_json_success();
}

/**
 * Bersihkan path relatif dari input: hanya izinkan karakter wajar,
 * buang usaha path traversal ("../"), paksa pemisah "/".
 *
 * @param string $path Path mentah dari input.
 * @return string
 */
function wscanom_sanitize_relative_path( $path ) {
    $path = str_replace( '\\', '/', (string) $path );
    $path = ltrim( $path, '/' );
    // Buang segmen ".." supaya tidak bisa keluar dari base dir.
    $segments = array_filter(
        explode( '/', $path ),
        function ( $segment ) {
            return '' !== $segment && '.' !== $segment && '..' !== $segment;
        }
    );
    return implode( '/', $segments );
}

/**
 * Validasi path relatif menjadi path absolut yang dipastikan tetap berada
 * di dalam base dir (pertahanan berlapis terhadap path traversal).
 *
 * @param string $relative_path Path relatif (sudah disanitasi).
 * @return string|false Path absolut, atau false kalau di luar base dir / tidak ada.
 */
function wscanom_resolve_within_base( $relative_path ) {
    $base      = wscanom_scan_base_dir();
    $full_path = rtrim( $base, '/' ) . '/' . $relative_path;

    $real_full = realpath( $full_path );
    $real_base = realpath( $base );

    if ( ! $real_full || ! $real_base || 0 !== strpos( $real_full, $real_base ) ) {
        return false;
    }

    return $real_full;
}

/**
 * Pindahkan satu file ke karantina. Ini aksi yang mengubah filesystem
 * (bukan sekadar baca), jadi kapabilitas diharuskan 'manage_options' secara
 * eksplisit (bukan lewat wscanom_required_cap(), yang bisa melonggar jadi
 * 'manage_network' dalam konteks Network Admin — karantina selalu aksi
 * per-situs, bukan lintas-jaringan).
 */
add_action( 'wp_ajax_wscanom_quarantine_file', 'wscanom_ajax_quarantine_file' );
function wscanom_ajax_quarantine_file() {
    if ( ! check_ajax_referer( 'wscanom_ajax', 'nonce', false ) ) {
        wp_send_json_error( array( 'message' => __( 'Nonce tidak valid, muat ulang halaman.', 'wscanom' ) ), 403 );
    }
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( array( 'message' => __( 'Kamu tidak punya izin melakukan ini.', 'wscanom' ) ), 403 );
    }

    $relative_path = isset( $_POST['file'] ) ? wscanom_sanitize_relative_path( wp_unslash( $_POST['file'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
    if ( '' === $relative_path ) {
        wp_send_json_error( array( 'message' => __( 'Data tidak valid.', 'wscanom' ) ) );
    }

    $full_path = wscanom_resolve_within_base( $relative_path );
    if ( ! $full_path ) {
        wp_send_json_error( array( 'message' => __( 'File tidak ditemukan atau di luar jangkauan yang diizinkan.', 'wscanom' ) ) );
    }

    $result = wscanom_quarantine_file( $full_path, $relative_path );

    if ( is_wp_error( $result ) ) {
        wp_send_json_error( array( 'message' => $result->get_error_message() ) );
    }

    wp_send_json_success( array( 'id' => $result ) );
}

/**
 * Pindai file sentinel di root WordPress (index.php, wp-config.php, dll).
 * Daftar pendek dan tetap, jadi tidak perlu scan bertahap seperti wp-content.
 */
add_action( 'wp_ajax_wscanom_scan_root', 'wscanom_ajax_scan_root' );
function wscanom_ajax_scan_root() {
    wscanom_ajax_guard();

    $results = array();

    foreach ( wscanom_list_root_sentinel_files() as $file ) {
        $scan = wscanom_scan_file( $file['full'], $file['relative'] );

        if ( $scan['score'] > 0 || $scan['whitelisted'] ) {
            $results[] = array(
                'file'        => $file['relative'],
                'score'       => $scan['score'],
                'findings'    => wp_list_pluck( $scan['findings'], 'catatan' ),
                'whitelisted' => $scan['whitelisted'],
                'hash'        => $scan['hash'],
                'isRoot'      => true,
            );
        }
    }

    wp_send_json_success( array( 'results' => $results ) );
}

/**
 * Bersihkan blok tersuntik (pola "XXX-CORE-START/END") dari file sentinel
 * root, in-place. Berbeda dari karantina: file TIDAK dipindah (tidak bisa,
 * situs butuh file ini), hanya blok yang cocok pola yang dibuang, dan
 * seluruh isi sebelum dibersihkan disimpan sebagai backup yang bisa
 * dipulihkan dari tabel karantina.
 */
add_action( 'wp_ajax_wscanom_strip_block', 'wscanom_ajax_strip_block' );
function wscanom_ajax_strip_block() {
    if ( ! check_ajax_referer( 'wscanom_ajax', 'nonce', false ) ) {
        wp_send_json_error( array( 'message' => __( 'Nonce tidak valid, muat ulang halaman.', 'wscanom' ) ), 403 );
    }
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( array( 'message' => __( 'Kamu tidak punya izin melakukan ini.', 'wscanom' ) ), 403 );
    }

    $relative_path = isset( $_POST['file'] ) ? sanitize_text_field( wp_unslash( $_POST['file'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing

    $full_path = wscanom_resolve_root_sentinel( $relative_path );
    if ( ! $full_path ) {
        wp_send_json_error( array( 'message' => __( 'File tidak dikenali sebagai file sentinel root yang valid.', 'wscanom' ) ) );
    }

    $result = wscanom_strip_marker_blocks( $full_path, $relative_path );

    if ( is_wp_error( $result ) ) {
        wp_send_json_error( array( 'message' => $result->get_error_message() ) );
    }

    wp_send_json_success( $result );
}
