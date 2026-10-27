<?php
/**
 * WScanom — Pengecekan kesehatan server, BACA-SAJA.
 *
 * Penting untuk jujur soal batasnya: plugin WordPress TIDAK BISA memperbaiki
 * konfigurasi server (itu butuh akses di luar jangkauan PHP). File ini
 * murni memeriksa dan melaporkan, lalu menyarankan — tidak pernah mengubah
 * apa pun di server secara otomatis.
 *
 * @package WScanom
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Jalankan seluruh pengecekan dan kembalikan hasilnya.
 *
 * @return array<int,array{label:string,status:string,detail:string}> status: 'ok'|'warn'|'bad'.
 */
function wscanom_run_health_checks() {
    $checks = array();

    // --- Versi PHP ---
    $php_version = PHP_VERSION;
    $checks[]    = array(
        'label'  => __( 'Versi PHP', 'wscanom' ),
        'status' => version_compare( $php_version, '8.1', '>=' ) ? 'ok' : ( version_compare( $php_version, '7.4', '>=' ) ? 'warn' : 'bad' ),
        'detail' => sprintf(
            /* translators: %s: versi PHP */
            __( 'Terpasang: %s. Versi PHP yang sudah tidak didukung resmi (end-of-life) tidak lagi menerima tambalan keamanan dari tim PHP.', 'wscanom' ),
            $php_version
        ),
    );

    // --- HTTPS ---
    $checks[] = array(
        'label'  => __( 'HTTPS', 'wscanom' ),
        'status' => wscanom_site_uses_https() ? 'ok' : 'bad',
        'detail' => wscanom_site_uses_https()
            ? __( 'Situs sudah diakses lewat HTTPS.', 'wscanom' )
            : __( 'Situs belum HTTPS. Hubungi hosting untuk mengaktifkan SSL — WScanom tidak bisa memasangnya sendiri.', 'wscanom' ),
    );

    // --- display_errors ---
    $display_errors = (string) ini_get( 'display_errors' );
    $checks[]       = array(
        'label'  => __( 'Tampilkan error PHP ke publik', 'wscanom' ),
        'status' => in_array( strtolower( $display_errors ), array( '1', 'on', 'true' ), true ) ? 'warn' : 'ok',
        'detail' => __( 'Kalau aktif di situs produksi, pesan error PHP (yang bisa membocorkan path server/struktur kode) tampil ke pengunjung biasa. Idealnya dimatikan di wp-config.php (WP_DEBUG_DISPLAY => false) untuk situs yang sudah live.', 'wscanom' ),
    );

    // --- file editor ---
    $editor_disabled = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
    $checks[]        = array(
        'label'  => __( 'Theme/Plugin Editor', 'wscanom' ),
        'status' => $editor_disabled ? 'ok' : 'warn',
        'detail' => $editor_disabled
            ? __( 'Sudah dimatikan (lewat WScanom atau wp-config.php).', 'wscanom' )
            : __( 'Masih aktif. WScanom sudah mencoba mematikan ini otomatis — kalau status di sini masih "belum", kemungkinan ada plugin/konfigurasi lain yang menyalakannya kembali.', 'wscanom' ),
    );

    // --- listing direktori wp-content ---
    $index_exists = file_exists( rtrim( WP_CONTENT_DIR, '/' ) . '/index.php' );
    $checks[]     = array(
        'label'  => __( 'Listing folder wp-content', 'wscanom' ),
        'status' => $index_exists ? 'ok' : 'warn',
        'detail' => $index_exists
            ? __( 'Folder wp-content punya index.php kosong, mencegah listing isi folder kalau server salah konfigurasi.', 'wscanom' )
            : __( 'Tidak ditemukan index.php kosong di wp-content. Kalau server salah konfigurasi (Options +Indexes di Apache), isi folder ini bisa tampil ke publik.', 'wscanom' ),
    );

    // --- WP_DEBUG di produksi ---
    $wp_debug = defined( 'WP_DEBUG' ) && WP_DEBUG;
    $checks[] = array(
        'label'  => __( 'Mode Debug WordPress', 'wscanom' ),
        'status' => $wp_debug ? 'warn' : 'ok',
        'detail' => $wp_debug
            ? __( 'WP_DEBUG aktif. Wajar untuk situs pengembangan, tapi sebaiknya dimatikan di situs produksi yang sudah live.', 'wscanom' )
            : __( 'Tidak aktif — sesuai untuk situs produksi.', 'wscanom' ),
    );

    // --- auto-update core keamanan ---
    $auto_updates_disabled = defined( 'AUTOMATIC_UPDATER_DISABLED' ) && AUTOMATIC_UPDATER_DISABLED;
    $checks[]               = array(
        'label'  => __( 'Update keamanan otomatis WordPress', 'wscanom' ),
        'status' => $auto_updates_disabled ? 'warn' : 'ok',
        'detail' => $auto_updates_disabled
            ? __( 'Dimatikan lewat konstanta AUTOMATIC_UPDATER_DISABLED. Situs tidak akan menerima tambalan keamanan inti WordPress secara otomatis.', 'wscanom' )
            : __( 'Aktif — situs akan menerima tambalan keamanan inti WordPress secara otomatis.', 'wscanom' ),
    );

    // --- Larang eksekusi PHP di uploads: VERIFIKASI NYATA lewat percobaan
    // HTTP sungguhan, bukan cuma memeriksa file .htaccess ada atau tidak
    // (lihat includes/hardening.php — keberadaan file TIDAK membuktikan
    // server benar-benar menghormatinya, terutama di nginx). ---
    if ( function_exists( 'wscanom_get_exec_deny_probe_result' ) ) {
        $probe      = wscanom_get_exec_deny_probe_result();
        $status_map = array(
            'verified_blocked' => 'ok',
            'not_blocked'      => 'bad',
            'inconclusive'     => 'warn',
        );
        $checks[] = array(
            'label'  => __( 'Larang eksekusi PHP di uploads (terverifikasi)', 'wscanom' ),
            'status' => $status_map[ $probe['status'] ] ?? 'warn',
            'detail' => $probe['detail'],
        );
    }

    return $checks;
}
