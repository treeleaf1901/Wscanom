<?php
/**
 * WScanom — Uninstall cleanup.
 *
 * Dijalankan WordPress hanya saat plugin dihapus (bukan sekadar
 * dinonaktifkan) lewat halaman Plugins. Membersihkan semua data yang
 * disimpan plugin ini: whitelist, ringkasan scan terakhir, dan pengaturan.
 *
 * @package WScanom
 */

// Pastikan file ini hanya dieksekusi oleh WordPress saat proses uninstall.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

/**
 * Hapus folder beserta isinya secara rekursif. Dipakai untuk membersihkan
 * folder karantina saat uninstall penuh — tidak memakai WP_Filesystem
 * karena uninstall.php berjalan tanpa inisialisasinya secara default.
 *
 * @param string $dir Path absolut folder yang akan dihapus.
 * @return void
 */
function wscanom_uninstall_rrmdir( $dir ) {
    if ( ! is_dir( $dir ) ) {
        return;
    }

    $items = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ( $items as $item ) {
        if ( $item->isDir() ) {
            @rmdir( $item->getPathname() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
        } else {
            @unlink( $item->getPathname() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
        }
    }

    @rmdir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
}

/**
 * Hapus seluruh option dan data milik plugin ini untuk satu situs,
 * termasuk folder karantina beserta isinya (sampel malware yang
 * dikarantina tidak perlu disimpan setelah plugin dihapus total).
 *
 * @return void
 */
function wscanom_uninstall_cleanup_site() {
    delete_option( 'wscanom_whitelist' );
    delete_option( 'wscanom_last_scan_summary' );
    delete_option( 'wscanom_settings' );
    delete_option( 'wscanom_quarantine_log' );
    delete_option( 'wscanom_activity_log' );
    delete_transient( 'wscanom_cron_resume_state' );

    // Bersihkan tanda "wajib reset password" (dari fitur Aksi Darurat) yang
    // mungkin masih tersisa di user meta — tanpa ini, flag itu akan tetap
    // ada selamanya di database meski plugin sudah dihapus total, dan kalau
    // plugin ini (atau sejenisnya) terpasang lagi nanti bisa memicu perilaku
    // tak terduga dari data lama yang sudah tidak relevan.
    delete_metadata( 'user', 0, 'wscanom_force_reset', '', true );

    $timestamp = wp_next_scheduled( 'wscanom_scheduled_scan' );
    if ( $timestamp ) {
        wp_unschedule_event( $timestamp, 'wscanom_scheduled_scan' );
    }

    $continue_timestamp = wp_next_scheduled( 'wscanom_scheduled_scan_continue' );
    if ( $continue_timestamp ) {
        wp_unschedule_event( $continue_timestamp, 'wscanom_scheduled_scan_continue' );
    }

    if ( defined( 'WP_CONTENT_DIR' ) ) {
        wscanom_uninstall_rrmdir( WP_CONTENT_DIR . '/wscanom-quarantine' );
    }
}

if ( is_multisite() ) {
    $sites = get_sites( array( 'number' => 0 ) );
    foreach ( $sites as $site ) {
        switch_to_blog( $site->blog_id );
        wscanom_uninstall_cleanup_site();
        restore_current_blog();
    }
} else {
    wscanom_uninstall_cleanup_site();
}
