<?php
/**
 * Plugin Name:       WScanom
 * Plugin URI:        https://github.com/treeleaf/wscanom
 * Description:       Pemindai pola webshell/backdoor pada file .php di wp-content — scan bertahap (tidak membebani server), whitelist, riwayat scan, dan notifikasi email — plus proteksi aktif: brute-force login, CAPTCHA, verifikasi dua langkah (2FA), pengerasan XML-RPC, pengerasan privasi, log aktivitas, pemeriksaan kesehatan server, dan aksi darurat. Pemeriksaan tambahan, bukan pengganti scanner keamanan utama.
 * Version:           1.6.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Tree Leaf
 * Author URI:        https://github.com/treeleaf
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wscanom
 * Domain Path:       /languages
 * Network:           true
 *
 * @package WScanom
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Cegah akses langsung ke file ini.
}

define( 'WSCANOM_VERSION', '1.6.0' );
define( 'WSCANOM_FILE', __FILE__ );
define( 'WSCANOM_DIR', plugin_dir_path( __FILE__ ) );

require_once WSCANOM_DIR . 'includes/patterns.php';
require_once WSCANOM_DIR . 'includes/scanner.php';
require_once WSCANOM_DIR . 'includes/cron.php';
require_once WSCANOM_DIR . 'includes/activity-log.php';
require_once WSCANOM_DIR . 'includes/hardening.php';
require_once WSCANOM_DIR . 'includes/login-protection.php';
require_once WSCANOM_DIR . 'includes/captcha.php';
require_once WSCANOM_DIR . 'includes/two-factor.php';
require_once WSCANOM_DIR . 'includes/privacy-hardening.php';
require_once WSCANOM_DIR . 'includes/health-check.php';
require_once WSCANOM_DIR . 'includes/admin-page.php';
require_once WSCANOM_DIR . 'includes/ajax.php';

/**
 * Muat berkas terjemahan plugin.
 *
 * @return void
 */
function wscanom_load_textdomain() {
    load_plugin_textdomain( 'wscanom', false, dirname( plugin_basename( WSCANOM_FILE ) ) . '/languages' );
}
add_action( 'plugins_loaded', 'wscanom_load_textdomain' );

/**
 * Inisialisasi WP_Filesystem secara dini (dipakai scanner.php untuk membaca
 * file lewat API resmi, bukan fungsi file PHP mentah).
 *
 * @return void
 */
function wscanom_init_filesystem() {
    global $wp_filesystem;
    if ( ! $wp_filesystem ) {
        require_once ABSPATH . 'wp-admin/includes/file.php';
        WP_Filesystem();
    }
}
add_action( 'admin_init', 'wscanom_init_filesystem' );
add_action( WSCANOM_CRON_HOOK, 'wscanom_init_filesystem', 5 ); // sebelum scan terjadwal jalan.
add_action( WSCANOM_CRON_CONTINUE_HOOK, 'wscanom_init_filesystem', 5 ); // sebelum lanjutan scan terjadwal jalan.

register_activation_hook( WSCANOM_FILE, 'wscanom_on_activate' );
/**
 * Dijalankan saat plugin diaktifkan: jadwalkan scan harian.
 *
 * @return void
 */
function wscanom_on_activate() {
    wscanom_schedule_cron();
    // Pasang proteksi exec-deny di uploads segera, bukan menunggu scan
    // terjadwal pertama (bisa sampai 1 jam + jadwal harian berikutnya).
    if ( function_exists( 'wscanom_write_uploads_exec_deny' ) ) {
        wscanom_write_uploads_exec_deny();
    }
    // Tandai supaya permintaan wp-admin BERIKUTNYA (bukan permintaan
    // aktivasi ini sendiri, yang masih di tengah proses redirect WordPress
    // sendiri) mengarahkan admin ke halaman sambutan. Umur pendek (cukup
    // untuk satu kali muat halaman admin berikutnya) supaya tidak nyangkut
    // kalau transient gagal terhapus karena sebab apa pun.
    set_transient( 'wscanom_activation_redirect', true, MINUTE_IN_SECONDS );
}

register_deactivation_hook( WSCANOM_FILE, 'wscanom_on_deactivate' );
/**
 * Dijalankan saat plugin dinonaktifkan: batalkan jadwal scan.
 * Data (whitelist, riwayat) sengaja TIDAK dihapus di sini supaya aktivasi
 * ulang tidak kehilangan histori; penghapusan data hanya terjadi saat
 * uninstall penuh (lihat uninstall.php).
 *
 * @return void
 */
function wscanom_on_deactivate() {
    wscanom_unschedule_cron();
}

/**
 * Tambahkan tautan "Settings"/"Scan" singkat di halaman daftar plugin.
 *
 * @param array $links Tautan aksi yang sudah ada.
 * @return array
 */
function wscanom_plugin_action_links( $links ) {
    $scan_link = '<a href="' . esc_url( admin_url( 'tools.php?page=wscanom' ) ) . '">' . esc_html__( 'Scan', 'wscanom' ) . '</a>';
    array_unshift( $links, $scan_link );
    return $links;
}
add_filter( 'plugin_action_links_' . plugin_basename( WSCANOM_FILE ), 'wscanom_plugin_action_links' );
