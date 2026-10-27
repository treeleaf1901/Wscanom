<?php
/**
 * WScanom — Halaman admin, menu, dan enqueue asset.
 *
 * @package WScanom
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Kapabilitas yang dibutuhkan untuk mengakses scanner.
 * Di jaringan multisite, scan lintas-situs lewat Network Admin butuh 'manage_network'.
 *
 * @return string
 */
function wscanom_required_cap() {
    return is_network_admin() ? 'manage_network' : 'manage_options';
}

/**
 * Tangani submit form pengaturan proteksi (matikan Theme/Plugin Editor,
 * auto-karantina, dsb). Pakai admin-post.php biasa (bukan AJAX) karena ini
 * aksi yang jarang dipakai dan lebih sederhana dengan reload halaman biasa.
 * Dipakai bersama oleh halaman pengaturan utama dan halaman sambutan
 * pertama aktivasi — "redirect_to" dan "first" dari form menentukan admin
 * dibawa kembali ke halaman mana setelah simpan.
 */
add_action( 'admin_post_wscanom_save_settings', 'wscanom_handle_save_settings_request' );
function wscanom_handle_save_settings_request() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'Kamu tidak punya izin melakukan ini.', 'wscanom' ) );
    }

    check_admin_referer( 'wscanom_save_settings' );

    // DIGABUNG (bukan ditimpa total) ke pengaturan yang sudah ada — halaman
    // ini punya beberapa form terpisah (Pengaturan Proteksi, Pengerasan
    // Lanjutan), dan tiap form cuma mengirim field miliknya sendiri lewat
    // POST. Kalau ditimpa total, menyimpan form yang satu akan diam-diam
    // mereset checkbox di form yang lain balik ke "mati" (karena checkbox
    // yang tidak dicentang memang tidak pernah ikut terkirim di $_POST).
    $old_settings = wscanom_get_settings();
    $settings     = array_merge(
        $old_settings,
        array(
            'email_alerts'               => ! empty( $_POST['email_alerts'] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
            'alert_min_score'            => isset( $_POST['alert_min_score'] ) ? max( 1, min( 10, (int) $_POST['alert_min_score'] ) ) : 7, // phpcs:ignore WordPress.Security.NonceVerification.Missing
            'disable_file_editor'        => ! empty( $_POST['disable_file_editor'] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
            'auto_quarantine'            => ! empty( $_POST['auto_quarantine'] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
            'auto_quarantine_min_weight' => isset( $_POST['auto_quarantine_min_weight'] ) ? max( 1, min( 10, (int) $_POST['auto_quarantine_min_weight'] ) ) : 9, // phpcs:ignore WordPress.Security.NonceVerification.Missing
            'bruteforce_protection'      => ! empty( $_POST['bruteforce_protection'] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
            'bruteforce_max_attempts'    => isset( $_POST['bruteforce_max_attempts'] ) ? max( 3, min( 20, (int) $_POST['bruteforce_max_attempts'] ) ) : 5, // phpcs:ignore WordPress.Security.NonceVerification.Missing
            'bruteforce_lockout_minutes' => isset( $_POST['bruteforce_lockout_minutes'] ) ? max( 1, min( 1440, (int) $_POST['bruteforce_lockout_minutes'] ) ) : 20, // phpcs:ignore WordPress.Security.NonceVerification.Missing
            'login_captcha'              => ! empty( $_POST['login_captcha'] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
        )
    );

    update_option( WSCANOM_SETTINGS_OPTION, $settings, false );
    if ( function_exists( 'wscanom_log_settings_diff' ) ) {
        wscanom_log_settings_diff( $old_settings, $settings );
    }

    $target_page = ( isset( $_POST['redirect_to'] ) && 'welcome' === $_POST['redirect_to'] ) ? 'wscanom-welcome' : 'wscanom'; // phpcs:ignore WordPress.Security.NonceVerification.Missing
    $redirect_args = array(
        'page'           => $target_page,
        'wscanom_notice' => 'settings_saved',
    );
    if ( 'wscanom-welcome' === $target_page ) {
        // Setelah simpan dari halaman sambutan, lanjut langsung ke scan
        // pertama — konsisten dengan filosofi "terima beres": admin cuma
        // perlu satu klik ("Aktifkan & Pindai"), bukan dua (simpan, lalu
        // cari sendiri tombol scan).
        $redirect_args['first'] = '1';
    }

    wp_safe_redirect( add_query_arg( $redirect_args, admin_url( 'tools.php' ) ) );
    exit;
}

/**
 * Tangani submit form "Pengerasan Lanjutan" — SENGAJA pakai action/nonce
 * terpisah dari pengaturan proteksi biasa, karena field di sini (matikan
 * XML-RPC total, paksa HTTPS, matikan feed) bisa mematahkan fungsi situs
 * kalau situsnya belum siap. Tidak ada jalan untuk mengaktifkan ini selain
 * admin sendiri yang submit form ini secara sadar — tidak pernah lewat
 * default, tidak pernah lewat aksi otomatis apa pun.
 */
add_action( 'admin_post_wscanom_save_advanced', 'wscanom_handle_save_advanced_request' );
function wscanom_handle_save_advanced_request() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'Kamu tidak punya izin melakukan ini.', 'wscanom' ) );
    }

    check_admin_referer( 'wscanom_save_advanced' );

    $old_settings = wscanom_get_settings();

    // Daftar putih nilai yang sah untuk header IP tepercaya — nilai di luar
    // daftar ini (termasuk hasil tempelan/manipulasi form) selalu jatuh
    // kembali ke '' (cuma REMOTE_ADDR), tidak pernah diterima mentah-mentah.
    $allowed_ip_headers = function_exists( 'wscanom_trusted_ip_header_options' ) ? array_keys( wscanom_trusted_ip_header_options() ) : array();
    $submitted_ip_header = isset( $_POST['trusted_ip_header'] ) ? sanitize_key( wp_unslash( $_POST['trusted_ip_header'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
    $trusted_ip_header    = in_array( $submitted_ip_header, $allowed_ip_headers, true ) ? $submitted_ip_header : '';

    $settings = array_merge(
        $old_settings,
        array(
            'disable_xmlrpc_entirely' => ! empty( $_POST['disable_xmlrpc_entirely'] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
            'force_https'              => ! empty( $_POST['force_https'] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
            'disable_feeds'            => ! empty( $_POST['disable_feeds'] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
            'trusted_ip_header'        => $trusted_ip_header,
            'bruteforce_progressive_lockout' => ! empty( $_POST['bruteforce_progressive_lockout'] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
        )
    );

    update_option( WSCANOM_SETTINGS_OPTION, $settings, false );
    if ( function_exists( 'wscanom_log_settings_diff' ) ) {
        wscanom_log_settings_diff( $old_settings, $settings );
    }

    wp_safe_redirect( add_query_arg( array( 'page' => 'wscanom', 'wscanom_notice' => 'settings_saved' ), admin_url( 'tools.php' ) ) );
    exit;
}

/**
 * Tangani tombol aksi darurat (paksa reset password semua user, atau
 * putuskan semua sesi login). Satu handler untuk keduanya, dibedakan lewat
 * nilai tombol yang ditekan — keduanya aksi SEKALI JALAN, bukan pengaturan
 * yang tersimpan, jadi tidak masuk ke wscanom_get_settings().
 */
add_action( 'admin_post_wscanom_emergency_action', 'wscanom_handle_emergency_action_request' );
function wscanom_handle_emergency_action_request() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'Kamu tidak punya izin melakukan ini.', 'wscanom' ) );
    }

    check_admin_referer( 'wscanom_emergency_action' );

    $action = isset( $_POST['emergency_action'] ) ? sanitize_key( wp_unslash( $_POST['emergency_action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
    $notice = 'emergency_done';

    if ( 'force_password_reset' === $action && function_exists( 'wscanom_force_password_reset' ) ) {
        wscanom_force_password_reset( 0 );
    } elseif ( 'logout_all' === $action && function_exists( 'wscanom_logout_all_users' ) ) {
        wscanom_logout_all_users();
    } else {
        $notice = 'error';
    }

    wp_safe_redirect( add_query_arg( array( 'page' => 'wscanom', 'wscanom_notice' => $notice ), admin_url( 'tools.php' ) ) );
    exit;
}

/**
 * Tangani tombol "Uji Sekarang" di panel Pemeriksaan Kesehatan — jalankan
 * ULANG uji coba eksekusi PHP di folder uploads secara paksa (abaikan cache
 * 12 jam), dipakai admin kalau baru saja mengubah konfigurasi server dan
 * ingin verifikasi langsung tanpa menunggu cache kadaluarsa sendiri.
 */
add_action( 'admin_post_wscanom_retest_exec_deny', 'wscanom_handle_retest_exec_deny_request' );
function wscanom_handle_retest_exec_deny_request() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'Kamu tidak punya izin melakukan ini.', 'wscanom' ) );
    }

    check_admin_referer( 'wscanom_retest_exec_deny' );

    if ( function_exists( 'wscanom_get_exec_deny_probe_result' ) ) {
        wscanom_get_exec_deny_probe_result( true );
    }

    wp_safe_redirect( add_query_arg( array( 'page' => 'wscanom', 'wscanom_notice' => 'exec_deny_rechecked' ), admin_url( 'tools.php' ) ) );
    exit;
}

/**
 * Tangani submit form "Pulihkan dari Karantina".
 * Pakai admin-post.php biasa (bukan AJAX) karena ini aksi yang jarang
 * dipakai dan lebih sederhana dengan reload halaman biasa.
 */
add_action( 'admin_post_wscanom_restore', 'wscanom_handle_restore_request' );
function wscanom_handle_restore_request() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'Kamu tidak punya izin melakukan ini.', 'wscanom' ) );
    }

    check_admin_referer( 'wscanom_restore' );

    $id = isset( $_POST['quarantine_id'] ) ? sanitize_text_field( wp_unslash( $_POST['quarantine_id'] ) ) : '';

    $notice = 'restored';
    if ( '' === $id ) {
        $notice = 'error';
    } else {
        $result = wscanom_restore_quarantined( $id );
        if ( is_wp_error( $result ) ) {
            $notice = 'error';
        }
    }

    wp_safe_redirect( add_query_arg( array( 'page' => 'wscanom', 'wscanom_notice' => $notice ), admin_url( 'tools.php' ) ) );
    exit;
}

add_action( 'admin_menu', 'wscanom_register_admin_menu' );
function wscanom_register_admin_menu() {
    add_management_page(
        __( 'WScanom', 'wscanom' ),
        __( 'WScanom', 'wscanom' ),
        'manage_options',
        'wscanom',
        'wscanom_render_page'
    );

    // Halaman sambutan pertama kali aktivasi. Didaftarkan sebagai submenu
    // (supaya kapabilitas, menu admin, dan enqueue asset otomatis ikut
    // mekanisme WordPress yang sudah ada) lalu langsung disembunyikan dari
    // daftar menu — tetap bisa diakses lewat redirect aktivasi atau tautan
    // "Lihat ringkasan proteksi" di halaman utama, tapi tidak numpuk jadi
    // dua entri menu yang membingungkan di bawah Tools.
    add_submenu_page(
        'tools.php',
        __( 'Selamat Datang — WScanom', 'wscanom' ),
        __( 'WScanom Welcome', 'wscanom' ),
        'manage_options',
        'wscanom-welcome',
        'wscanom_render_welcome_page'
    );
    remove_submenu_page( 'tools.php', 'wscanom-welcome' );
}

/**
 * Redirect ke halaman sambutan sesaat setelah plugin diaktifkan (sekali
 * saja, bukan tiap kali admin buka wp-admin). Transient pendek dipasang di
 * wscanom_on_activate() (wscanom.php); kalau tidak ada tandanya, fungsi ini
 * tidak melakukan apa pun.
 *
 * Tidak jalan untuk aktivasi massal (banyak plugin sekaligus dicentang lalu
 * "Activate") — me-redirect paksa di tengah proses itu akan membingungkan
 * dan bisa mengganggu aktivasi plugin lain yang antre di baris yang sama.
 *
 * @return void
 */
function wscanom_maybe_redirect_to_welcome() {
    if ( ! get_transient( 'wscanom_activation_redirect' ) ) {
        return;
    }
    delete_transient( 'wscanom_activation_redirect' );

    if ( isset( $_GET['activate-multi'] ) || ! current_user_can( 'manage_options' ) || wp_doing_ajax() ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        return;
    }

    wp_safe_redirect( admin_url( 'tools.php?page=wscanom-welcome&first=1' ) );
    exit;
}
add_action( 'admin_init', 'wscanom_maybe_redirect_to_welcome' );

if ( is_multisite() ) {
    add_action( 'network_admin_menu', 'wscanom_register_network_admin_menu' );
}
function wscanom_register_network_admin_menu() {
    add_submenu_page(
        'settings.php',
        __( 'WScanom (Jaringan)', 'wscanom' ),
        __( 'WScanom', 'wscanom' ),
        'manage_network',
        'wscanom-network',
        'wscanom_render_network_page'
    );
}

// admin_enqueue_scripts juga tereksekusi di halaman Network Admin,
// jadi satu pendaftaran ini sudah cukup untuk kedua konteks.
add_action( 'admin_enqueue_scripts', 'wscanom_enqueue_assets' );

/**
 * Daftarkan JS/CSS hanya di halaman WScanom sendiri (bukan di semua halaman admin).
 *
 * @param string $hook Hook halaman admin saat ini.
 * @return void
 */
function wscanom_enqueue_assets( $hook ) {
    $is_wscanom_page = ( false !== strpos( (string) $hook, 'wscanom' ) );
    if ( ! $is_wscanom_page ) {
        return;
    }

    wp_enqueue_style(
        'wscanom-admin',
        plugins_url( 'assets/admin.css', WSCANOM_FILE ),
        array(),
        WSCANOM_VERSION
    );

    wp_enqueue_script(
        'wscanom-admin',
        plugins_url( 'assets/admin.js', WSCANOM_FILE ),
        array(),
        WSCANOM_VERSION,
        true
    );

    wp_localize_script(
        'wscanom-admin',
        'WScanomData',
        array(
            'ajaxUrl'  => admin_url( 'admin-ajax.php' ),
            'nonce'    => wp_create_nonce( 'wscanom_ajax' ),
            'batchSize' => 75,
            'strings'  => array(
                'listing'     => __( 'Mengumpulkan daftar file...', 'wscanom' ),
                'scanning'    => __( 'Memindai %1$d dari %2$d file...', 'wscanom' ),
                'scanningRoot' => __( 'Memindai file sentinel di root (index.php, wp-config.php, dll)...', 'wscanom' ),
                'done'        => __( 'Selesai. Ditemukan %d file dengan indikasi mencurigakan.', 'wscanom' ),
                'doneClean'   => __( 'Selesai. Tidak ada file mencurigakan yang terdeteksi.', 'wscanom' ),
                'error'       => __( 'Terjadi kesalahan saat memindai, coba lagi.', 'wscanom' ),
                'whitelisted' => __( 'Ditandai aman (whitelist)', 'wscanom' ),
                'markSafe'    => __( 'Tandai Aman', 'wscanom' ),
                'unmarkSafe'  => __( 'Batalkan Tandai Aman', 'wscanom' ),
                'quarantine'      => __( 'Karantina', 'wscanom' ),
                'quarantined'     => __( 'Dikarantina', 'wscanom' ),
                'confirmQuarantine' => __( 'Pindahkan file ini ke karantina? File akan dinonaktifkan dan dipindah dari lokasi aslinya, tapi masih bisa dipulihkan lewat tabel di bawah.', 'wscanom' ),
                'stripBlock'   => __( 'Bersihkan Blok Tersuntik', 'wscanom' ),
                'stripped'     => __( 'Sudah Dibersihkan', 'wscanom' ),
                'confirmStrip' => __( 'File ini tidak bisa dipindah (situs butuh file ini untuk jalan). Hanya blok kode yang cocok pola backdoor yang akan dibuang, sisanya dibiarkan utuh. Backup lengkap sebelum dibersihkan akan disimpan di tabel karantina. Lanjutkan?', 'wscanom' ),
            ),
        )
    );
}

/**
 * Render halaman scan untuk satu situs (dipakai di admin biasa, dan dipanggil
 * ulang per-situs dari halaman network).
 *
 * @return void
 */
function wscanom_render_page() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'Kamu tidak punya izin mengakses halaman ini.', 'wscanom' ) );
    }
    $notice = isset( $_GET['wscanom_notice'] ) ? sanitize_text_field( wp_unslash( $_GET['wscanom_notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    ?>
    <div class="wrap wscanom-wrap">
        <div class="wscanom-masthead">
            <span class="dashicons dashicons-shield" aria-hidden="true"></span>
            <div>
                <h1>WScanom</h1>
                <p><?php esc_html_e( 'Pemindai webshell/backdoor dan rangkaian proteksi aktif untuk situs ini — login, privasi, dan tanggap darurat, semuanya berjalan sendiri sejak diaktifkan.', 'wscanom' ); ?></p>
            </div>
        </div>

        <?php if ( 'restored' === $notice ) : ?>
            <div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'File berhasil dipulihkan dari karantina ke lokasi asalnya.', 'wscanom' ); ?></p></div>
        <?php elseif ( 'error' === $notice ) : ?>
            <div class="notice notice-error is-dismissible"><p><?php esc_html_e( 'Gagal memulihkan file dari karantina.', 'wscanom' ); ?></p></div>
        <?php elseif ( 'settings_saved' === $notice ) : ?>
            <div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Pengaturan proteksi disimpan.', 'wscanom' ); ?></p></div>
        <?php elseif ( 'emergency_done' === $notice ) : ?>
            <div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Aksi darurat selesai dijalankan. Lihat Log Aktivitas di bawah untuk detail.', 'wscanom' ); ?></p></div>
        <?php elseif ( 'exec_deny_rechecked' === $notice ) : ?>
            <div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Uji coba proteksi eksekusi PHP di uploads selesai dijalankan ulang. Lihat hasilnya di Pemeriksaan Kesehatan Server di bawah.', 'wscanom' ); ?></p></div>
        <?php endif; ?>

        <?php wscanom_render_status_overview(); ?>

        <p class="wscanom-welcome-link">
            <a href="<?php echo esc_url( admin_url( 'tools.php?page=wscanom-welcome' ) ); ?>"><?php esc_html_e( 'Lihat ringkasan proteksi otomatis yang terpasang »', 'wscanom' ); ?></a>
        </p>

        <?php wscanom_render_last_cron_summary(); ?>
        <?php wscanom_render_scan_ui(); ?>
        <?php wscanom_render_quarantine_table(); ?>
        <?php wscanom_render_protection_settings(); ?>
        <?php wscanom_render_2fa_overview_card(); ?>
        <?php wscanom_render_advanced_hardening_settings(); ?>
        <?php wscanom_render_emergency_actions(); ?>
        <?php wscanom_render_health_check_panel(); ?>
        <?php wscanom_render_activity_log_panel(); ?>

        <p class="wscanom-disclaimer">
            <strong><?php esc_html_e( 'Catatan penting:', 'wscanom' ); ?></strong>
            <?php esc_html_e( 'WScanom adalah pemindai berbasis pola, bukan database signature besar seperti Wordfence/Sucuri. Hasilnya bisa salah tuduh (terutama pada plugin cache/minifier yang memang memakai teknik mirip obfuscation) dan bisa kelewatan untuk teknik yang benar-benar baru. Gunakan sebagai lapisan pemeriksaan tambahan, bukan satu-satunya alat keamanan situsmu.', 'wscanom' ); ?>
        </p>
    </div>
    <?php
}

/**
 * Kartu ringkasan paling atas: berapa dari proteksi inti yang sedang aktif,
 * sekilas pandang tanpa perlu menggulir ke tiap panel. Tujuannya meyakinkan
 * admin dalam 3 detik pertama bahwa situsnya memang dalam keadaan terjaga —
 * bukan sekadar daftar tombol tanpa konteks.
 *
 * @return void
 */
function wscanom_render_status_overview() {
    $settings = wscanom_get_settings();

    $core_protections = array(
        'disable_file_editor'   => __( 'Editor kode terkunci', 'wscanom' ),
        'auto_quarantine'       => __( 'Auto-karantina', 'wscanom' ),
        'bruteforce_protection' => __( 'Pembatas brute-force', 'wscanom' ),
        'login_captcha'         => __( 'CAPTCHA login', 'wscanom' ),
    );

    $active_count = 0;
    foreach ( $core_protections as $key => $label ) {
        if ( ! empty( $settings[ $key ] ) ) {
            ++$active_count;
        }
    }
    $total_core = count( $core_protections );

    $is_https = function_exists( 'wscanom_site_uses_https' ) ? wscanom_site_uses_https() : is_ssl();

    $own_2fa = function_exists( 'wscanom_user_has_2fa' ) && wscanom_user_has_2fa( get_current_user_id() );

    $status_level = ( $active_count === $total_core ) ? 'good' : 'warn';
    ?>
    <div class="wscanom-overview wscanom-overview--<?php echo esc_attr( $status_level ); ?>">
        <div class="wscanom-overview-main">
            <span class="dashicons <?php echo 'good' === $status_level ? 'dashicons-yes-alt' : 'dashicons-warning'; ?>" aria-hidden="true"></span>
            <div>
                <strong>
                    <?php
                    echo esc_html(
                        sprintf(
                            /* translators: 1: jumlah proteksi aktif, 2: total proteksi inti */
                            __( '%1$d dari %2$d proteksi inti aktif', 'wscanom' ),
                            $active_count,
                            $total_core
                        )
                    );
                    ?>
                </strong>
                <span class="wscanom-overview-sub">
                    <?php
                    echo esc_html(
                        'good' === $status_level
                            ? __( 'Semua pengaturan default masih menyala — tidak ada yang perlu kamu lakukan.', 'wscanom' )
                            : __( 'Beberapa proteksi default dimatikan. Periksa panel Pengaturan Proteksi di bawah kalau ini bukan kesengajaan.', 'wscanom' )
                    );
                    ?>
                </span>
            </div>
        </div>
        <div class="wscanom-overview-chips">
            <span class="wscanom-chip <?php echo $is_https ? 'wscanom-chip--on' : 'wscanom-chip--off'; ?>"><?php echo esc_html( $is_https ? __( 'HTTPS aktif', 'wscanom' ) : __( 'Belum HTTPS', 'wscanom' ) ); ?></span>
            <span class="wscanom-chip <?php echo $own_2fa ? 'wscanom-chip--on' : 'wscanom-chip--off'; ?>"><?php echo esc_html( $own_2fa ? __( '2FA akunmu aktif', 'wscanom' ) : __( '2FA akunmu belum aktif', 'wscanom' ) ); ?></span>
        </div>
    </div>
    <?php
}

/**
 * Tabel "Pengerasan Lanjutan" — pengaturan yang BISA mematahkan fungsi
 * situs kalau diaktifkan tanpa situsnya siap, jadi semuanya default MATI
 * dan ditampilkan dengan DETEKSI DINI (status terkini) tepat di atas
 * masing-masing, bukan cuma teks peringatan statis — supaya admin melihat
 * kondisi situsnya SENDIRI sebelum menekan tombol, bukan menebak-nebak.
 *
 * @return void
 */
function wscanom_render_advanced_hardening_settings() {
    $settings     = wscanom_get_settings();
    $jetpack_deps = function_exists( 'wscanom_detect_xmlrpc_dependents' ) ? wscanom_detect_xmlrpc_dependents() : array();
    $is_https     = function_exists( 'wscanom_site_uses_https' ) ? wscanom_site_uses_https() : is_ssl();
    ?>
    <div class="wscanom-card wscanom-card--advanced">
        <div class="wscanom-card-head">
            <span class="dashicons dashicons-admin-tools" aria-hidden="true"></span>
            <div>
                <h2><?php esc_html_e( 'Pengerasan Lanjutan', 'wscanom' ); ?> <span class="wscanom-badge wscanom-badge-manual"><?php esc_html_e( 'Manual', 'wscanom' ); ?></span></h2>
                <p class="wscanom-card-subtitle"><?php esc_html_e( 'Tiga opsi ini bisa mematahkan fungsi tertentu di situsmu kalau diaktifkan tanpa persiapan, jadi semuanya mati secara default dan tidak pernah dinyalakan otomatis oleh WScanom. Baca status "deteksi dini" di tiap baris sebelum menyalakan.', 'wscanom' ); ?></p>
            </div>
        </div>
    <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
        <?php wp_nonce_field( 'wscanom_save_advanced' ); ?>
        <input type="hidden" name="action" value="wscanom_save_advanced" />
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html_e( 'Matikan XML-RPC total', 'wscanom' ); ?></th>
                <td>
                    <?php if ( ! empty( $jetpack_deps ) ) : ?>
                        <p class="wscanom-disclaimer" style="margin-bottom:8px;">
                            <strong><?php esc_html_e( 'Deteksi dini:', 'wscanom' ); ?></strong>
                            <?php
                            echo esc_html(
                                sprintf(
                                    /* translators: %s: daftar nama plugin */
                                    __( 'Terdeteksi plugin aktif yang biasanya BUTUH XML-RPC: %s. Mengaktifkan ini kemungkinan besar akan memutus fungsi plugin tersebut.', 'wscanom' ),
                                    implode( ', ', $jetpack_deps )
                                )
                            );
                            ?>
                        </p>
                    <?php endif; ?>
                    <label>
                        <input type="checkbox" name="disable_xmlrpc_entirely" value="1" <?php checked( ! empty( $settings['disable_xmlrpc_entirely'] ) ); ?> />
                        <?php esc_html_e( 'Matikan XML-RPC sepenuhnya (bukan cuma pingback, yang sudah dimatikan otomatis).', 'wscanom' ); ?>
                    </label>
                    <p class="description"><?php esc_html_e( 'Bisa memutus Jetpack, aplikasi WordPress mobile resmi, dan integrasi lain yang memakai XML-RPC untuk publish/sync jarak jauh. Metode pingback (celah brute-force/DDoS paling umum lewat XML-RPC) SUDAH dimatikan otomatis di luar pengaturan ini — opsi ini hanya perlu kalau kamu yakin situsmu sama sekali tidak memakai integrasi apa pun yang butuh XML-RPC.', 'wscanom' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Paksa semua trafik ke HTTPS', 'wscanom' ); ?></th>
                <td>
                    <p class="wscanom-disclaimer" style="margin-bottom:8px;">
                        <strong><?php esc_html_e( 'Deteksi dini:', 'wscanom' ); ?></strong>
                        <?php
                        echo esc_html(
                            $is_https
                                ? __( 'Situs ini SAAT INI terdeteksi sudah bisa diakses lewat HTTPS — aman untuk mengaktifkan.', 'wscanom' )
                                : __( 'Situs ini SAAT INI BELUM terdeteksi HTTPS. JANGAN aktifkan dulu — kalau diaktifkan sekarang, situs bisa jadi tidak bisa diakses sama sekali (redirect tanpa tujuan yang valid). Aktifkan SSL di hosting dulu, baru nyalakan ini.', 'wscanom' )
                        );
                        ?>
                    </p>
                    <label>
                        <input type="checkbox" name="force_https" value="1" <?php checked( ! empty( $settings['force_https'] ) ); ?> <?php disabled( ! $is_https ); ?> />
                        <?php esc_html_e( 'Redirect semua permintaan HTTP ke HTTPS secara paksa.', 'wscanom' ); ?>
                    </label>
                    <?php if ( ! $is_https ) : ?>
                        <p class="description"><?php esc_html_e( 'Kotak centang ini dikunci sampai situs terdeteksi HTTPS, supaya tidak bisa tidak sengaja mengunci situs sendiri dari akses.', 'wscanom' ); ?></p>
                    <?php endif; ?>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Matikan feed RSS/Atom', 'wscanom' ); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="disable_feeds" value="1" <?php checked( ! empty( $settings['disable_feeds'] ) ); ?> />
                        <?php esc_html_e( 'Matikan /feed/ dan variannya.', 'wscanom' ); ?>
                    </label>
                    <p class="description"><?php esc_html_e( 'Bukan risiko keamanan besar — cuma mempersempit info yang bisa dikumpulkan pemindai otomatis. Matikan HANYA kalau kamu yakin tidak ada pembaca RSS, layanan sindikasi, atau newsletter yang bergantung pada feed situs ini.', 'wscanom' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Header IP tepercaya', 'wscanom' ); ?></th>
                <td>
                    <?php
                    $current_remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '-'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.NonceVerification.Recommended
                    $header_options       = function_exists( 'wscanom_trusted_ip_header_options' ) ? wscanom_trusted_ip_header_options() : array();
                    $header_labels        = array(
                        'cf_connecting_ip' => 'CF-Connecting-IP (Cloudflare)',
                        'true_client_ip'   => 'True-Client-IP (Cloudflare Enterprise / Akamai)',
                        'x_real_ip'        => 'X-Real-IP (nginx reverse proxy umum)',
                        'x_forwarded_for'  => 'X-Forwarded-For (CDN/load balancer umum)',
                    );
                    ?>
                    <p class="wscanom-disclaimer" style="margin-bottom:8px;">
                        <strong><?php esc_html_e( 'Deteksi dini:', 'wscanom' ); ?></strong>
                        <?php
                        echo esc_html(
                            sprintf(
                                /* translators: %s: alamat IP REMOTE_ADDR saat ini */
                                __( 'REMOTE_ADDR permintaan ini SAAT INI: %s. Bandingkan dengan isi header di bawah sebelum memutuskan mempercayai salah satunya — kalau nilainya TIDAK sama persis dengan IP asli perangkatmu, jangan pilih header itu.', 'wscanom' ),
                                $current_remote_addr
                            )
                        );
                        ?>
                    </p>
                    <table class="widefat" style="max-width:520px;margin-bottom:10px;">
                        <tbody>
                            <?php foreach ( $header_labels as $key => $label ) : ?>
                                <?php $peek = function_exists( 'wscanom_peek_ip_header' ) ? wscanom_peek_ip_header( $key ) : ''; ?>
                                <tr>
                                    <td><?php echo esc_html( $label ); ?></td>
                                    <td><code><?php echo esc_html( '' !== $peek ? $peek : __( '(tidak ada di permintaan ini)', 'wscanom' ) ); ?></code></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    <label>
                        <select name="trusted_ip_header">
                            <option value="" <?php selected( '', $settings['trusted_ip_header'] ?? '' ); ?>><?php esc_html_e( 'Tidak ada — cuma pakai REMOTE_ADDR (default, paling aman)', 'wscanom' ); ?></option>
                            <?php foreach ( $header_labels as $key => $label ) : ?>
                                <option value="<?php echo esc_attr( $key ); ?>" <?php selected( $key, $settings['trusted_ip_header'] ?? '' ); ?>><?php echo esc_html( $label ); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </label>
                    <p class="description"><?php esc_html_e( 'Hanya pilih salah satu kalau situsmu BENAR-BENAR selalu diakses lewat proxy/CDN tersebut. Kalau dipilih padahal situsmu bisa diakses langsung tanpa proxy itu, pengunjung mana pun bisa memalsukan header ini sendiri dan membuat pembatas brute-force salah mengenali alamat IP-nya — bukan menambah keamanan, malah melubanginya.', 'wscanom' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Lockout progresif', 'wscanom' ); ?></th>
                <td>
                    <?php
                    $base_lockout_minutes = max( 1, (int) ( $settings['bruteforce_lockout_minutes'] ?? 20 ) );
                    $preview_cycles       = array( 1, 2, 3, 4 );
                    ?>
                    <p class="wscanom-disclaimer" style="margin-bottom:8px;">
                        <strong><?php esc_html_e( 'Deteksi dini:', 'wscanom' ); ?></strong>
                        <?php
                        echo esc_html(
                            sprintf(
                                /* translators: %d: durasi lockout dasar saat ini dalam menit */
                                __( 'Berdasarkan durasi lockout dasar saat ini (%d menit), kalau IP/akun yang sama kena lockout berkali-kali dalam 7 hari, durasinya akan naik begini:', 'wscanom' ),
                                $base_lockout_minutes
                            )
                        );
                        ?>
                    </p>
                    <table class="widefat" style="max-width:420px;margin-bottom:10px;">
                        <tbody>
                            <?php foreach ( $preview_cycles as $cycle ) : ?>
                                <?php $preview_minutes = function_exists( 'wscanom_progressive_lockout_minutes' ) ? wscanom_progressive_lockout_minutes( $base_lockout_minutes, $cycle ) : $base_lockout_minutes; ?>
                                <tr>
                                    <td>
                                        <?php
                                        echo esc_html(
                                            sprintf(
                                                /* translators: %d: nomor siklus lockout */
                                                __( 'Lockout ke-%d', 'wscanom' ),
                                                $cycle
                                            )
                                        );
                                        ?>
                                    </td>
                                    <td><code><?php echo esc_html( $preview_minutes . ' ' . __( 'menit', 'wscanom' ) ); ?></code></td>
                                </tr>
                            <?php endforeach; ?>
                            <tr>
                                <td><?php esc_html_e( 'Batas mutlak (berapa pun siklusnya)', 'wscanom' ); ?></td>
                                <td><code><?php echo esc_html( WSCANOM_PROGRESSIVE_LOCKOUT_CAP_MINUTES . ' ' . __( 'menit (24 jam)', 'wscanom' ) ); ?></code></td>
                            </tr>
                        </tbody>
                    </table>
                    <label>
                        <input type="checkbox" name="bruteforce_progressive_lockout" value="1" <?php checked( ! empty( $settings['bruteforce_progressive_lockout'] ) ); ?> />
                        <?php esc_html_e( 'Naikkan durasi lockout secara bertahap untuk IP/akun yang berulang kali kena lockout dalam 7 hari terakhir.', 'wscanom' ); ?>
                    </label>
                    <p class="description"><?php esc_html_e( 'Membuat brute-force yang gigih makin mahal tiap kali mencoba ulang. Risikonya: kalau KAMU SENDIRI sering lupa password dan berkali-kali kena lockout, durasi kuncinya juga ikut naik sampai maksimal 24 jam. Begitu login berhasil, seluruh riwayat eskalasi langsung direset ke nol — jadi ini hanya berdampak pada percobaan yang terus gagal berulang, bukan kesalahan ketik sesekali.', 'wscanom' ); ?></p>
                </td>
            </tr>
        </table>
        <p><button type="submit" class="button button-primary"><?php esc_html_e( 'Simpan Pengerasan Lanjutan', 'wscanom' ); ?></button></p>
    </form>
    </div>
    <?php
}

/**
 * Panel "Aksi Darurat" — dua tombol sekali-klik untuk dipakai SETELAH
 * admin curiga/yakin situsnya kena kompromi: putus semua sesi login yang
 * mungkin sudah dibajak, dan/atau paksa semua akun reset password. Bukan
 * pengaturan yang tersimpan, jadi selalu tampil sama tiap buka halaman —
 * dan selalu minta konfirmasi di browser sebelum benar-benar jalan, karena
 * efeknya langsung ("Post hacking action": memutus kerusakan lanjutan
 * secepat mungkin setelah terindikasi kompromi).
 *
 * @return void
 */
function wscanom_render_emergency_actions() {
    ?>
    <div class="wscanom-card wscanom-card--emergency">
        <div class="wscanom-card-head">
            <span class="dashicons dashicons-sos" aria-hidden="true"></span>
            <div>
                <h2><?php esc_html_e( 'Aksi Darurat', 'wscanom' ); ?></h2>
                <p class="wscanom-card-subtitle"><?php esc_html_e( 'Untuk dipakai SETELAH situs ini dicurigai atau terbukti disusupi — memutus akses siapa pun yang mungkin sudah mencuri sesi login atau password, sebelum kerusakan berlanjut.', 'wscanom' ); ?></p>
            </div>
        </div>
        <div class="wscanom-emergency-buttons">
            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" onsubmit="return confirm('<?php echo esc_js( __( 'Semua user akan dipaksa reset password dan sesi login aktifnya diputus. Lanjutkan?', 'wscanom' ) ); ?>');">
                <?php wp_nonce_field( 'wscanom_emergency_action' ); ?>
                <input type="hidden" name="action" value="wscanom_emergency_action" />
                <input type="hidden" name="emergency_action" value="force_password_reset" />
                <button type="submit" class="button wscanom-btn-danger"><?php esc_html_e( 'Paksa Reset Password Semua User', 'wscanom' ); ?></button>
            </form>
            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" onsubmit="return confirm('<?php echo esc_js( __( 'Semua user (termasuk kamu) akan langsung keluar dari sesi login saat ini. Lanjutkan?', 'wscanom' ) ); ?>');">
                <?php wp_nonce_field( 'wscanom_emergency_action' ); ?>
                <input type="hidden" name="action" value="wscanom_emergency_action" />
                <input type="hidden" name="emergency_action" value="logout_all" />
                <button type="submit" class="button wscanom-btn-danger"><?php esc_html_e( 'Keluarkan Semua User dari Sesi Login', 'wscanom' ); ?></button>
            </form>
        </div>
    </div>
    <?php
}

/**
 * Panel pemeriksaan kesehatan server — BACA SAJA, lihat includes/health-check.php.
 *
 * @return void
 */
function wscanom_render_health_check_panel() {
    if ( ! function_exists( 'wscanom_run_health_checks' ) ) {
        return;
    }
    $checks = wscanom_run_health_checks();
    $colors = array(
        'ok'   => '#00a32a',
        'warn' => '#dba617',
        'bad'  => '#d63638',
    );
    ?>
    <div class="wscanom-card wscanom-card--health">
        <div class="wscanom-card-head">
            <span class="dashicons dashicons-heart" aria-hidden="true"></span>
            <div>
                <h2><?php esc_html_e( 'Pemeriksaan Kesehatan Server', 'wscanom' ); ?></h2>
                <p class="wscanom-card-subtitle"><?php esc_html_e( 'Baca-saja. WScanom tidak bisa mengubah konfigurasi server (itu butuh akses hosting) — panel ini murni melaporkan dan menyarankan.', 'wscanom' ); ?></p>
            </div>
        </div>
        <table class="widefat striped">
            <thead><tr><th style="width:220px;"><?php esc_html_e( 'Pemeriksaan', 'wscanom' ); ?></th><th style="width:120px;"><?php esc_html_e( 'Status', 'wscanom' ); ?></th><th><?php esc_html_e( 'Detail', 'wscanom' ); ?></th></tr></thead>
            <tbody>
                <?php foreach ( $checks as $check ) : ?>
                    <tr>
                        <td><strong><?php echo esc_html( $check['label'] ); ?></strong></td>
                        <td>
                            <span class="wscanom-dot" style="background:<?php echo esc_attr( $colors[ $check['status'] ] ?? '#666' ); ?>;"></span>
                            <span style="color:<?php echo esc_attr( $colors[ $check['status'] ] ?? '#666' ); ?>;font-weight:600;">
                                <?php echo esc_html( 'ok' === $check['status'] ? __( 'Baik', 'wscanom' ) : ( 'warn' === $check['status'] ? __( 'Perhatian', 'wscanom' ) : __( 'Perlu Tindakan', 'wscanom' ) ) ); ?>
                            </span>
                        </td>
                        <td><?php echo esc_html( $check['detail'] ); ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php if ( function_exists( 'wscanom_get_exec_deny_probe_result' ) ) : ?>
            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:10px;">
                <?php wp_nonce_field( 'wscanom_retest_exec_deny' ); ?>
                <input type="hidden" name="action" value="wscanom_retest_exec_deny" />
                <button type="submit" class="button"><?php esc_html_e( 'Uji Sekarang: Larang Eksekusi PHP di Uploads', 'wscanom' ); ?></button>
                <p class="description"><?php esc_html_e( 'Baris "Larang eksekusi PHP di uploads" di atas dicek ulang otomatis setiap 12 jam. Tombol ini memaksa pengecekan ulang langsung — berguna setelah kamu mengubah konfigurasi server (mis. pindah hosting, ganti dari Apache ke nginx).', 'wscanom' ); ?></p>
            </form>
        <?php endif; ?>
    </div>
    <?php
}

/**
 * Panel log aktivitas — lihat includes/activity-log.php.
 *
 * @return void
 */
function wscanom_render_activity_log_panel() {
    if ( ! function_exists( 'wscanom_get_log_entries' ) ) {
        return;
    }
    $entries = wscanom_get_log_entries( 50 );
    ?>
    <div class="wscanom-card wscanom-card--log">
        <div class="wscanom-card-head">
            <span class="dashicons dashicons-list-view" aria-hidden="true"></span>
            <div>
                <h2><?php esc_html_e( 'Log Aktivitas', 'wscanom' ); ?></h2>
                <p class="wscanom-card-subtitle"><?php esc_html_e( 'Login gagal/berhasil, perubahan pengaturan, dan aksi darurat yang dijalankan — 300 entri terbaru.', 'wscanom' ); ?></p>
            </div>
        </div>
        <?php if ( empty( $entries ) ) : ?>
            <p><?php esc_html_e( 'Belum ada aktivitas tercatat.', 'wscanom' ); ?></p>
        <?php else : ?>
            <table class="widefat striped">
                <thead><tr><th style="width:160px;"><?php esc_html_e( 'Waktu', 'wscanom' ); ?></th><th style="width:160px;"><?php esc_html_e( 'Jenis', 'wscanom' ); ?></th><th><?php esc_html_e( 'Keterangan', 'wscanom' ); ?></th></tr></thead>
                <tbody>
                    <?php foreach ( $entries as $entry ) : ?>
                        <tr>
                            <td><?php echo esc_html( wp_date( 'Y-m-d H:i', $entry['time'] ) ); ?></td>
                            <td><?php echo esc_html( wscanom_log_type_label( $entry['type'] ) ); ?></td>
                            <td><?php echo esc_html( $entry['message'] ); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
    <?php
}

/**
 * Blok UI scan (tombol, progress bar, tabel hasil) — dipakai bersama oleh
 * halaman utama dan halaman sambutan pertama kali aktivasi, supaya mesin
 * scan-nya (admin.js) sama persis di kedua tempat.
 *
 * @param bool $auto_start Kalau true, scan langsung jalan sendiri begitu
 *                         halaman dimuat (dipakai di halaman sambutan untuk
 *                         filosofi "terima beres" — admin tidak perlu klik
 *                         apa pun supaya scan pertama langsung jalan).
 * @return void
 */
function wscanom_render_scan_ui( $auto_start = false ) {
    ?>
    <div class="wscanom-card wscanom-card--scan">
        <div class="wscanom-card-head">
            <span class="dashicons dashicons-search" aria-hidden="true"></span>
            <div>
                <h2><?php esc_html_e( 'Pindai Sekarang', 'wscanom' ); ?></h2>
                <p class="wscanom-card-subtitle"><?php esc_html_e( 'Memeriksa seluruh file .php di wp-content secara bertahap, langsung di browser ini — hasil muncul berurutan, skor tertinggi di atas.', 'wscanom' ); ?></p>
            </div>
        </div>
        <p>
            <button type="button" id="wscanom-start-scan" class="button button-primary">
                <?php esc_html_e( 'Jalankan Scan Sekarang', 'wscanom' ); ?>
            </button>
        </p>

        <div id="wscanom-progress" class="wscanom-progress" hidden>
            <div class="wscanom-progress-bar"><div class="wscanom-progress-fill"></div></div>
            <p id="wscanom-progress-text"></p>
        </div>

        <div id="wscanom-summary"></div>

        <table class="widefat striped" id="wscanom-results-table" hidden>
            <thead>
                <tr>
                    <th style="width:80px;"><?php esc_html_e( 'Skor', 'wscanom' ); ?></th>
                    <th><?php esc_html_e( 'File', 'wscanom' ); ?></th>
                    <th><?php esc_html_e( 'Temuan', 'wscanom' ); ?></th>
                    <th style="width:220px;"><?php esc_html_e( 'Aksi', 'wscanom' ); ?></th>
                </tr>
            </thead>
            <tbody id="wscanom-results-body"></tbody>
        </table>
    </div>
    <?php
    if ( $auto_start ) {
        // Scan jalan sendiri tanpa admin perlu klik apa pun. Ditaruh sebagai
        // script inline terpisah (bukan mengubah admin.js) supaya perilaku
        // "auto" ini jelas kontennya di mana dan tidak memengaruhi halaman
        // utama yang memang sengaja butuh klik manual.
        ?>
        <script>
        document.addEventListener( 'DOMContentLoaded', function () {
            var btn = document.getElementById( 'wscanom-start-scan' );
            if ( btn ) {
                btn.click();
            }
        } );
        </script>
        <?php
    }
}

/**
 * Halaman sambutan yang muncul otomatis sesaat setelah plugin diaktifkan
 * (lihat wscanom_maybe_redirect_to_welcome()). Tujuannya dua:
 *
 * 1. VISIBILITAS — sebelumnya proteksi (matikan editor, exec-deny uploads)
 *    terpasang diam-diam tanpa admin pernah diberi tahu. Di sini dijelaskan
 *    dengan bahasa awam, bukan istilah teknis seperti "htaccess".
 * 2. SCAN PERTAMA INSTAN — sebelumnya scan pertama baru terjadwal 1 jam
 *    setelah aktivasi (lewat WP-Cron, yang sendiri butuh ada pengunjung
 *    buka situs supaya "berdetak"). Kalau admin install plugin ini justru
 *    karena situsnya sudah dicurigai kena hack, jeda itu berbahaya — jadi
 *    di sini scan langsung jalan sendiri begitu halaman dimuat (parameter
 *    "first=1" dari redirect aktivasi memicu auto-start di wscanom_render_scan_ui()).
 *
 * @return void
 */
function wscanom_render_welcome_page() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'Kamu tidak punya izin mengakses halaman ini.', 'wscanom' ) );
    }

    $auto_start = isset( $_GET['first'] ) && '1' === $_GET['first']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    $notice     = isset( $_GET['wscanom_notice'] ) ? sanitize_text_field( wp_unslash( $_GET['wscanom_notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    ?>
    <div class="wrap wscanom-wrap wscanom-welcome-wrap">
        <div class="wscanom-welcome-banner">
            <span class="dashicons dashicons-shield-alt"></span>
            <div>
                <h1><?php esc_html_e( 'WScanom aktif — situsmu mulai dilindungi', 'wscanom' ); ?></h1>
                <p><?php esc_html_e( 'Tidak ada yang perlu kamu atur. Proteksi di bawah ini sudah terpasang otomatis sejak kamu klik Activate, dan scan pertama sedang/baru saja berjalan.', 'wscanom' ); ?></p>
            </div>
        </div>

        <?php if ( 'settings_saved' === $notice ) : ?>
            <div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Pengaturan disimpan. Melanjutkan ke scan.', 'wscanom' ); ?></p></div>
        <?php endif; ?>

        <div class="wscanom-welcome-cards">
            <div class="wscanom-welcome-card">
                <span class="dashicons dashicons-edit-page"></span>
                <h3><?php esc_html_e( 'Editor kode bawaan WordPress dimatikan', 'wscanom' ); ?></h3>
                <p><?php esc_html_e( 'Kalau suatu saat ada yang berhasil masuk ke akun admin situsmu (misalnya lewat password yang mudah ditebak), dia tidak akan bisa menyisipkan kode jahat lewat menu edit tema/plugin bawaan WordPress — menu itu sekarang disembunyikan sepenuhnya.', 'wscanom' ); ?></p>
            </div>
            <div class="wscanom-welcome-card">
                <span class="dashicons dashicons-lock"></span>
                <h3><?php esc_html_e( 'Folder upload dikunci dari kode berbahaya', 'wscanom' ); ?></h3>
                <p><?php esc_html_e( 'Folder tempat gambar dan file media disimpan sekarang tidak bisa dipakai menjalankan kode PHP sama sekali — kalaupun ada file berbahaya yang menyamar sebagai gambar berhasil masuk ke situ, file itu tidak akan pernah bisa "dijalankan".', 'wscanom' ); ?></p>
            </div>
            <div class="wscanom-welcome-card">
                <span class="dashicons dashicons-search"></span>
                <h3><?php esc_html_e( 'Pengecekan otomatis & instan', 'wscanom' ); ?></h3>
                <p><?php esc_html_e( 'Setiap kali kamu install/aktifkan plugin atau tema baru, WScanom langsung memeriksanya saat itu juga — bukan menunggu jadwal berikutnya. Kalau ditemukan sesuatu yang sangat meyakinkan sebagai kode berbahaya, langsung diamankan otomatis, tidak menunggu kamu klik apa pun.', 'wscanom' ); ?></p>
            </div>
            <div class="wscanom-welcome-card">
                <span class="dashicons dashicons-admin-network"></span>
                <h3><?php esc_html_e( 'Login dijaga dari percobaan paksa', 'wscanom' ); ?></h3>
                <p><?php esc_html_e( 'Percobaan login yang gagal berkali-kali otomatis ditunda, dan halaman login dilengkapi verifikasi keamanan sederhana — menghalau bot yang mencoba menebak password tanpa henti.', 'wscanom' ); ?></p>
            </div>
        </div>

        <p class="wscanom-welcome-extra">
            <?php
            echo wp_kses(
                sprintf(
                    /* translators: %s: tautan ke halaman profil untuk mengaktifkan 2FA */
                    __( 'Ingin satu lapis lagi? Aktifkan <a href="%s">verifikasi dua langkah (2FA)</a> untuk akunmu sendiri — opsional, kamu yang mengaktifkan sendiri kapan saja.', 'wscanom' ),
                    esc_url( get_edit_user_link() . '#wscanom-2fa' )
                ),
                array( 'a' => array( 'href' => array() ) )
            );
            ?>
        </p>

        <p class="wscanom-disclaimer">
            <strong><?php esc_html_e( 'Jujur soal batasnya:', 'wscanom' ); ?></strong>
            <?php esc_html_e( 'tidak ada plugin keamanan — termasuk ini — yang bisa menjamin 100% situsmu tidak akan pernah kena serangan. Tiga hal di atas mempersempit dan memperlambat gerak penyerang, bukan jaminan mutlak. Kalau kamu memakai password yang kuat dan rutin update plugin/tema, risikonya jauh lebih kecil lagi.', 'wscanom' ); ?>
        </p>

        <?php wscanom_render_scan_ui( $auto_start ); ?>

        <?php wscanom_render_protection_settings( 'welcome', __( 'Simpan & Lanjutkan', 'wscanom' ) ); ?>

        <p class="wscanom-skip-link">
            <a href="<?php echo esc_url( admin_url( 'tools.php?page=wscanom' ) ); ?>"><?php esc_html_e( 'Lewati, langsung ke halaman utama WScanom →', 'wscanom' ); ?></a>
        </p>
    </div>
    <?php
}

/**
 * Tampilkan ringkasan hasil scan terjadwal (WP-Cron) terakhir, kalau ada.
 * Scan terjadwal berjalan di background tanpa ada yang menonton, jadi ini
 * satu-satunya tempat admin bisa tahu scan itu benar-benar berjalan dan apa
 * hasilnya tanpa harus menunggu email alert (yang hanya terkirim kalau ada
 * temuan di atas ambang skor, atau tidak terkirim sama sekali kalau
 * notifikasi email dimatikan).
 *
 * @return void
 */
function wscanom_render_last_cron_summary() {
    $summary = function_exists( 'wscanom_get_last_scan_summary' ) ? wscanom_get_last_scan_summary() : null;

    if ( ! $summary ) {
        return;
    }

    $flagged_count = count( $summary['flagged'] );
    $is_incomplete = ! empty( $summary['incomplete'] );
    ?>
    <div class="wscanom-strip <?php echo $is_incomplete ? 'wscanom-strip--warn' : 'wscanom-strip--info'; ?>">
        <span class="dashicons <?php echo $is_incomplete ? 'dashicons-warning' : 'dashicons-clock'; ?>" aria-hidden="true"></span>
        <div>
            <strong><?php esc_html_e( 'Scan terjadwal terakhir (otomatis harian):', 'wscanom' ); ?></strong>
            <?php
            echo esc_html(
                sprintf(
                    /* translators: 1: waktu, 2: jumlah file dipindai, 3: jumlah ditandai */
                    __( '%1$s — %2$d file dipindai, %3$d ditandai mencurigakan.', 'wscanom' ),
                    wp_date( 'Y-m-d H:i', $summary['time'] ),
                    (int) $summary['total_files'],
                    $flagged_count
                )
            );
            ?>
            <?php if ( $is_incomplete ) : ?>
                <br /><?php esc_html_e( 'Scan ini belum menjangkau semua file (kemungkinan situs terlalu besar untuk satu anggaran waktu WP-Cron). Hasil di atas sebagian — jalankan "Scan Sekarang" di bawah untuk hasil lengkap dan terkini.', 'wscanom' ); ?>
            <?php endif; ?>
        </div>
    </div>
    <?php
}

/**
 * Tampilkan dan tangani panel pengaturan proteksi otomatis. Semua proteksi
 * di sini defaultnya AKTIF sejak plugin diaktifkan (lihat
 * wscanom_default_settings() di includes/cron.php) — panel ini cuma untuk
 * kasus khusus yang perlu mematikannya, bukan syarat supaya proteksi jalan.
 *
 * @return void
 */
function wscanom_render_protection_settings( $redirect_to = 'main', $submit_label = '' ) {
    $settings = wscanom_get_settings();
    if ( '' === $submit_label ) {
        $submit_label = __( 'Simpan Pengaturan', 'wscanom' );
    }
    ?>
    <div class="wscanom-card wscanom-card--settings">
        <div class="wscanom-card-head">
            <span class="dashicons dashicons-admin-settings" aria-hidden="true"></span>
            <div>
                <h2><?php esc_html_e( 'Pengaturan Proteksi Utama', 'wscanom' ); ?></h2>
                <p class="wscanom-card-subtitle"><?php esc_html_e( 'Semuanya sudah menyala sejak plugin diaktifkan. Halaman ini di sini kalau kamu perlu menyesuaikan sesuatu — bukan syarat supaya situsmu terlindungi.', 'wscanom' ); ?></p>
            </div>
        </div>

        <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wscanom-settings-form">
            <?php wp_nonce_field( 'wscanom_save_settings' ); ?>
            <input type="hidden" name="action" value="wscanom_save_settings" />
            <input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>" />

            <div class="wscanom-setting-row">
                <label class="wscanom-switch">
                    <input type="checkbox" name="disable_file_editor" value="1" <?php checked( ! empty( $settings['disable_file_editor'] ) ); ?> />
                    <span class="wscanom-switch-track"></span>
                </label>
                <div class="wscanom-setting-copy">
                    <strong><?php esc_html_e( 'Kunci editor kode bawaan WordPress', 'wscanom' ); ?></strong>
                    <p><?php esc_html_e( 'Menutup menu Theme/Plugin File Editor sepenuhnya. Kalau suatu saat akun admin bobol lewat password lemah, penyerang tidak akan pernah bisa menyisipkan kode lewat jalur ini — satu-satunya proteksi di halaman ini yang benar-benar mencegah total, bukan sekadar mendeteksi lebih cepat.', 'wscanom' ); ?></p>
                </div>
            </div>

            <div class="wscanom-setting-row">
                <label class="wscanom-switch">
                    <input type="checkbox" name="auto_quarantine" value="1" <?php checked( ! empty( $settings['auto_quarantine'] ) ); ?> />
                    <span class="wscanom-switch-track"></span>
                </label>
                <div class="wscanom-setting-copy">
                    <strong><?php esc_html_e( 'Karantina otomatis untuk temuan yang sangat meyakinkan', 'wscanom' ); ?></strong>
                    <p><?php esc_html_e( 'Begitu plugin/tema baru diinstall atau diupdate, langsung diperiksa saat itu juga. Kalau ada satu pola berbahaya yang sendirian sudah sangat meyakinkan (bukan gabungan beberapa pola ringan), file itu langsung diamankan tanpa menunggu siapa pun klik apa pun. Semua tindakan tetap tercatat dan bisa dipulihkan.', 'wscanom' ); ?></p>
                    <label class="wscanom-inline-number">
                        <?php esc_html_e( 'Ambang bobot minimum', 'wscanom' ); ?>
                        <input type="number" name="auto_quarantine_min_weight" min="1" max="10" value="<?php echo esc_attr( $settings['auto_quarantine_min_weight'] ); ?>" />
                        <span class="wscanom-hint"><?php esc_html_e( '1–10, default 9', 'wscanom' ); ?></span>
                    </label>
                </div>
            </div>

            <div class="wscanom-setting-row">
                <label class="wscanom-switch">
                    <input type="checkbox" name="bruteforce_protection" value="1" <?php checked( ! empty( $settings['bruteforce_protection'] ) ); ?> />
                    <span class="wscanom-switch-track"></span>
                </label>
                <div class="wscanom-setting-copy">
                    <strong><?php esc_html_e( 'Pembatas percobaan login (brute-force)', 'wscanom' ); ?></strong>
                    <p><?php esc_html_e( 'Mengunci sementara percobaan login yang gagal berkali-kali, dilacak baik per-alamat IP maupun per-akun lintas IP (menangkap serangan terdistribusi dari banyak sumber sekaligus). Hanya menunda, tidak pernah mengunci permanen — login yang benar tidak terpengaruh sama sekali.', 'wscanom' ); ?></p>
                    <label class="wscanom-inline-number">
                        <?php esc_html_e( 'Maksimum percobaan', 'wscanom' ); ?>
                        <input type="number" name="bruteforce_max_attempts" min="3" max="20" value="<?php echo esc_attr( $settings['bruteforce_max_attempts'] ); ?>" />
                        <span class="wscanom-hint"><?php esc_html_e( 'default 5', 'wscanom' ); ?></span>
                    </label>
                    <label class="wscanom-inline-number">
                        <?php esc_html_e( 'Lama kunci (menit)', 'wscanom' ); ?>
                        <input type="number" name="bruteforce_lockout_minutes" min="1" max="1440" value="<?php echo esc_attr( $settings['bruteforce_lockout_minutes'] ); ?>" />
                        <span class="wscanom-hint"><?php esc_html_e( 'default 20', 'wscanom' ); ?></span>
                    </label>
                </div>
            </div>

            <div class="wscanom-setting-row">
                <label class="wscanom-switch">
                    <input type="checkbox" name="login_captcha" value="1" <?php checked( ! empty( $settings['login_captcha'] ) ); ?> />
                    <span class="wscanom-switch-track"></span>
                </label>
                <div class="wscanom-setting-copy">
                    <strong><?php esc_html_e( 'Verifikasi keamanan (CAPTCHA) di form login', 'wscanom' ); ?></strong>
                    <p><?php esc_html_e( 'Soal aritmatika sederhana di halaman login — cukup untuk menghalau bot otomatis yang mencoba ribuan kombinasi tanpa sungguhan "melihat" halamannya, tanpa layanan pihak ketiga, tanpa kunci API, dan tanpa mengirim data apa pun keluar dari situsmu.', 'wscanom' ); ?></p>
                </div>
            </div>

            <div class="wscanom-setting-row">
                <label class="wscanom-switch">
                    <input type="checkbox" name="email_alerts" value="1" <?php checked( ! empty( $settings['email_alerts'] ) ); ?> />
                    <span class="wscanom-switch-track"></span>
                </label>
                <div class="wscanom-setting-copy">
                    <strong><?php esc_html_e( 'Notifikasi email saat ada temuan', 'wscanom' ); ?></strong>
                    <p><?php esc_html_e( 'Dikirim ke alamat email admin situs setiap kali scan menemukan file di atas ambang skor berikut.', 'wscanom' ); ?></p>
                    <label class="wscanom-inline-number">
                        <?php esc_html_e( 'Ambang skor alert', 'wscanom' ); ?>
                        <input type="number" name="alert_min_score" min="1" max="10" value="<?php echo esc_attr( $settings['alert_min_score'] ); ?>" />
                        <span class="wscanom-hint"><?php esc_html_e( '1–10, default 7', 'wscanom' ); ?></span>
                    </label>
                </div>
            </div>

            <p class="wscanom-form-submit"><button type="submit" class="button button-primary"><?php echo esc_html( $submit_label ); ?></button></p>
        </form>
    </div>
    <?php
}

/**
 * Kartu ringkasan 2FA: berapa dari semua user yang punya kapabilitas
 * manage_options/edit_posts dkk sudah mengaktifkan 2FA miliknya sendiri.
 * 2FA diatur per-user lewat halaman profil masing-masing (lihat
 * includes/two-factor.php) — kartu ini cuma ringkasan + jalan pintas ke sana,
 * bukan tempat mengaktifkan/mematikan 2FA siapa pun.
 *
 * @return void
 */
function wscanom_render_2fa_overview_card() {
    if ( ! function_exists( 'wscanom_user_has_2fa' ) ) {
        return;
    }

    $users         = get_users( array( 'fields' => 'ID' ) );
    $total         = count( $users );
    $enabled_count = 0;
    foreach ( $users as $user_id ) {
        if ( wscanom_user_has_2fa( $user_id ) ) {
            ++$enabled_count;
        }
    }

    $own_enabled = wscanom_user_has_2fa( get_current_user_id() );
    ?>
    <div class="wscanom-card wscanom-card--twofactor">
        <div class="wscanom-card-head">
            <span class="dashicons dashicons-smartphone" aria-hidden="true"></span>
            <div>
                <h2><?php esc_html_e( 'Verifikasi Dua Langkah (2FA)', 'wscanom' ); ?></h2>
                <p class="wscanom-card-subtitle"><?php esc_html_e( 'Lapisan kedua setelah password, pakai aplikasi authenticator (Google Authenticator, Authy, dll). Diatur per akun lewat halaman profil masing-masing — tidak bisa diaktifkan oleh orang lain untukmu, dan tidak pernah aktif tanpa kamu konfirmasi sendiri lebih dulu.', 'wscanom' ); ?></p>
            </div>
        </div>
        <p>
            <?php
            echo esc_html(
                sprintf(
                    /* translators: 1: jumlah user dengan 2FA aktif, 2: total user */
                    __( '%1$d dari %2$d akun di situs ini sudah mengaktifkan 2FA.', 'wscanom' ),
                    $enabled_count,
                    $total
                )
            );
            ?>
            <?php if ( $own_enabled ) : ?>
                <span class="wscanom-badge wscanom-badge-on"><?php esc_html_e( 'Akunmu: aktif', 'wscanom' ); ?></span>
            <?php else : ?>
                <span class="wscanom-badge wscanom-badge-off"><?php esc_html_e( 'Akunmu: belum aktif', 'wscanom' ); ?></span>
            <?php endif; ?>
        </p>
        <p>
            <a class="button <?php echo $own_enabled ? '' : 'button-primary'; ?>" href="<?php echo esc_url( get_edit_user_link() . '#wscanom-2fa' ); ?>">
                <?php echo $own_enabled ? esc_html__( 'Kelola 2FA Akunku', 'wscanom' ) : esc_html__( 'Aktifkan 2FA untuk Akunku', 'wscanom' ); ?>
            </a>
        </p>
    </div>
    <?php
}

/**
 * Tampilkan tabel riwayat file yang sedang dikarantina, dengan tombol pulihkan.
 *
 * @return void
 */
function wscanom_render_quarantine_table() {
    $log = wscanom_get_quarantine_log();

    if ( empty( $log ) ) {
        return;
    }

    // Terbaru dulu.
    uasort(
        $log,
        function ( $a, $b ) {
            return $b['time'] <=> $a['time'];
        }
    );
    ?>
    <div class="wscanom-card wscanom-card--quarantine">
        <div class="wscanom-card-head">
            <span class="dashicons dashicons-lock" aria-hidden="true"></span>
            <div>
                <h2><?php esc_html_e( 'File dalam Karantina', 'wscanom' ); ?></h2>
                <p class="wscanom-card-subtitle"><?php esc_html_e( 'File biasa di sini sudah dipindahkan keluar dari lokasi aslinya dan tidak bisa dieksekusi. Entri "Backup penuh (root)" adalah salinan isi lengkap sebelum blok tersuntik dibersihkan. Pulihkan hanya kalau kamu yakin ini salah tuduh.', 'wscanom' ); ?></p>
            </div>
        </div>
    <table class="widefat striped">
        <thead>
            <tr>
                <th><?php esc_html_e( 'File asal', 'wscanom' ); ?></th>
                <th style="width:140px;"><?php esc_html_e( 'Jenis', 'wscanom' ); ?></th>
                <th style="width:200px;"><?php esc_html_e( 'Waktu', 'wscanom' ); ?></th>
                <th style="width:160px;"><?php esc_html_e( 'Aksi', 'wscanom' ); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ( $log as $id => $entry ) : ?>
                <?php $is_root_backup = isset( $entry['type'] ) && 'root_backup' === $entry['type']; ?>
                <?php $is_auto = ! empty( $entry['auto'] ); ?>
                <tr>
                    <td>
                        <code><?php echo esc_html( $entry['original_path'] ); ?></code>
                        <?php if ( $is_auto ) : ?>
                            <br /><span class="wscanom-badge" title="<?php echo esc_attr( ! empty( $entry['reason'] ) ? implode( '; ', (array) $entry['reason'] ) : '' ); ?>"><?php esc_html_e( 'Dikarantina otomatis', 'wscanom' ); ?></span>
                        <?php endif; ?>
                    </td>
                    <td><?php echo $is_root_backup ? esc_html__( 'Backup penuh (root)', 'wscanom' ) : esc_html__( 'File dipindah', 'wscanom' ); ?></td>
                    <td><?php echo esc_html( wp_date( 'Y-m-d H:i', $entry['time'] ) ); ?></td>
                    <td>
                        <?php
                        $confirm_text = $is_root_backup
                            ? __( 'File ini akan ditimpa dengan isi SEBELUM dibersihkan, termasuk blok kode backdoor yang sudah dibuang. Hanya lakukan ini jika pembersihan sebelumnya salah tuduh. Lanjutkan?', 'wscanom' )
                            : __( 'Yakin mau memulihkan file ini ke lokasi asalnya?', 'wscanom' );
                        ?>
                        <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" onsubmit="return confirm('<?php echo esc_js( $confirm_text ); ?>');">
                            <?php wp_nonce_field( 'wscanom_restore' ); ?>
                            <input type="hidden" name="action" value="wscanom_restore" />
                            <input type="hidden" name="quarantine_id" value="<?php echo esc_attr( $id ); ?>" />
                            <button type="submit" class="button button-small"><?php esc_html_e( 'Pulihkan', 'wscanom' ); ?></button>
                        </form>
                    </td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    </div>
    <?php
}

/**
 * Halaman Network Admin: daftar situs di jaringan, masing-masing dengan
 * tautan ke halaman scan situsnya (wp-content dibagi bersama di multisite
 * standar, jadi cukup diingatkan; uploads tiap situs tetap terpisah dan
 * ikut terpindai saat scan dijalankan dari situs tersebut).
 *
 * @return void
 */
function wscanom_render_network_page() {
    if ( ! current_user_can( 'manage_network' ) ) {
        wp_die( esc_html__( 'Kamu tidak punya izin mengakses halaman ini.', 'wscanom' ) );
    }

    $site_limit  = 200;
    $sites       = get_sites( array( 'number' => $site_limit ) );
    $total_sites = (int) get_sites(
        array(
            'number' => 0,
            'fields' => 'ids',
            'count'  => true,
        )
    );
    ?>
    <div class="wrap">
        <h1><?php esc_html_e( 'WScanom — Jaringan', 'wscanom' ); ?></h1>
        <p>
            <?php esc_html_e( 'wp-content (plugin dan tema) umumnya dibagi oleh semua situs di jaringan ini, jadi memindai satu situs biasanya sudah mencakup semuanya. Folder uploads tiap situs berbeda-beda, jadi tetap jalankan scan dari tiap situs secara berkala.', 'wscanom' ); ?>
        </p>
        <?php if ( $total_sites > count( $sites ) ) : ?>
            <div class="notice notice-warning" style="padding:10px 12px;">
                <p style="margin:0.4em 0;">
                    <?php
                    echo esc_html(
                        sprintf(
                            /* translators: 1: jumlah situs ditampilkan, 2: total situs di jaringan */
                            __( 'Daftar di bawah hanya menampilkan %1$d dari total %2$d situs di jaringan ini. Situs lainnya tidak terdaftar di halaman ini — buka tautan "Tools > WScanom" langsung dari dashboard situs tersebut untuk memindainya.', 'wscanom' ),
                            count( $sites ),
                            $total_sites
                        )
                    );
                    ?>
                </p>
            </div>
        <?php endif; ?>
        <table class="widefat striped">
            <thead>
                <tr>
                    <th><?php esc_html_e( 'Situs', 'wscanom' ); ?></th>
                    <th><?php esc_html_e( 'Aksi', 'wscanom' ); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ( $sites as $site ) : ?>
                    <?php
                    switch_to_blog( $site->blog_id );
                    $site_url   = home_url( '/' );
                    $scan_url   = admin_url( 'tools.php?page=wscanom' );
                    restore_current_blog();
                    ?>
                    <tr>
                        <td><?php echo esc_html( $site_url ); ?></td>
                        <td><a class="button" href="<?php echo esc_url( $scan_url ); ?>"><?php esc_html_e( 'Buka Scanner Situs Ini', 'wscanom' ); ?></a></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php
}
