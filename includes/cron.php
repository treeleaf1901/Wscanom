<?php
/**
 * WScanom — Scan terjadwal, riwayat, dan notifikasi email.
 *
 * @package WScanom
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'WSCANOM_CRON_HOOK', 'wscanom_scheduled_scan' );
define( 'WSCANOM_HISTORY_OPTION', 'wscanom_last_scan_summary' );
define( 'WSCANOM_SETTINGS_OPTION', 'wscanom_settings' );
define( 'WSCANOM_CRON_RESUME_TRANSIENT', 'wscanom_cron_resume_state' );
define( 'WSCANOM_CRON_CONTINUE_HOOK', 'wscanom_scheduled_scan_continue' );
// Batas aman jumlah "lanjutan" berantai sebelum menyerah dan melaporkan
// hasil sebagian — mencegah loop penjadwalan ulang tak berkesudahan kalau
// situsnya luar biasa besar atau budget waktu per-run terlalu kecil.
define( 'WSCANOM_CRON_MAX_CHAIN', 20 );

/**
 * Nilai pengaturan default.
 *
 * @return array
 */
function wscanom_default_settings() {
    return array(
        'email_alerts'              => true,
        'alert_min_score'           => 7,
        // Proteksi otomatis — defaultnya AKTIF supaya situs terlindungi sejak
        // aktivasi tanpa admin perlu konfigurasi apa pun ("terima beres").
        // Tetap bisa dimatikan lewat halaman pengaturan untuk kasus khusus
        // (mis. developer yang memang perlu Theme/Plugin Editor).
        'disable_file_editor'       => true,
        'auto_quarantine'           => true,
        // Ambang ini dicek terhadap bobot SATU pola tertinggi yang cocok
        // pada file (bukan skor total gabungan semua pola), sengaja lebih
        // ketat daripada ambang tampilan di tabel hasil — supaya tindakan
        // OTOMATIS (tanpa persetujuan manusia) hanya terjadi untuk pola
        // yang nyaris pasti bukan false positive (lihat includes/patterns.php).
        'auto_quarantine_min_weight' => 9,

        // --- Pembatas brute-force login: AMAN, default aktif ---
        // Nilai default sengaja longgar (5x, kunci 20 menit) supaya admin
        // yang salah ketik password sendiri beberapa kali tidak langsung
        // terkunci dari situsnya sendiri.
        'bruteforce_protection'     => true,
        'bruteforce_max_attempts'   => 5,
        'bruteforce_lockout_minutes' => 20,

        // --- Lockout progresif: BERISIKO kalau admin sendiri sering lupa
        // password (durasi kunci bisa naik berkali-kali lipat sampai
        // maksimal 24 jam untuk IP/akun yang berulang kali kena lockout
        // dalam 7 hari terakhir), default MATI — admin yang aktifkan sendiri
        // lewat tabel Pengerasan Lanjutan setelah membaca penjelasan cara
        // kerjanya. Begitu login BERHASIL, seluruh riwayat eskalasi langsung
        // direset ke nol (lihat wscanom_clear_login_attempts()). ---
        'bruteforce_progressive_lockout' => false,

        // --- CAPTCHA di form login: AMAN, default aktif ---
        // Soal matematika sederhana, tidak ada layanan pihak ketiga, tidak
        // ada risiko mengunci siapa pun (siapa saja bisa menjawab).
        'login_captcha'             => true,

        // --- Header IP tepercaya: BERISIKO kalau situsnya ternyata bisa
        // diakses langsung tanpa lewat proxy tersebut (header bisa
        // dipalsukan pengunjung, melewati pembatas brute-force sepenuhnya),
        // default KOSONG (cuma pakai REMOTE_ADDR, selalu aman) — admin yang
        // pilih sendiri lewat tabel Pengerasan Lanjutan setelah melihat
        // perbandingan nilai REMOTE_ADDR vs header tersebut secara langsung. ---
        'trusted_ip_header'         => '',

        // --- Pengerasan lanjutan: BERISIKO kalau situsnya tidak siap,
        // semua default MATI, admin yang aktifkan sendiri setelah membaca
        // deteksi dini yang ditampilkan di UI (lihat admin-page.php). ---
        'disable_xmlrpc_entirely'   => false,
        'force_https'               => false,
        'disable_feeds'              => false,
    );
}

/**
 * Ambil pengaturan plugin untuk situs saat ini.
 *
 * @return array
 */
function wscanom_get_settings() {
    $settings = get_option( WSCANOM_SETTINGS_OPTION, array() );
    return wp_parse_args( is_array( $settings ) ? $settings : array(), wscanom_default_settings() );
}

/**
 * Jadwalkan scan harian saat plugin diaktifkan.
 *
 * @return void
 */
function wscanom_schedule_cron() {
    if ( ! wp_next_scheduled( WSCANOM_CRON_HOOK ) ) {
        wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', WSCANOM_CRON_HOOK );
    }
}

/**
 * Batalkan jadwal saat plugin dinonaktifkan.
 *
 * @return void
 */
function wscanom_unschedule_cron() {
    $timestamp = wp_next_scheduled( WSCANOM_CRON_HOOK );
    if ( $timestamp ) {
        wp_unschedule_event( $timestamp, WSCANOM_CRON_HOOK );
    }

    // Batalkan juga event "lanjutan" (kalau sedang ada scan yang terpotong
    // budget waktu dan menunggu disambung) supaya tidak ada proses yatim
    // yang tetap berjalan setelah plugin dinonaktifkan.
    $continue_timestamp = wp_next_scheduled( WSCANOM_CRON_CONTINUE_HOOK );
    if ( $continue_timestamp ) {
        wp_unschedule_event( $continue_timestamp, WSCANOM_CRON_CONTINUE_HOOK );
    }
    delete_transient( WSCANOM_CRON_RESUME_TRANSIENT );
}

add_action( WSCANOM_CRON_HOOK, 'wscanom_run_scheduled_scan' );
add_action( WSCANOM_CRON_CONTINUE_HOOK, 'wscanom_run_scheduled_scan' );

/**
 * Batas waktu (detik) yang dianggap aman untuk satu "jalan" scan terjadwal
 * sebelum berhenti sejenak dan menyambung lagi lewat event terpisah.
 * WP-Cron biasanya berjalan lewat self-request HTTP yang masih tunduk pada
 * max_execution_time PHP (sering 30-60 detik di hosting bersama) — tanpa
 * batas ini, situs dengan banyak file bisa membuat proses scan terpotong
 * paksa oleh PHP di tengah jalan, TANPA ringkasan tersimpan dan TANPA
 * notifikasi apa pun ke admin (gagal diam-diam).
 *
 * @return int
 */
function wscanom_cron_time_budget() {
    return (int) apply_filters( 'wscanom_cron_time_budget', 20 );
}

/**
 * Jalankan scan di background (konteks WP-Cron). Berbeda dari scan AJAX
 * interaktif (yang sengaja dipecah per-batch dari sisi browser supaya
 * tidak timeout), proses cron dulunya memindai SEMUA file dalam satu jalan
 * — pada situs besar ini bisa melebihi max_execution_time PHP dan membuat
 * proses mati di tengah jalan tanpa jejak kegagalan apa pun. Sekarang,
 * progres disimpan berkala (transient) dan proses melanjutkan dirinya
 * sendiri lewat event terpisah kalau anggaran waktu habis sebelum semua
 * file selesai dipindai, sampai batas rantai aman (WSCANOM_CRON_MAX_CHAIN)
 * — kalau batas itu tercapai, hasil SEBAGIAN tetap disimpan dan ditandai
 * 'incomplete' supaya terlihat jelas di UI, bukan hilang begitu saja.
 *
 * @return void
 */
function wscanom_run_scheduled_scan() {
    $start = microtime( true );
    $budget = wscanom_cron_time_budget();
    $base  = wscanom_scan_base_dir();

    $state = get_transient( WSCANOM_CRON_RESUME_TRANSIENT );
    if ( is_array( $state ) && isset( $state['files'], $state['total'] ) ) {
        $files     = $state['files'];
        $total     = $state['total'];
        $flagged   = $state['flagged'];
        $top_score = $state['top_score'];
        $chain     = isset( $state['chain'] ) ? (int) $state['chain'] : 1;
    } else {
        $files     = wscanom_list_php_files( $base );
        $total     = count( $files );
        $flagged   = array();
        $top_score = 0;
        $chain     = 1;
    }

    $timed_out = false;

    while ( ! empty( $files ) ) {
        if ( microtime( true ) - $start > $budget ) {
            $timed_out = true;
            break;
        }

        $relative_path = array_shift( $files );
        $full_path     = $base . '/' . $relative_path;
        $scan          = wscanom_scan_file( $full_path, $relative_path );

        if ( $scan['score'] > 0 && ! $scan['whitelisted'] ) {
            $flagged[] = array(
                'file'  => $relative_path,
                'score' => $scan['score'],
            );
            $top_score = max( $top_score, $scan['score'] );
        }
    }

    if ( $timed_out && ! empty( $files ) ) {
        if ( $chain >= WSCANOM_CRON_MAX_CHAIN ) {
            // Menyerah: simpan apa pun yang sempat ditemukan sejauh ini,
            // tapi tandai jelas bahwa scan TIDAK selesai menjangkau semua
            // file, supaya admin tahu hasil ini tidak lengkap alih-alih
            // mengira situsnya sepenuhnya bersih.
            delete_transient( WSCANOM_CRON_RESUME_TRANSIENT );
            wscanom_finish_scheduled_scan( $total, $flagged, $top_score, true );
            return;
        }

        // Simpan progres dan sambung lagi lewat event terpisah sesegera
        // mungkin (bukan menunggu jadwal harian berikutnya).
        set_transient(
            WSCANOM_CRON_RESUME_TRANSIENT,
            array(
                'files'     => $files,
                'total'     => $total,
                'flagged'   => $flagged,
                'top_score' => $top_score,
                'chain'     => $chain + 1,
            ),
            HOUR_IN_SECONDS
        );
        if ( ! wp_next_scheduled( WSCANOM_CRON_CONTINUE_HOOK ) ) {
            wp_schedule_single_event( time() + MINUTE_IN_SECONDS, WSCANOM_CRON_CONTINUE_HOOK );
        }
        return;
    }

    delete_transient( WSCANOM_CRON_RESUME_TRANSIENT );
    wscanom_finish_scheduled_scan( $total, $flagged, $top_score, false );
}

/**
 * Simpan ringkasan akhir scan terjadwal (selesai penuh atau sebagian) dan
 * kirim notifikasi email kalau relevan.
 *
 * @param int   $total      Total file yang terdaftar untuk dipindai.
 * @param array $flagged    Daftar temuan.
 * @param int   $top_score  Skor tertinggi dari temuan.
 * @param bool  $incomplete True kalau scan berhenti sebelum menjangkau semua file.
 * @return void
 */
function wscanom_finish_scheduled_scan( $total, $flagged, $top_score, $incomplete ) {
    usort(
        $flagged,
        function ( $a, $b ) {
            return $b['score'] <=> $a['score'];
        }
    );

    $summary = array(
        'time'        => time(),
        'total_files' => $total,
        'flagged'     => $flagged,
        'top_score'   => $top_score,
        'incomplete'  => $incomplete,
    );

    update_option( WSCANOM_HISTORY_OPTION, $summary, false );

    wscanom_maybe_send_alert( $summary );
}

/**
 * Ambil ringkasan scan terjadwal terakhir.
 *
 * @return array|null
 */
function wscanom_get_last_scan_summary() {
    $summary = get_option( WSCANOM_HISTORY_OPTION, null );
    return is_array( $summary ) ? $summary : null;
}

/**
 * Kirim email ke admin jika ada temuan dengan skor di atas ambang
 * yang dikonfigurasi, dan notifikasi email diaktifkan.
 *
 * @param array $summary Ringkasan hasil scan.
 * @return void
 */
function wscanom_maybe_send_alert( $summary ) {
    $settings = wscanom_get_settings();

    if ( empty( $settings['email_alerts'] ) ) {
        return;
    }

    $worth_alerting = array_filter(
        $summary['flagged'],
        function ( $row ) use ( $settings ) {
            return $row['score'] >= (int) $settings['alert_min_score'];
        }
    );

    if ( empty( $worth_alerting ) ) {
        return;
    }

    $admin_email = get_option( 'admin_email' );
    $site_name   = get_bloginfo( 'name' );
    $scan_url    = admin_url( 'tools.php?page=wscanom' );

    $lines   = array();
    $lines[] = sprintf(
        /* translators: 1: jumlah file, 2: nama situs */
        __( 'WScanom menemukan %1$d file dengan indikasi mencurigakan di situs %2$s.', 'wscanom' ),
        count( $worth_alerting ),
        $site_name
    );
    $lines[] = '';
    foreach ( array_slice( $worth_alerting, 0, 20 ) as $row ) {
        $lines[] = sprintf( '[%d] %s', $row['score'], $row['file'] );
    }
    $lines[] = '';
    $lines[] = sprintf(
        /* translators: %s: tautan ke halaman scanner */
        __( 'Buka halaman WScanom untuk detail dan tindak lanjut: %s', 'wscanom' ),
        $scan_url
    );

    wp_mail(
        $admin_email,
        sprintf(
            /* translators: %s: nama situs */
            __( '[%s] WScanom menemukan file mencurigakan', 'wscanom' ),
            $site_name
        ),
        implode( "\n", $lines )
    );
}
