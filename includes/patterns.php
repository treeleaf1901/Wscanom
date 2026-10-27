<?php
/**
 * WScanom — Daftar pola deteksi webshell/backdoor.
 *
 * @package WScanom
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Mengembalikan daftar pola regex yang dicari pada tiap file .php.
 * Tiap entri: nama_internal => [regex, bobot risiko 1-10, catatan untuk ditampilkan].
 *
 * @return array
 */
function wscanom_get_patterns() {
    return array(
        // --- Eksekusi kode dari string / request, inti dari webshell ---
        'eval_base64' => array(
            'regex'   => '/eval\s*\(\s*base64_decode/i',
            'bobot'   => 10,
            'catatan' => __( 'eval() atas hasil decode base64 — pola webshell paling umum', 'wscanom' ),
        ),
        'eval_gzinflate' => array(
            'regex'   => '/eval\s*\(\s*gzinflate/i',
            'bobot'   => 10,
            'catatan' => __( 'eval() atas data terkompresi — biasa menyembunyikan payload', 'wscanom' ),
        ),
        'eval_str_rot13' => array(
            'regex'   => '/eval\s*\(\s*str_rot13/i',
            'bobot'   => 9,
            'catatan' => __( 'eval() atas string ter-obfuscate rot13', 'wscanom' ),
        ),
        'assert_eval' => array(
            'regex'   => '/assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
            'bobot'   => 10,
            'catatan' => __( 'assert() dieksekusi dari input pengunjung', 'wscanom' ),
        ),
        'create_function_backdoor' => array(
            'regex'   => '/create_function\s*\(.*\$_(GET|POST|REQUEST)/is',
            'bobot'   => 9,
            'catatan' => __( 'create_function dengan input user — pola backdoor klasik', 'wscanom' ),
        ),
        'preg_replace_e' => array(
            'regex'   => '/preg_replace\s*\([^,]*\/e["\']/i',
            'bobot'   => 9,
            'catatan' => __( 'preg_replace modifier /e mengeksekusi kode', 'wscanom' ),
        ),

        // --- Eksekusi command sistem ---
        'system_from_request' => array(
            'regex'   => '/(system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST)/i',
            'bobot'   => 10,
            'catatan' => __( 'eksekusi perintah sistem langsung dari input pengunjung', 'wscanom' ),
        ),

        // --- File write dari input user ---
        'file_put_contents_request' => array(
            'regex'   => '/file_put_contents\s*\(\s*\$_(GET|POST|REQUEST)/i',
            'bobot'   => 8,
            'catatan' => __( 'menulis file dari input pengunjung — bisa dipakai upload webshell lain', 'wscanom' ),
        ),

        // --- Obfuscation umum ---
        'obfuscated_var_var' => array(
            'regex'   => '/\$\{?\$\{?\$_(GET|POST|REQUEST|COOKIE)/i',
            'bobot'   => 8,
            'catatan' => __( 'variable-variable dari input pengunjung — menyembunyikan pemanggilan fungsi', 'wscanom' ),
        ),
        'chr_concat_long' => array(
            'regex'   => '/(chr\(\d+\)\s*\.\s*){6,}/i',
            'bobot'   => 7,
            'catatan' => __( 'rangkaian chr() panjang — membentuk string fungsi tersembunyi', 'wscanom' ),
        ),
        'gzuncompress_payload' => array(
            'regex'   => '/gzuncompress\s*\(\s*base64_decode/i',
            'bobot'   => 8,
            'catatan' => __( 'payload terkompresi dan ter-encode — pola packer malware', 'wscanom' ),
        ),

        // --- Backdoor mail / exfiltration ---
        'mail_with_request' => array(
            'regex'   => '/mail\s*\(.*\$_(GET|POST|REQUEST)/is',
            'bobot'   => 5,
            'catatan' => __( 'fungsi mail() dipengaruhi input pengunjung — bisa dipakai spam relay', 'wscanom' ),
        ),
        'curl_to_raw_ip' => array(
            'regex'   => '/curl_setopt.*CURLOPT_URL.*\$_(GET|POST|REQUEST)/is',
            'bobot'   => 6,
            'catatan' => __( 'target curl dari input pengunjung — bisa dipakai SSRF/exfiltrasi', 'wscanom' ),
        ),

        // --- "Auto-download": dropper yang mengambil payload dari luar ---
        'remote_fetch_eval' => array(
            'regex'   => '/eval\s*\(\s*(wp_remote_retrieve_body|file_get_contents)\s*\(/i',
            'bobot'   => 10,
            'catatan' => __( 'eval() langsung atas hasil ambil data dari URL luar — pola updater/C2 malware', 'wscanom' ),
        ),
        'write_remote_content' => array(
            'regex'   => '/(file_put_contents|fwrite)\s*\([^,]+,\s*(file_get_contents|curl_exec|fopen)\s*\(\s*["\']https?:\/\//i',
            'bobot'   => 10,
            'catatan' => __( 'menyimpan isi dari URL luar ke file lokal — dropper mengunduh payload tambahan', 'wscanom' ),
        ),

        // --- "Auto-create": admin siluman atau cron tersembunyi ---
        'hidden_admin_creation' => array(
            'regex'   => '/wp_insert_user\s*\([^;]*administrator/i',
            'bobot'   => 10,
            'catatan' => __( 'membuat user baru dengan role administrator secara terprogram', 'wscanom' ),
        ),
        'wpdb_direct_user_insert' => array(
            'regex'   => '/\$wpdb\s*->\s*(query|insert)\s*\([^;]*wp_(users|usermeta)[^;]*admin/i',
            'bobot'   => 10,
            'catatan' => __( 'insert langsung ke tabel user/usermeta lewat query database, melewati validasi WordPress', 'wscanom' ),
        ),
        'hidden_cron_backdoor' => array(
            'regex'   => '/wp_schedule_event\s*\([^;]*(wp_temp|wp_vcd|system_check|update_check|auto_update_x)/i',
            'bobot'   => 9,
            'catatan' => __( 'cron job tersembunyi dengan nama hook mencurigakan', 'wscanom' ),
        ),

        // --- "Streaming"/redirect: pembajakan traffic, cloaking SEO, injeksi iklan ---
        'cloaking_bot_check' => array(
            'regex'   => '/strpos\s*\(\s*\$_SERVER\[[\'"]HTTP_USER_AGENT[\'"]\].*(googlebot|bingbot|yandex|baiduspider)/i',
            'bobot'   => 6,
            'catatan' => __( 'konten berbeda dikirim khusus untuk bot mesin pencari — pola cloaking SEO spam', 'wscanom' ),
        ),
        'hidden_iframe' => array(
            'regex'   => '/<iframe[^>]+style\s*=\s*["\'][^"\']*display\s*:\s*none/i',
            'bobot'   => 7,
            'catatan' => __( 'iframe tersembunyi (display:none) — umum dipakai pembajakan traffic/iklan siluman', 'wscanom' ),
        ),
        'htaccess_rewrite' => array(
            'regex'   => '/(file_put_contents|fwrite)\s*\([^,]*\.htaccess/i',
            'bobot'   => 7,
            'catatan' => __( 'menulis ke file .htaccess dari PHP — bisa dipakai menanam redirect paksa', 'wscanom' ),
        ),

        // --- Marker generik self-replicating backdoor (mis. "WDG-CORE" style) ---
        'self_replicating_marker' => array(
            'regex'   => '/file_exists\s*\([^)]*\)\s*&&\s*!\s*\w+\s*\([^)]*has_?marker/i',
            'bobot'   => 6,
            'catatan' => __( 'pola cek-lalu-tanam-ulang file — ciri backdoor yang menyebarkan diri sendiri (self-healing)', 'wscanom' ),
        ),
        'core_marker_comment' => array(
            'regex'   => '/\/\*\s*[A-Z0-9_-]{2,20}-CORE-(START|END)\s*\*\//i',
            'bobot'   => 9,
            'catatan' => __( 'komentar penanda blok kode tersuntik (pola "XXX-CORE-START/END") — khas backdoor yang menandai wilayahnya sendiri untuk ditulis ulang', 'wscanom' ),
        ),
    );
}

/**
 * Nama file yang umum dipakai sebagai kedok webshell.
 *
 * Akhiran ekstensinya sengaja dibuat dinamis dari wscanom_scannable_extensions()
 * (bukan di-hardcode "\.php$"), supaya "c99.phtml" atau "wso.php5" tetap
 * dapat bonus skor "nama file mencurigakan" ini — bukan cuma "c99.php" —
 * konsisten dengan ekstensi yang memang dipindai oleh wscanom_list_php_files().
 *
 * @return array
 */
function wscanom_suspicious_filenames() {
    $ext_group = implode( '|', array_map( 'preg_quote', wscanom_scannable_extensions() ) );

    return array(
        '/^wp-tmp\.(?:' . $ext_group . ')$/i',
        '/^wp-feed\.(?:' . $ext_group . ')$/i',
        '/^wp-vcd\.(?:' . $ext_group . ')$/i',
        '/^[a-f0-9]{8,32}\.(?:' . $ext_group . ')$/i',
        '/^(?:shell|c99|r57|wso|up|cmd|b374k|indoxploit)\.(?:' . $ext_group . ')$/i',
    );
}
