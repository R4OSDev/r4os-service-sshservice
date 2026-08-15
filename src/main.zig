const r4os = @import("r4os");
const std = @import("std");
const ssh_chacha = @import("ssh_chacha.zig");
const sftp_write_policy = @import("sftp_write_policy.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Ed25519 = std.crypto.sign.Ed25519;
const X25519 = std.crypto.dh.X25519;
const Poly1305 = std.crypto.onetimeauth.Poly1305;

const service_name = "SSHD";
const selftest_arg = "/SELFTEST";
const ping_arg = "/PING";
const status_arg = "/STATUS";
const registry_key = "SYSTEM\\Services\\SSHD";
const log_origin = "SSHD";
const ssh_ident = "SSH-2.0-R4OS_SSHD_0.52.9";
const ssh_banner = ssh_ident ++ "\r\n";

const default_enabled = true;
const default_client_target = "WindowsOpenSSH";
const default_user_name = "r4os";
const default_password = "rosebud";
const default_listen_port: u16 = 22;
const default_max_sessions: u32 = 8;
const default_log_passwords = true;
const default_shell_path = "C:\\R4OS\\SOFTWARE\\TERMINAL\\TERMINAL.R4X";
const default_shell_args = "/NOAUTOEXEC";
const default_sftp_root = "/C/";
const default_host_key_type = "ed25519";

const op_status: u16 = 1;
const op_ping: u16 = 2;
const listen_wait_ticks: u32 = 450;
const service_register_wait_ticks: u32 = 120;
const client_flush_ticks: u64 = 5;
const session_worker_slots_max: usize = 8;
// Vier vorbereitete Kryptopuffer belegen bereits knapp 4 MB. Bei einer
// frischen Registry steht MaxSessions auf acht; alle acht im Mainloop
// vorzuwärmen führte nach dem ersten Allokationsfehler zu einer endlosen
// Retry-Schleife und verhungerte Accept- sowie Service-Endpoint-Arbeit.
// Zusätzliche Slots bleiben erlaubt und allokieren ihren Scratch bei Bedarf.
const session_scratch_prewarm_max: u32 = 4;
const accept_burst_max: usize = 4;
// 0.56.5: Idle-Accept-Intervall bleibt 100 ms. Der Versuch mit 15 ms
// (2026-07-03) flutete die Single-Thread-Request-Queue von TCPSVC
// (accept_poll 26..56 -> 649..930 pro Lauf) und hungerte dessen andere
// Klienten aus: ssh-exec-Erstversuch fiel in 3/3 Laeufen (attempts=2,
// ~15 s statt 1,7 s), NETCAT/FTPSVC bekamen teils gar keine Antwort
// mehr. Jeder Accept-Poll ist ein TCPSVC-Request mit Service-Wait -
// dieses Intervall ist Queue-Fairness gegenueber allen TCPSVC-Klienten,
// nicht nur eine RX-Frage.
const accept_idle_poll_ms: u64 = 100;
const session_worker_stack_bytes: u64 = 2 * 1024 * 1024;
var ssh_crypto_lock: u32 = 0;
var tcp_service_lock: u32 = 0;
var sftp_stage_nonce_lock: u32 = 0;
var sftp_stage_nonce: u32 = 0;
var transfer_event_sequence: u64 = 0;
// 0.56.5: Eigener Lock NUR fuer den Accept-Poll des Main-Loops, getrennt
// vom tcp_service_lock der Session-Worker-I/O. Vorher serialisierte EIN
// globaler Lock Accept UND Worker-I/O: waehrend ein Worker sendet
// (Banner/KEX, bis ~150 ms unterm Lock), kam der Main-Loop nicht an den
// Accept -> bei mehreren schnellen Verbindungen wurden established-
// Verbindungen zu spaet geclaimt (Kernel acc=N, SSHD accepted<<N,
// Client-Banner-Timeout). Der Kernel-Endpoint-Layer serialisiert intern
// bereits pro Operation (registry_lock) und ordnet Antworten per
// request_id zu; die SSHD-seitige Accept-vs-Worker-Serialisierung ist
// fuer die Korrektheit redundant. Accept hat nur EINEN Aufrufer
// (Main-Loop) -> dieser Lock ist praktisch nie contended.
var tcp_accept_lock: u32 = 0;
const session_slow_warn_ms: u64 = 30 * 1000;
const session_stop_join_ticks: u64 = 120;
const session_timeout_ms: u64 = 30000;
const auth_timeout_ms: u64 = 2 * 60 * 1000;
const channel_idle_timeout_ms: u64 = 10 * 60 * 1000;
// Ein offener SSH-Kanal darf nach einem hart verschwundenen Hostclient nicht
// bis zum zehnminuetigen allgemeinen Idle-Timeout einen Worker belegen.
// OpenSSH beantwortet die unbekannte Global-Request mit REQUEST_FAILURE;
// diese Antwort ist der reine Liveness-Nachweis.
const channel_keepalive_idle_ms: u64 = 5_000;
const channel_keepalive_interval_ms: u64 = 5_000;
const channel_idle_poll_sleep_ms: u64 = 50;
const channel_eof_grace_ms: u64 = 1500;
const exec_output_settle_ms: u64 = 8000;
const channel_packet_timeout_ms: u64 = 5000;
const channel_packet_total_timeout_ms: u64 = 30000;
const transfer_idle_timeout_ms: u64 = 120 * 1000;
const transfer_packet_total_timeout_ms: u64 = 120 * 1000;
const tcp_service_wait_ms: u64 = 5000;
// 0.56.2: accept/call-Wait 50/100 -> 150 ms. Der Wait ist die OBERGRENZE
// des Wartens auf die TCPSVC-Antwort (Completion weckt sofort); mit dem
// gesunden TX/RX-Pfad kommen Antworten in wenigen ms. 50 ms verpasste
// unter Scheduler-Last einen Teil der Accept-Antworten -> Cancel ->
// die bereits geclaimte Verbindung verwaiste (Kernel acc=9, SSHD
// accepted=1..4). NICHT wieder auf 500 ms setzen: laeuft der Wait doch
// einmal voll (Antwort klemmt), haelt er solange den globalen
// tcp_service_lock und verhungert Accept + Worker-I/O (frueherer
// 500-ms-Fehlversuch in dieser Unterversion).
const tcp_service_call_wait_ms: u64 = 150;
const tcp_write_wait_ms: u64 = 15000;
const transfer_tcp_service_wait_ms: u64 = 5000;
// 0.56.5: Accept-Service-Wait 150 ms (final). Historie der Experimente
// am 2026-07-03: 40 ms verschaerfte die TCPSVC-Queue-Flut, 1000 ms
// blockierte den Main-Loop in Congestion-Phasen sekundenlang pro Poll
// (Gate 1/3). Die eigentliche Gefahr eines Cancels - services.reply()
// auf den gecancelten Request liefert NOT_FOUND und TCPSVC riss dann
// die gerade geclaimte CLIENT-VERBINDUNG ab - ist seitdem in TCPSVC
// selbst behoben: unzustellbare Accept-Replies werden dort GEPARKT und
// beim naechsten Accept-Poll sofort ausgeliefert (parked_port in
// TcpService/src/main.zig). Damit ist ein Cancel harmlos und 150 ms
// nur noch die Reaktivitaetsgrenze des Main-Loops.
const tcp_accept_service_wait_ms: u64 = 150;
const tcp_fast_service_wait_ms: u64 = 1000;
const channel_read_service_wait_ms: u64 = 1000;
const tcp_service_cleanup_wait_ms: u64 = 5000;
const tcp_control_ack_wait_ms: u64 = 1000;
const tcp_control_retransmit_wait_ms: u64 = 150;
const ssh_max_payload_len: usize = 64 * 1024;
const ssh_max_packet_len: usize = ssh_max_payload_len + 64;
const ssh_max_kex_payload_len: usize = 4096;
const ssh_max_ident_len: usize = 255;
const ssh_ident_read_chunk_max: usize = 256;
const ssh_preload_max: usize = 1024;
const ssh_channel_packet_max: u32 = 32 * 1024;
const ssh_channel_window: u32 = 32 * 1024;
const ssh_channel_window_adjust_threshold: usize = 16 * 1024;
const ssh_channel_output_chunk_max: usize = 8192;
const sftp_version: u32 = 3;
const sftp_output_capacity: usize = 32768;
const sftp_upload_capacity: usize = 64 * 1024;
const sftp_input_capacity: usize = 256 * 1024;
const sftp_write_data_max: usize = 32 * 1024;
const sftp_read_chunk_max: usize = sftp_output_capacity - 32;
const sftp_readdir_batch_max: u32 = 16;
const sftp_path_capacity: usize = 1024; // contract file_path_max_bytes + NUL (0.60.19)
const sftp_handle_file = "F1";
const sftp_handle_dir = "D1";
const scp_max_file_size: usize = std.math.maxInt(u32);
const scp_filename_capacity: usize = @as(usize, r4os.abi.fat_path_component_max_bytes) + 1;
const scp_header_capacity: usize = scp_filename_capacity + 64;
const scp_source_data_chunk_max: usize = ssh_channel_output_chunk_max - 1;
const transfer_stream_chunk_max: usize = 32 * 1024;
const transfer_sleep_stride: u64 = 256 * 1024;

const sftp_msg_init: u8 = 1;
const sftp_msg_version: u8 = 2;
const sftp_msg_open: u8 = 3;
const sftp_msg_close: u8 = 4;
const sftp_msg_read: u8 = 5;
const sftp_msg_write: u8 = 6;
const sftp_msg_lstat: u8 = 7;
const sftp_msg_fstat: u8 = 8;
const sftp_msg_setstat: u8 = 9;
const sftp_msg_fsetstat: u8 = 10;
const sftp_msg_opendir: u8 = 11;
const sftp_msg_readdir: u8 = 12;
const sftp_msg_remove: u8 = 13;
const sftp_msg_mkdir: u8 = 14;
const sftp_msg_rmdir: u8 = 15;
const sftp_msg_realpath: u8 = 16;
const sftp_msg_stat: u8 = 17;
const sftp_msg_rename: u8 = 18;
const sftp_msg_status: u8 = 101;
const sftp_msg_handle: u8 = 102;
const sftp_msg_data: u8 = 103;
const sftp_msg_name: u8 = 104;
const sftp_msg_attrs: u8 = 105;

const sftp_status_ok: u32 = 0;
const sftp_status_eof: u32 = 1;
const sftp_status_no_such_file: u32 = 2;
const sftp_status_permission_denied: u32 = 3;
const sftp_status_failure: u32 = 4;
const sftp_status_bad_message: u32 = 5;
const sftp_status_op_unsupported: u32 = 8;

const sftp_pflag_read = sftp_write_policy.pflag_read;
const sftp_pflag_write = sftp_write_policy.pflag_write;

const sftp_attr_size: u32 = 0x0000_0001;
const sftp_attr_permissions: u32 = 0x0000_0004;
const sftp_attr_acmodtime: u32 = 0x0000_0008;
const sftp_perm_dir: u32 = 0x41ff;
const sftp_perm_file: u32 = 0x81b6;
const transfer_max_file_size: u64 = 0xFFFF_FFFF;

const registry_host_key_seed = "HostKeySeed";
const registry_host_key_public = "HostKeyPublic";

const ssh_msg_disconnect: u8 = 1;
const ssh_msg_service_request: u8 = 5;
const ssh_msg_service_accept: u8 = 6;
const ssh_msg_kexinit: u8 = 20;
const ssh_msg_newkeys: u8 = 21;
const ssh_msg_kex_ecdh_init: u8 = 30;
const ssh_msg_kex_ecdh_reply: u8 = 31;
const ssh_msg_userauth_request: u8 = 50;
const ssh_msg_userauth_failure: u8 = 51;
const ssh_msg_userauth_success: u8 = 52;
const ssh_msg_global_request: u8 = 80;
const ssh_msg_request_success: u8 = 81;
const ssh_msg_request_failure: u8 = 82;
const ssh_msg_channel_open: u8 = 90;
const ssh_msg_channel_open_confirmation: u8 = 91;
const ssh_msg_channel_open_failure: u8 = 92;
const ssh_msg_channel_window_adjust: u8 = 93;
const ssh_msg_channel_data: u8 = 94;
const ssh_msg_channel_eof: u8 = 96;
const ssh_msg_channel_close: u8 = 97;
const ssh_msg_channel_request: u8 = 98;
const ssh_msg_channel_success: u8 = 99;
const ssh_msg_channel_failure: u8 = 100;

const ssh_disconnect_host_not_allowed: u32 = 1;
const ssh_disconnect_protocol_error: u32 = 2;
const ssh_disconnect_key_exchange_failed: u32 = 3;
const ssh_disconnect_service_not_available: u32 = 7;
const ssh_open_administratively_prohibited: u32 = 1;

const alg_kex_curve25519 = "curve25519-sha256";
const alg_kex_curve25519_libssh = "curve25519-sha256@libssh.org";
const alg_host_ed25519 = "ssh-ed25519";
const alg_cipher_chacha = "chacha20-poly1305@openssh.com";
const alg_mac_hmac_sha256 = "hmac-sha2-256";
const alg_compression_none = "none";
const ssh_service_userauth = "ssh-userauth";
const ssh_service_connection = "ssh-connection";
const ssh_auth_method_none = "none";
const ssh_auth_method_password = "password";
const ssh_channel_session = "session";

const App = struct {
    sys: r4os.r4sys.Context,
    net: r4os.r4net.Context,

    fn init(r4_app: *r4os.App) ?App {
        return .{
            .sys = r4_app.system(),
            .net = r4_app.networkLowLevel() orelse return null,
        };
    }
};

const Config = struct {
    enabled: bool = default_enabled,
    listen_port: u16 = default_listen_port,
    max_sessions: u32 = default_max_sessions,
    log_passwords: bool = default_log_passwords,
    user_name: [32]u8 = .{0} ** 32,
    password: [32]u8 = .{0} ** 32,
    shell_path: [128]u8 = .{0} ** 128,
    shell_args: [96]u8 = .{0} ** 96,
    sftp_root: [32]u8 = .{0} ** 32,
    host_key_type: [32]u8 = .{0} ** 32,
};

const ServiceStats = struct {
    requests: u32 = 0,
    status_requests: u32 = 0,
    pings: u32 = 0,
    bad_ops: u32 = 0,
    accepted: u32 = 0,
    active_sessions: u32 = 0,
    banners_sent: u32 = 0,
    host_key_generated: u32 = 0,
    host_key_loaded: u32 = 0,
    transport_sessions: u32 = 0,
    kexinit_seen: u32 = 0,
    newkeys: u32 = 0,
    encrypted_service_requests: u32 = 0,
    encrypted_auth_requests: u32 = 0,
    auth_failures: u32 = 0,
    auth_successes: u32 = 0,
    channel_opens: u32 = 0,
    shell_sessions: u32 = 0,
    exec_sessions: u32 = 0,
    sftp_sessions: u32 = 0,
    sftp_opens: u32 = 0,
    sftp_reads: u32 = 0,
    sftp_writes: u32 = 0,
    sftp_readdirs: u32 = 0,
    sftp_removes: u32 = 0,
    sftp_renames: u32 = 0,
    sftp_bytes_in: u32 = 0,
    sftp_bytes_out: u32 = 0,
    scp_sessions: u32 = 0,
    scp_reads: u32 = 0,
    scp_writes: u32 = 0,
    scp_bytes_in: u32 = 0,
    scp_bytes_out: u32 = 0,
    transfer_aborts: u32 = 0,
    transfer_failures: u32 = 0,
    // Guards both latched transfer records.  STATUS runs on the service
    // task while a session worker updates these arrays and scalars; a plain
    // sequence check cannot make concurrent non-atomic field copies safe.
    transfer_record_lock: u32 = 0,
    last_transfer_sequence: u64 = 0,
    last_transfer_bytes: u64 = 0,
    last_transfer_ticks: u64 = 0,
    last_transfer_rc: i32 = 0,
    last_transfer_abort_rc: i32 = 0,
    last_transfer_kind: [16]u8 = .{0} ** 16,
    last_transfer_result: [32]u8 = .{0} ** 32,
    last_transfer_path: [128]u8 = .{0} ** 128,
    // Latched independently from the generic last-transfer view.  A GET
    // following a PUT must not erase the write result used by the hardware
    // acceptance helper.
    last_sftp_write_sequence: u64 = 0,
    last_sftp_write_bytes: u64 = 0,
    last_sftp_write_ticks: u64 = 0,
    last_sftp_write_rc: i32 = 0,
    last_sftp_write_abort_rc: i32 = 0,
    last_sftp_write_result: [32]u8 = .{0} ** 32,
    last_sftp_write_path: [128]u8 = .{0} ** 128,
    channel_window_adjusts: u32 = 0,
    channel_data_in: u32 = 0,
    channel_data_out: u32 = 0,
    channel_client_closes: u32 = 0,
    channel_client_eofs: u32 = 0,
    channel_idle_timeouts: u32 = 0,
    channel_keepalives_sent: u32 = 0,
    channel_keepalive_replies: u32 = 0,
    channel_keepalive_timeouts: u32 = 0,
    channel_output_failures: u32 = 0,
    // 0.56.34b-Diagnose Shell-Kanal: Ausgaenge des pollEncryptedPacket im
    // Channel-Loop (pending / service-transient / leer) - klaert, warum
    // Client-Pakete (in/eof/close) eine Session nie erreichen.
    chan_poll_pending: u32 = 0,
    chan_poll_transient: u32 = 0,
    chan_poll_idle: u32 = 0,
    last_console_state_rc: i32 = 0,
    last_console_state_len: u32 = 0,
    last_console_stream_bytes: u32 = 0,
    last_console_read_len: u32 = 0,
    last_console_send_len: u32 = 0,
    tcp_read_transients: u32 = 0,
    tcp_write_transients: u32 = 0,
    tcp_service_transients: u32 = 0,
    tcp_write_seq_skips: u32 = 0,
    client_aborts: u32 = 0,
    session_worker_started: u32 = 0,
    session_worker_completed: u32 = 0,
    session_worker_joined: u32 = 0,
    session_worker_create_failed: u32 = 0,
    session_worker_join_errors: u32 = 0,
    session_limit_waits: u32 = 0,
    accept_polls: u32 = 0,
    accept_empty: u32 = 0,
    accept_ok: u32 = 0,
    accept_errors: u32 = 0,
    last_accept_flags: u32 = 0,
    last_accept_handle: u32 = 0,
    session_slow_clients: u32 = 0,
    session_close_errors: u32 = 0,
    session_scratch_allocated: u32 = 0,
    session_scratch_freed: u32 = 0,
    session_scratch_failures: u32 = 0,
    session_scratch_ready: u32 = 0,
    session_scratch_in_use: u32 = 0,
    last_worker_id: u32 = 0,
    last_worker_thread: u32 = 0,
    last_worker_exit: i32 = 0,
    last_session_ticks: u64 = 0,
    max_session_ticks: u64 = 0,
    last_channel_exit: i32 = 0,
    last_close_reason: [32]u8 = .{0} ** 32,
    last_session_kind: [16]u8 = .{0} ** 16,
    last_exec_command: [96]u8 = .{0} ** 96,
    disconnects_sent: u32 = 0,
    tcp_errors: u32 = 0,
    protocol_errors: u32 = 0,
    crypto_errors: u32 = 0,
    last_packet_len: u32 = 0,
    last_payload_len: u32 = 0,
    last_read_want: u32 = 0,
    last_read_got: u32 = 0,
    last_read_stage: [32]u8 = .{0} ** 32,
    last_fail_packet_len: u32 = 0,
    last_fail_payload_len: u32 = 0,
    last_fail_read_want: u32 = 0,
    last_fail_read_got: u32 = 0,
    last_fail_read_stage: [32]u8 = .{0} ** 32,
    last_tcp_pending_rx: u32 = 0,
    last_tcp_rx_window: u32 = 0,
    last_tcp_tx_window: u32 = 0,
    last_tcp_retransmits: u32 = 0,
    last_tcp_rx_drops: u32 = 0,
    last_tcp_flags: u32 = 0,
    last_tcp_service_status: u32 = 0,
    registry_repairs: u32 = 0,
    last_tcp_result: i32 = 0,
    last_protocol_error: [48]u8 = .{0} ** 48,
    last_auth_user: [32]u8 = .{0} ** 32,
    last_auth_method: [24]u8 = .{0} ** 24,
    last_auth_password: [64]u8 = .{0} ** 64,
    last_failed_auth_user: [32]u8 = .{0} ** 32,
    last_failed_auth_method: [24]u8 = .{0} ** 24,
    last_failed_auth_password: [64]u8 = .{0} ** 64,
};

const HostKey = struct {
    seed: [32]u8,
    public_key: [32]u8,
    key_pair: Ed25519.KeyPair,
};

const SessionWorkerSlot = struct {
    used: bool = false,
    slow_reported: bool = false,
    thread_handle: r4os.abi.ProgramJoinHandle = .{},
    session_id: u32 = 0,
    conn_id: u32 = 0,
    started_tick: u64 = 0,
    // These fields are the only live worker state read by the parent service
    // task. Keep them atomic; the full ServiceStats is merged only after Join.
    last_activity_tick: u64 = 0,
    finished_tick: u64 = 0,
    exit_code: i32 = 0,
    close_ok: bool = false,
    close_result: i32 = 0,
    banner_sent: bool = false,
    transfer_active: u32 = 0,
    watchdog_abort_sent: u32 = 0,
    watchdog_abort_result: i32 = 0,
    app: *const App = undefined,
    config: Config = .{},
    host_key: HostKey = undefined,
    buffers: ?*SessionBuffers = null,
    stats: ServiceStats = .{},
};

const TransportKeys = struct {
    c2s: [64]u8 = .{0} ** 64,
    s2c: [64]u8 = .{0} ** 64,
};

const SessionBuffers = struct {
    server_kex_payload: [1024]u8 = .{0} ** 1024,
    client_payload: []u8 = &.{},
    ecdh_payload: []u8 = &.{},
    encrypted_payload: []u8 = &.{},
    plain_packet: []u8 = &.{},
    encrypted_packet: []u8 = &.{},
    packet_body: []u8 = &.{},
    encrypted_body: []u8 = &.{},
    preloaded_plain: [ssh_preload_max]u8 = .{0} ** ssh_preload_max,
    preloaded_plain_pos: usize = 0,
    preloaded_plain_len: usize = 0,
    console_output: [r4os.abi.console_output_capacity + 1]u8 = .{0} ** (r4os.abi.console_output_capacity + 1),
    sftp_recipient_channel: u32 = 0,
    sftp_input: []u8 = &.{},
    sftp_output: [sftp_output_capacity]u8 = .{0} ** sftp_output_capacity,
    sftp_upload: []u8 = &.{},
    // A direct diagnostic must finish its generation-bound inventory read
    // before it writes to TCPSVC: every synchronous service write creates
    // and retires an r4x-async-io task and therefore changes the task epoch.
    // Keep the complete bounded snapshot in session-owned heap scratch so
    // concurrent SSH sessions neither share storage nor grow their stacks.
    direct_task_inventory: [@as(usize, direct_diag_task_limit)]r4os.abi.ProgramTaskSnapshot = undefined,
};

const AuthAttempt = struct {
    user: []const u8 = "",
    service: []const u8 = "",
    method: []const u8 = "",
    password: []const u8 = "",
    change_request: bool = false,
};

const SftpHandleKind = enum(u8) {
    none,
    read_file,
    write_file,
    dir,
};

const ScpMode = enum(u8) {
    none,
    source,
    sink,
};

const ScpState = enum(u8) {
    none,
    source_wait_initial_ack,
    source_wait_header_ack,
    source_wait_final_ack,
    sink_wait_command,
    sink_read_data,
    sink_wait_final_ack,
    done,
};

const ChannelState = struct {
    open: bool = false,
    pty: bool = false,
    shell_started: bool = false,
    exec_started: bool = false,
    sftp_started: bool = false,
    scp_started: bool = false,
    client_eof: bool = false,
    close_sent: bool = false,
    client_channel: u32 = 0,
    server_channel: u32 = 0,
    shell_instance: u32 = 0,
    shell_skip_next_lf: bool = false,
    cols: u32 = 80,
    rows: u32 = 25,
    last_output_len: u32 = 0,
    last_clear_count: u32 = 0,
    last_console_revision: u32 = 0,
    last_console_stream_bytes: u32 = 0,
    last_output_dropped_bytes: u32 = 0,
    last_console_change_tick: u64 = 0,
    exec_output_observed: bool = false,
    last_exit_code: i32 = 0,
    keepalive_outstanding: bool = false,
    last_keepalive_tick: u64 = 0,
    channel_window_consumed: usize = 0,
    sftp_input_len: usize = 0,
    sftp_handle_kind: SftpHandleKind = .none,
    sftp_upload_len: usize = 0,
    sftp_write_offset: u64 = 0,
    sftp_file_size: u64 = 0,
    // Transiently covers the target/stage lookups and StreamBegin performed
    // by SFTP OPEN before a durable file handle or cleanup claim exists.
    sftp_open_pending: bool = false,
    sftp_stream_active: bool = false,
    // Finish succeeded and the kernel owns an exact create-only publication
    // token. A failed acknowledgement must retry publication, not Finish or
    // path-based cleanup.
    sftp_publish_pending: bool = false,
    sftp_write_failed: bool = false,
    sftp_cleanup_pending: bool = false,
    sftp_failure_rc: i32 = 0,
    sftp_abort_rc: i32 = 0,
    sftp_dir_index: u32 = 0,
    sftp_path: [sftp_path_capacity]u8 = .{0} ** sftp_path_capacity,
    // Write uploads are streamed into a connection-unique sibling and only
    // published to sftp_path by fileReplaceAtomic after a successful CLOSE.
    // A failed stream begin can therefore never truncate an existing target.
    sftp_staged_path: [sftp_path_capacity]u8 = .{0} ** sftp_path_capacity,
    sftp_backup_path: [sftp_path_capacity]u8 = .{0} ** sftp_path_capacity,
    scp_mode: ScpMode = .none,
    scp_state: ScpState = .none,
    scp_input_len: usize = 0,
    scp_expected_len: usize = 0,
    scp_received_len: usize = 0,
    scp_stream_active: bool = false,
    scp_cleanup_pending: bool = false,
    scp_failure_rc: i32 = 0,
    scp_abort_rc: i32 = 0,
    scp_target_is_dir: bool = false,
    scp_path: [sftp_path_capacity]u8 = .{0} ** sftp_path_capacity,
    // Sink uploads use the same create-only ownership transfer as SFTP:
    // bytes remain under a private 8.3 sibling until the complete payload has
    // been finished and atomically published.
    scp_staged_path: [sftp_path_capacity]u8 = .{0} ** sftp_path_capacity,
    scp_backup_path: [sftp_path_capacity]u8 = .{0} ** sftp_path_capacity,
    scp_name: [scp_filename_capacity]u8 = .{0} ** scp_filename_capacity,
    transfer_start_tick: u64 = 0,
    last_activity_tick: u64 = 0,
    eof_tick: u64 = 0,
    session_slot: ?*SessionWorkerSlot = null,
};

const KexSelection = struct {
    kex: []const u8 = "",
    host_key: []const u8 = "",
    cipher_c2s: []const u8 = "",
    cipher_s2c: []const u8 = "",
    compression_c2s: []const u8 = "",
    compression_s2c: []const u8 = "",
    first_kex_packet_follows: bool = false,
    first_kex_name: []const u8 = "",
};

const SessionRng = struct {
    state: [32]u8,
    counter: u64 = 0,

    fn init(app: *const App, host_seed: [32]u8, conn_id: u32, session_index: u32) SessionRng {
        var h = Sha256.init(.{});
        h.update("R4OS SSHD 0.52.8 session rng");
        h.update(&host_seed);
        hashU64(&h, app.sys.ticks());
        const time_state = app.sys.timeState();
        hashU64(&h, time_state.monotonic_ticks);
        hashU32(&h, time_state.seconds_since_midnight);
        hashU32(&h, conn_id);
        hashU32(&h, session_index);
        var seed: [32]u8 = undefined;
        h.final(&seed);
        if (allZero(seed[0..])) seed[0] = 1;
        return .{ .state = seed };
    }

    fn fill(self: *SessionRng, out: []u8) void {
        var offset: usize = 0;
        while (offset < out.len) {
            var h = Sha256.init(.{});
            h.update("R4OS SSHD rng block");
            h.update(&self.state);
            hashU64(&h, self.counter);
            var block: [32]u8 = undefined;
            h.final(&block);
            const n = @min(block.len, out.len - offset);
            @memcpy(out[offset .. offset + n], block[0..n]);
            offset += n;

            var h2 = Sha256.init(.{});
            h2.update("R4OS SSHD rng reseed");
            h2.update(&self.state);
            h2.update(&block);
            hashU64(&h2, self.counter);
            h2.final(&self.state);
            self.counter +%= 1;
        }
    }
};

pub fn r4_app_main(r4_app: *r4os.App) i32 {
    var app = App.init(r4_app) orelse return r4os.abi.err_no_group;
    if (hasArg(app.sys.argsRaw(), selftest_arg)) return runSelfTest(&app);
    if (hasArg(app.sys.argsRaw(), ping_arg)) return runPingClient(&app);
    if (hasArg(app.sys.argsRaw(), status_arg)) return runStatusClient(&app);
    return runService(&app);
}

fn runService(app: *const App) i32 {
    if (!app.sys.hasFn("service_call")) return r4os.abi.service_api_result_invalid;

    var stats = ServiceStats{};
    stats.registry_repairs = ensureRegistryDefaults(app);
    var config = loadConfig(app);
    if (!config.enabled) {
        app.sys.println("SSHD disabled by Registry");
        return 0;
    }
    var host_key = loadOrCreateHostKey(app, &stats) orelse {
        app.sys.println("SSHD host key unavailable");
        return -2;
    };
    if (!app.sys.hasFn("thread_create_handle") or !app.sys.hasFn("thread_handle_join")) {
        app.sys.println("SSHD requires R4X session worker threads");
        return r4os.abi.thread_error_unsupported;
    }
    var sessions = [_]SessionWorkerSlot{SessionWorkerSlot{}} ** session_worker_slots_max;

    var info: r4os.abi.ServiceInfo = .{};
    var endpoint_handle: u32 = 0;
    var waited: u32 = 0;
    while (waited < service_register_wait_ticks and endpoint_handle == 0) : (waited += 1) {
        const rc = app.sys.serviceEndpointRegister(service_name, 0, &info);
        if (rc == r4os.abi.service_api_result_ok and info.handle != 0) {
            endpoint_handle = info.handle;
            app.sys.write("SSHD endpoint handle=");
            app.sys.printU64(@intCast(endpoint_handle));
            app.sys.println("");
            break;
        }
        app.sys.sleepTicks(1);
    }
    if (endpoint_handle == 0) {
        app.sys.println("SSHD endpoint registration failed");
        return r4os.abi.service_api_result_no_endpoint;
    }

    if (!waitForListen(app, config.listen_port, &stats)) {
        _ = app.sys.serviceEndpointUnregister(endpoint_handle);
        app.sys.println("SSHD listen failed");
        return -1;
    }

    var next_accept_poll: u64 = 0;
    while (!app.sys.programShouldClose()) {
        const now = app.sys.ticks();
        const poll = app.sys.serviceEndpointPoll(endpoint_handle);
        if (poll < 0) {
            closeListener(app, config.listen_port);
            stopSessionWorkers(app, &stats, sessions[0..]);
            freeAllSessionScratch(app, &stats, sessions[0..]);
            _ = app.sys.serviceEndpointUnregister(endpoint_handle);
            return poll;
        }
        if (poll > 0) {
            const rc = handleRequest(app, endpoint_handle, &stats, &config, sessions[0..]);
            if (rc < 0) {
                closeListener(app, config.listen_port);
                stopSessionWorkers(app, &stats, sessions[0..]);
                freeAllSessionScratch(app, &stats, sessions[0..]);
                _ = app.sys.serviceEndpointUnregister(endpoint_handle);
                return rc;
            }
        }

        pollSessionWorkers(app, &stats, sessions[0..], false);
        prewarmSessionScratch(app, &stats, &config, sessions[0..]);
        if (now >= next_accept_poll) {
            if (pollClients(app, &stats, &config, &host_key, sessions[0..])) {
                next_accept_poll = now;
            } else {
                const idle_ticks = app.sys.ticksFromMilliseconds(accept_idle_poll_ms);
                next_accept_poll = now + if (idle_ticks == 0) 1 else idle_ticks;
            }
        }
        app.sys.sleepTicks(1);
    }

    closeListener(app, config.listen_port);
    stopSessionWorkers(app, &stats, sessions[0..]);
    freeAllSessionScratch(app, &stats, sessions[0..]);
    _ = app.sys.serviceEndpointUnregister(endpoint_handle);
    app.sys.println("SSHD stopped cleanly");
    return 0;
}

fn handleRequest(app: *const App, endpoint_handle: u32, stats: *ServiceStats, config: *const Config, sessions: ?[]const SessionWorkerSlot) i32 {
    var header: r4os.abi.ServiceMessageHeader = .{};
    var payload: [r4os.abi.service_api_max_payload]u8 = undefined;
    const got = app.sys.serviceEndpointRecv(endpoint_handle, &header, payload[0..]);
    if (got < 0) return got;
    if (got == 0 and header.magic != r4os.abi.service_api_magic) return 0;

    stats.requests +%= 1;
    return switch (header.op) {
        op_status => replyStatus(app, endpoint_handle, header.request_id, stats, config, sessions),
        op_ping => replyPing(app, endpoint_handle, header.request_id, stats),
        else => blk: {
            stats.bad_ops +%= 1;
            break :blk app.sys.serviceEndpointReply(endpoint_handle, header.request_id, r4os.abi.service_api_result_bad_op, "BADOP");
        },
    };
}

fn replyStatus(app: *const App, endpoint_handle: u32, request_id: u32, stats: *ServiceStats, config: *const Config, sessions: ?[]const SessionWorkerSlot) i32 {
    stats.status_requests +%= 1;
    const snapshot = stats.*;
    return replyStatusView(app, endpoint_handle, request_id, &snapshot, config, sessions);
}

fn replyStatusView(app: *const App, endpoint_handle: u32, request_id: u32, stats: *const ServiceStats, config: *const Config, sessions: ?[]const SessionWorkerSlot) i32 {
    var out: [r4os.abi.service_api_max_payload]u8 = .{0} ** r4os.abi.service_api_max_payload;
    var pos: usize = 0;
    appendText(out[0..], &pos, "SSHD OK port=");
    appendU64(out[0..], &pos, @intCast(config.listen_port));
    appendText(out[0..], &pos, " sessions=");
    appendU64(out[0..], &pos, @intCast(config.max_sessions));
    appendText(out[0..], &pos, " active=");
    appendU64(out[0..], &pos, @intCast(stats.active_sessions));
    appendText(out[0..], &pos, " workers=");
    appendU64(out[0..], &pos, @intCast(stats.active_sessions));
    appendText(out[0..], &pos, "/");
    appendU64(out[0..], &pos, @intCast(session_worker_slots_max));
    appendText(out[0..], &pos, " worker_started=");
    appendU64(out[0..], &pos, @intCast(stats.session_worker_started));
    appendText(out[0..], &pos, " worker_done=");
    appendU64(out[0..], &pos, @intCast(stats.session_worker_completed));
    appendText(out[0..], &pos, " worker_joined=");
    appendU64(out[0..], &pos, @intCast(stats.session_worker_joined));
    appendText(out[0..], &pos, " worker_spawn_fail=");
    appendU64(out[0..], &pos, @intCast(stats.session_worker_create_failed));
    appendText(out[0..], &pos, " worker_join_err=");
    appendU64(out[0..], &pos, @intCast(stats.session_worker_join_errors));
    appendText(out[0..], &pos, " queued=");
    appendU64(out[0..], &pos, @intCast(stats.session_limit_waits));
    appendText(out[0..], &pos, " accept_poll=");
    appendU64(out[0..], &pos, @intCast(stats.accept_polls));
    appendText(out[0..], &pos, " accept_empty=");
    appendU64(out[0..], &pos, @intCast(stats.accept_empty));
    appendText(out[0..], &pos, " accept_ok=");
    appendU64(out[0..], &pos, @intCast(stats.accept_ok));
    appendText(out[0..], &pos, " accept_err=");
    appendU64(out[0..], &pos, @intCast(stats.accept_errors));
    appendText(out[0..], &pos, " accept_flags=");
    appendU64(out[0..], &pos, @intCast(stats.last_accept_flags));
    appendText(out[0..], &pos, " accept_handle=");
    appendU64(out[0..], &pos, @intCast(stats.last_accept_handle));
    appendText(out[0..], &pos, " slow=");
    appendU64(out[0..], &pos, @intCast(stats.session_slow_clients));
    appendText(out[0..], &pos, " scratch=");
    appendU64(out[0..], &pos, @intCast(stats.session_scratch_ready));
    appendText(out[0..], &pos, "/");
    appendU64(out[0..], &pos, @intCast(stats.session_scratch_in_use));
    appendText(out[0..], &pos, " scratch_alloc=");
    appendU64(out[0..], &pos, @intCast(stats.session_scratch_allocated));
    appendText(out[0..], &pos, " scratch_fail=");
    appendU64(out[0..], &pos, @intCast(stats.session_scratch_failures));
    appendText(out[0..], &pos, " last_worker=");
    appendU64(out[0..], &pos, @intCast(stats.last_worker_id));
    appendText(out[0..], &pos, " last_thread=");
    appendU64(out[0..], &pos, @intCast(stats.last_worker_thread));
    appendText(out[0..], &pos, " last_exit=");
    appendI32(out[0..], &pos, stats.last_worker_exit);
    appendText(out[0..], &pos, " last_ticks=");
    appendU64(out[0..], &pos, stats.last_session_ticks);
    appendText(out[0..], &pos, " max_ticks=");
    appendU64(out[0..], &pos, stats.max_session_ticks);
    appendText(out[0..], &pos, " accepted=");
    appendU64(out[0..], &pos, @intCast(stats.accepted));
    appendText(out[0..], &pos, " banners=");
    appendU64(out[0..], &pos, @intCast(stats.banners_sent));
    appendText(out[0..], &pos, " newkeys=");
    appendU64(out[0..], &pos, @intCast(stats.newkeys));
    appendText(out[0..], &pos, " service_req=");
    appendU64(out[0..], &pos, @intCast(stats.encrypted_service_requests));
    appendText(out[0..], &pos, " auth_ok=");
    appendU64(out[0..], &pos, @intCast(stats.auth_successes));
    appendText(out[0..], &pos, " auth_fail=");
    appendU64(out[0..], &pos, @intCast(stats.auth_failures));
    appendText(out[0..], &pos, " channels=");
    appendU64(out[0..], &pos, @intCast(stats.channel_opens));
    appendText(out[0..], &pos, " shells=");
    appendU64(out[0..], &pos, @intCast(stats.shell_sessions));
    appendText(out[0..], &pos, " execs=");
    appendU64(out[0..], &pos, @intCast(stats.exec_sessions));
    appendText(out[0..], &pos, " sftp=");
    appendU64(out[0..], &pos, @intCast(stats.sftp_sessions));
    appendText(out[0..], &pos, " sftp_open=");
    appendU64(out[0..], &pos, @intCast(stats.sftp_opens));
    appendText(out[0..], &pos, " sftp_read=");
    appendU64(out[0..], &pos, @intCast(stats.sftp_reads));
    appendText(out[0..], &pos, " sftp_write=");
    appendU64(out[0..], &pos, @intCast(stats.sftp_writes));
    appendText(out[0..], &pos, " sftp_ls=");
    appendU64(out[0..], &pos, @intCast(stats.sftp_readdirs));
    appendText(out[0..], &pos, " sftp_rm=");
    appendU64(out[0..], &pos, @intCast(stats.sftp_removes));
    appendText(out[0..], &pos, " sftp_rename=");
    appendU64(out[0..], &pos, @intCast(stats.sftp_renames));
    appendText(out[0..], &pos, " sftp_in=");
    appendU64(out[0..], &pos, @intCast(stats.sftp_bytes_in));
    appendText(out[0..], &pos, " sftp_out=");
    appendU64(out[0..], &pos, @intCast(stats.sftp_bytes_out));
    appendText(out[0..], &pos, " scp=");
    appendU64(out[0..], &pos, @intCast(stats.scp_sessions));
    appendText(out[0..], &pos, " scp_read=");
    appendU64(out[0..], &pos, @intCast(stats.scp_reads));
    appendText(out[0..], &pos, " scp_write=");
    appendU64(out[0..], &pos, @intCast(stats.scp_writes));
    appendText(out[0..], &pos, " scp_in=");
    appendU64(out[0..], &pos, @intCast(stats.scp_bytes_in));
    appendText(out[0..], &pos, " scp_out=");
    appendU64(out[0..], &pos, @intCast(stats.scp_bytes_out));
    appendText(out[0..], &pos, " xfer_abort=");
    appendU64(out[0..], &pos, @intCast(stats.transfer_aborts));
    appendText(out[0..], &pos, " xfer_fail=");
    appendU64(out[0..], &pos, @intCast(stats.transfer_failures));
    appendText(out[0..], &pos, " xfer_seq=");
    appendU64(out[0..], &pos, stats.last_transfer_sequence);
    appendText(out[0..], &pos, " xfer_bytes=");
    appendU64(out[0..], &pos, stats.last_transfer_bytes);
    appendText(out[0..], &pos, " xfer_ticks=");
    appendU64(out[0..], &pos, stats.last_transfer_ticks);
    appendText(out[0..], &pos, " xfer_rc=");
    appendI32(out[0..], &pos, stats.last_transfer_rc);
    appendText(out[0..], &pos, " xfer_abort_rc=");
    appendI32(out[0..], &pos, stats.last_transfer_abort_rc);
    if (spanZ(stats.last_transfer_kind[0..]).len != 0) {
        appendText(out[0..], &pos, " xfer_kind=");
        appendText(out[0..], &pos, spanZ(stats.last_transfer_kind[0..]));
    }
    if (spanZ(stats.last_transfer_result[0..]).len != 0) {
        appendText(out[0..], &pos, " xfer_result=");
        appendText(out[0..], &pos, spanZ(stats.last_transfer_result[0..]));
    }
    if (spanZ(stats.last_transfer_path[0..]).len != 0) {
        appendText(out[0..], &pos, " xfer_path=");
        appendText(out[0..], &pos, spanZ(stats.last_transfer_path[0..]));
    }
    appendText(out[0..], &pos, " write_xfer_seq=");
    appendU64(out[0..], &pos, stats.last_sftp_write_sequence);
    appendText(out[0..], &pos, " write_xfer_bytes=");
    appendU64(out[0..], &pos, stats.last_sftp_write_bytes);
    appendText(out[0..], &pos, " write_xfer_ticks=");
    appendU64(out[0..], &pos, stats.last_sftp_write_ticks);
    appendText(out[0..], &pos, " write_xfer_rc=");
    appendI32(out[0..], &pos, stats.last_sftp_write_rc);
    appendText(out[0..], &pos, " write_xfer_abort_rc=");
    appendI32(out[0..], &pos, stats.last_sftp_write_abort_rc);
    if (spanZ(stats.last_sftp_write_result[0..]).len != 0) {
        appendText(out[0..], &pos, " write_xfer_result=");
        appendText(out[0..], &pos, spanZ(stats.last_sftp_write_result[0..]));
    }
    if (spanZ(stats.last_sftp_write_path[0..]).len != 0) {
        appendText(out[0..], &pos, " write_xfer_path=");
        appendText(out[0..], &pos, spanZ(stats.last_sftp_write_path[0..]));
    }
    appendText(out[0..], &pos, " winadj=");
    appendU64(out[0..], &pos, @intCast(stats.channel_window_adjusts));
    appendText(out[0..], &pos, " chan_win=");
    appendU64(out[0..], &pos, ssh_channel_window);
    appendText(out[0..], &pos, " chan_pkt=");
    appendU64(out[0..], &pos, ssh_channel_packet_max);
    appendText(out[0..], &pos, " chan_thr=");
    appendU64(out[0..], &pos, @intCast(ssh_channel_window_adjust_threshold));
    appendText(out[0..], &pos, " sftp_buf=");
    appendU64(out[0..], &pos, @intCast(sftp_output_capacity));
    appendText(out[0..], &pos, " write_max=");
    appendU64(out[0..], &pos, @intCast(sftp_write_data_max));
    appendText(out[0..], &pos, " stream_chunk=");
    appendU64(out[0..], &pos, @intCast(transfer_stream_chunk_max));
    appendText(out[0..], &pos, " in=");
    appendU64(out[0..], &pos, @intCast(stats.channel_data_in));
    appendText(out[0..], &pos, " out=");
    appendU64(out[0..], &pos, @intCast(stats.channel_data_out));
    appendText(out[0..], &pos, " eof=");
    appendU64(out[0..], &pos, @intCast(stats.channel_client_eofs));
    appendText(out[0..], &pos, " client_close=");
    appendU64(out[0..], &pos, @intCast(stats.channel_client_closes));
    appendText(out[0..], &pos, " client_abort=");
    appendU64(out[0..], &pos, @intCast(stats.client_aborts));
    appendText(out[0..], &pos, " idle_timeout=");
    appendU64(out[0..], &pos, @intCast(stats.channel_idle_timeouts));
    appendText(out[0..], &pos, " keepalive=");
    appendU64(out[0..], &pos, @intCast(stats.channel_keepalives_sent));
    appendText(out[0..], &pos, "/");
    appendU64(out[0..], &pos, @intCast(stats.channel_keepalive_replies));
    appendText(out[0..], &pos, "/");
    appendU64(out[0..], &pos, @intCast(stats.channel_keepalive_timeouts));
    appendText(out[0..], &pos, " out_fail=");
    appendU64(out[0..], &pos, @intCast(stats.channel_output_failures));
    appendText(out[0..], &pos, " console=");
    appendI32(out[0..], &pos, stats.last_console_state_rc);
    appendText(out[0..], &pos, "/");
    appendU64(out[0..], &pos, @intCast(stats.last_console_state_len));
    appendText(out[0..], &pos, "/");
    appendU64(out[0..], &pos, @intCast(stats.last_console_read_len));
    appendText(out[0..], &pos, "/");
    appendU64(out[0..], &pos, @intCast(stats.last_console_send_len));
    appendText(out[0..], &pos, "/");
    appendU64(out[0..], &pos, @intCast(stats.last_console_stream_bytes));
    appendText(out[0..], &pos, " read_retry=");
    appendU64(out[0..], &pos, @intCast(stats.tcp_read_transients));
    appendText(out[0..], &pos, " write_retry=");
    appendU64(out[0..], &pos, @intCast(stats.tcp_write_transients));
    appendText(out[0..], &pos, " svc_retry=");
    appendU64(out[0..], &pos, @intCast(stats.tcp_service_transients));
    appendText(out[0..], &pos, " wr_seq_skip=");
    appendU64(out[0..], &pos, @intCast(stats.tcp_write_seq_skips));
    appendText(out[0..], &pos, " tcp=");
    appendI32(out[0..], &pos, stats.last_tcp_result);
    appendText(out[0..], &pos, "/");
    appendU64(out[0..], &pos, @intCast(stats.last_tcp_service_status));
    appendText(out[0..], &pos, "/");
    appendU64(out[0..], &pos, @intCast(stats.last_tcp_flags));
    appendText(out[0..], &pos, "/");
    appendU64(out[0..], &pos, @intCast(stats.last_tcp_tx_window));
    appendText(out[0..], &pos, " last_remote_exit=");
    appendI32(out[0..], &pos, stats.last_channel_exit);
    if (spanZ(stats.last_session_kind[0..]).len != 0) {
        appendText(out[0..], &pos, " last_kind=");
        appendText(out[0..], &pos, spanZ(stats.last_session_kind[0..]));
    }
    if (spanZ(stats.last_close_reason[0..]).len != 0) {
        appendText(out[0..], &pos, " close=");
        appendText(out[0..], &pos, spanZ(stats.last_close_reason[0..]));
    }
    if (spanZ(stats.last_exec_command[0..]).len != 0) {
        appendText(out[0..], &pos, " cmd=");
        appendText(out[0..], &pos, spanZ(stats.last_exec_command[0..]));
    }
    if (spanZ(stats.last_read_stage[0..]).len != 0) {
        appendText(out[0..], &pos, " pkt=");
        appendU64(out[0..], &pos, @intCast(stats.last_packet_len));
        appendText(out[0..], &pos, " pay=");
        appendU64(out[0..], &pos, @intCast(stats.last_payload_len));
        appendText(out[0..], &pos, " read=");
        appendU64(out[0..], &pos, @intCast(stats.last_read_got));
        appendText(out[0..], &pos, "/");
        appendU64(out[0..], &pos, @intCast(stats.last_read_want));
        appendText(out[0..], &pos, " stage=");
        appendText(out[0..], &pos, spanZ(stats.last_read_stage[0..]));
    }
    if (spanZ(stats.last_fail_read_stage[0..]).len != 0) {
        appendText(out[0..], &pos, " fail=");
        appendText(out[0..], &pos, spanZ(stats.last_fail_read_stage[0..]));
        appendText(out[0..], &pos, " fail_read=");
        appendU64(out[0..], &pos, @intCast(stats.last_fail_read_got));
        appendText(out[0..], &pos, "/");
        appendU64(out[0..], &pos, @intCast(stats.last_fail_read_want));
        appendText(out[0..], &pos, " fail_pkt=");
        appendU64(out[0..], &pos, @intCast(stats.last_fail_packet_len));
        appendText(out[0..], &pos, " fail_pay=");
        appendU64(out[0..], &pos, @intCast(stats.last_fail_payload_len));
        appendText(out[0..], &pos, " tcp_pending=");
        appendU64(out[0..], &pos, @intCast(stats.last_tcp_pending_rx));
        appendText(out[0..], &pos, " tcp_win=");
        appendU64(out[0..], &pos, @intCast(stats.last_tcp_rx_window));
        appendText(out[0..], &pos, " tcp_txwin=");
        appendU64(out[0..], &pos, @intCast(stats.last_tcp_tx_window));
        appendText(out[0..], &pos, " tcp_retrans=");
        appendU64(out[0..], &pos, @intCast(stats.last_tcp_retransmits));
        appendText(out[0..], &pos, " tcp_drop=");
        appendU64(out[0..], &pos, @intCast(stats.last_tcp_rx_drops));
        appendText(out[0..], &pos, " tcp_flags=");
        appendU64(out[0..], &pos, @intCast(stats.last_tcp_flags));
        appendText(out[0..], &pos, " tcp_status=");
        appendU64(out[0..], &pos, @intCast(stats.last_tcp_service_status));
        appendText(out[0..], &pos, " tcp_result=");
        appendI32(out[0..], &pos, stats.last_tcp_result);
    }
    appendText(out[0..], &pos, " hostkey=");
    appendText(out[0..], &pos, if (stats.host_key_generated != 0) "generated" else "loaded");
    appendText(out[0..], &pos, " user=");
    appendText(out[0..], &pos, spanZ(config.user_name[0..]));
    if (spanZ(stats.last_auth_user[0..]).len != 0) {
        appendText(out[0..], &pos, " last_auth_user=");
        appendText(out[0..], &pos, spanZ(stats.last_auth_user[0..]));
        appendText(out[0..], &pos, " method=");
        appendText(out[0..], &pos, spanZ(stats.last_auth_method[0..]));
    }
    if (config.log_passwords and spanZ(stats.last_auth_password[0..]).len != 0) {
        appendText(out[0..], &pos, " last_password=");
        appendText(out[0..], &pos, spanZ(stats.last_auth_password[0..]));
    }
    if (spanZ(stats.last_failed_auth_user[0..]).len != 0) {
        appendText(out[0..], &pos, " last_failed_user=");
        appendText(out[0..], &pos, spanZ(stats.last_failed_auth_user[0..]));
        appendText(out[0..], &pos, " failed_method=");
        appendText(out[0..], &pos, spanZ(stats.last_failed_auth_method[0..]));
    }
    if (config.log_passwords and spanZ(stats.last_failed_auth_password[0..]).len != 0) {
        appendText(out[0..], &pos, " failed_password=");
        appendText(out[0..], &pos, spanZ(stats.last_failed_auth_password[0..]));
    }
    if (spanZ(stats.last_protocol_error[0..]).len != 0) {
        appendText(out[0..], &pos, " last=");
        appendText(out[0..], &pos, spanZ(stats.last_protocol_error[0..]));
    }
    appendText(out[0..], &pos, " cpoll=");
    appendU64(out[0..], &pos, @intCast(stats.chan_poll_pending));
    appendText(out[0..], &pos, "/");
    appendU64(out[0..], &pos, @intCast(stats.chan_poll_transient));
    appendText(out[0..], &pos, "/");
    appendU64(out[0..], &pos, @intCast(stats.chan_poll_idle));
    // 0.56.34b-Diagnose: Live-Zustand der AKTIVEN Worker-Slots (Zombie-Jagd
    // nach Fingerprint-Reject). Merged-Stats zeigen nur gejointe Worker;
    // haengt ein Worker, sieht man hier Alter, letzte Read-Stage und
    // letzten Protokollfehler seines Slots.
    if (sessions) |slots| {
        const now = app.sys.ticks();
        var i: usize = 0;
        while (i < slots.len) : (i += 1) {
            const slot = &slots[i];
            if (!slot.used) continue;
            appendText(out[0..], &pos, " act[");
            appendU64(out[0..], &pos, @intCast(slot.session_id));
            appendText(out[0..], &pos, "]=conn:");
            appendU64(out[0..], &pos, @intCast(slot.conn_id));
            appendText(out[0..], &pos, ",age:");
            appendU64(out[0..], &pos, now -% slot.started_tick);
            const last_activity = @atomicLoad(u64, &slot.last_activity_tick, .acquire);
            appendText(out[0..], &pos, ",idle:");
            appendU64(out[0..], &pos, now -| last_activity);
            appendText(out[0..], &pos, ",transfer:");
            appendU64(out[0..], &pos, @atomicLoad(u32, &slot.transfer_active, .acquire));
            appendText(out[0..], &pos, ",watchdog:");
            appendU64(out[0..], &pos, @atomicLoad(u32, &slot.watchdog_abort_sent, .acquire));
        }
    }
    return app.sys.serviceEndpointReply(endpoint_handle, request_id, r4os.abi.service_api_result_ok, out[0..pos]);
}

fn replyPing(app: *const App, endpoint_handle: u32, request_id: u32, stats: *ServiceStats) i32 {
    stats.pings +%= 1;
    return app.sys.serviceEndpointReply(endpoint_handle, request_id, r4os.abi.service_api_result_ok, "SSHD PONG");
}

fn pollClients(app: *const App, stats: *ServiceStats, config: *const Config, host_key: *const HostKey, sessions: []SessionWorkerSlot) bool {
    var accepted: usize = 0;
    var accepted_any = false;
    while (accepted < accept_burst_max) : (accepted += 1) {
        if (!pollClient(app, stats, config, host_key, sessions)) break;
        accepted_any = true;
    }
    return accepted_any;
}

fn pollClient(app: *const App, stats: *ServiceStats, config: *const Config, host_key: *const HostKey, sessions: []SessionWorkerSlot) bool {
    if (stats.active_sessions >= sessionLimit(config)) {
        stats.session_limit_waits +%= 1;
        return false;
    }

    const slot = freeSessionSlotWithScratch(sessions) orelse freeSessionSlot(sessions) orelse {
        stats.session_limit_waits +%= 1;
        return false;
    };

    var accept: r4os.abi.TcpAcceptResult = .{};
    var structured: r4os.abi.NetServiceTcpResult = .{};
    stats.accept_polls +%= 1;
    const rc = tcpAcceptPollServiceResultWaitLocked(app, config.listen_port, &accept, &structured, tcpAcceptServiceWaitTicks(app));
    stats.last_tcp_result = if (rc == 0) structured.result else rc;
    stats.last_accept_flags = structured.flags;
    if (structured.handle != 0) stats.last_accept_handle = structured.handle;
    if (rc == 0) {
        stats.accept_empty +%= 1;
        return false;
    }
    if (rc < 0) {
        stats.tcp_errors +%= 1;
        stats.accept_errors +%= 1;
        stats.last_tcp_result = rc;
        return false;
    }
    if (accept.conn_id == 0 or structured.result != r4os.abi.tcp_result_ok) {
        stats.tcp_errors +%= 1;
        stats.accept_errors +%= 1;
        stats.last_tcp_result = structured.result;
        closeTcpSession(app, accept.conn_id);
        return true;
    }
    if (!ensureSessionScratch(app, stats, slot)) {
        closeTcpSession(app, accept.conn_id);
        return true;
    }

    stats.accepted +%= 1;
    stats.accept_ok +%= 1;
    stats.active_sessions +%= 1;
    stats.last_tcp_result = structured.result;
    const session_id = stats.accepted;
    const buffers = slot.buffers;
    slot.* = .{
        .used = true,
        .session_id = session_id,
        .conn_id = accept.conn_id,
        .started_tick = app.sys.ticks(),
        .last_activity_tick = app.sys.ticks(),
        .app = app,
        .config = config.*,
        .host_key = host_key.*,
        .buffers = buffers,
    };
    markSessionScratchInUse(stats, slot);
    slot.stats.accepted = session_id;
    app.sys.write("SSHD client accepted conn=");
    app.sys.printU64(@intCast(accept.conn_id));
    app.sys.println("");

    if (!sendSshBanner(app, accept.conn_id, stats)) {
        stats.active_sessions -|= 1;
        releaseSessionScratchToReady(stats, slot);
        resetSessionSlotForReuse(slot);
        closeTcpSession(app, accept.conn_id);
        return true;
    }
    slot.banner_sent = true;

    var thread_handle: r4os.abi.ProgramJoinHandle = .{};
    const spawn_rc = app.sys.threadCreateHandle(sshSessionWorkerMain, @intFromPtr(slot), session_worker_stack_bytes, 0, &thread_handle);
    if (spawn_rc != r4os.abi.thread_ok) {
        stats.session_worker_create_failed +%= 1;
        stats.tcp_errors +%= 1;
        stats.active_sessions -|= 1;
        releaseSessionScratchToReady(stats, slot);
        resetSessionSlotForReuse(slot);
        closeTcpSession(app, accept.conn_id);
        return true;
    }
    slot.thread_handle = thread_handle;
    stats.session_worker_started +%= 1;
    stats.last_worker_id = session_id;
    stats.last_worker_thread = thread_handle.thread_id;
    app.sys.write("SSHD session worker=");
    app.sys.printU64(@intCast(session_id));
    app.sys.write(" thread=");
    app.sys.printU64(@intCast(thread_handle.thread_id));
    app.sys.println("");
    return true;
}

fn sshSessionWorkerMain(arg: u64) callconv(.c) i32 {
    const slot: *SessionWorkerSlot = @ptrFromInt(arg);
    const app = slot.app;
    const buffers = slot.buffers orelse {
        slot.stats.tcp_errors +%= 1;
        setLastProtocolError(&slot.stats, "scratch-missing");
        slot.exit_code = -20;
        slot.finished_tick = app.sys.ticks();
        closeTcpSession(app, slot.conn_id);
        return -20;
    };
    resetSessionBuffers(buffers);
    @atomicStore(u64, &slot.last_activity_tick, app.sys.ticks(), .release);
    @atomicStore(u32, &slot.transfer_active, 0, .release);
    @atomicStore(u32, &slot.watchdog_abort_sent, 0, .release);
    @atomicStore(i32, &slot.watchdog_abort_result, 0, .release);

    const session_rc = handleSshTransport(app, slot.conn_id, 0, &slot.stats, &slot.config, &slot.host_key, buffers, slot);
    if (session_rc == 0) slot.stats.transport_sessions +%= 1;
    app.sys.sleepTicks(client_flush_ticks);

    finishTcpSession(app, slot, sessionNeedsTcpAbort(&slot.stats, session_rc));
    if (!slot.close_ok) {
        slot.stats.session_close_errors +%= 1;
        slot.stats.tcp_errors +%= 1;
    }
    slot.exit_code = session_rc;
    slot.finished_tick = app.sys.ticks();
    return session_rc;
}

fn prewarmSessionScratch(app: *const App, stats: *ServiceStats, config: *const Config, sessions: []SessionWorkerSlot) void {
    const prewarm_target = @min(sessionLimit(config), session_scratch_prewarm_max);
    if (stats.session_scratch_ready + stats.session_scratch_in_use >= prewarm_target) return;
    const slot = freeSessionSlotWithoutScratch(sessions) orelse return;
    _ = allocateSessionScratch(app, stats, slot, false);
}

fn ensureSessionScratch(app: *const App, stats: *ServiceStats, slot: *SessionWorkerSlot) bool {
    if (slot.buffers != null) return true;
    return allocateSessionScratch(app, stats, slot, true);
}

fn allocateSessionScratch(app: *const App, stats: *ServiceStats, slot: *SessionWorkerSlot, report_client_failure: bool) bool {
    if (slot.buffers != null) return true;
    const buffers = allocateSessionBuffers(app) orelse {
        stats.session_scratch_failures +%= 1;
        if (report_client_failure) {
            stats.tcp_errors +%= 1;
            setLastProtocolError(stats, "scratch");
        }
        return false;
    };
    slot.buffers = buffers;
    stats.session_scratch_allocated +%= 1;
    stats.session_scratch_ready +%= 1;
    return true;
}

fn allocateSessionBuffers(app: *const App) ?*SessionBuffers {
    return allocateSessionBuffersRaw(app) catch null;
}

fn allocateSessionBuffersRaw(app: *const App) !*SessionBuffers {
    const allocator = app.sys.allocator();
    const buffers = try allocator.create(SessionBuffers);
    buffers.* = .{};
    errdefer allocator.destroy(buffers);
    buffers.client_payload = try allocator.alignedAlloc(u8, .fromByteUnits(16), ssh_max_payload_len);
    errdefer allocator.free(buffers.client_payload);
    buffers.ecdh_payload = try allocator.alignedAlloc(u8, .fromByteUnits(16), ssh_max_payload_len);
    errdefer allocator.free(buffers.ecdh_payload);
    buffers.encrypted_payload = try allocator.alignedAlloc(u8, .fromByteUnits(16), ssh_max_payload_len);
    errdefer allocator.free(buffers.encrypted_payload);
    buffers.plain_packet = try allocator.alignedAlloc(u8, .fromByteUnits(16), ssh_max_packet_len + 32);
    errdefer allocator.free(buffers.plain_packet);
    buffers.encrypted_packet = try allocator.alignedAlloc(u8, .fromByteUnits(16), ssh_max_packet_len + 64);
    errdefer allocator.free(buffers.encrypted_packet);
    buffers.packet_body = try allocator.alignedAlloc(u8, .fromByteUnits(16), ssh_max_packet_len);
    errdefer allocator.free(buffers.packet_body);
    buffers.encrypted_body = try allocator.alignedAlloc(u8, .fromByteUnits(16), ssh_max_packet_len + 16);
    errdefer allocator.free(buffers.encrypted_body);
    buffers.sftp_input = try allocator.alignedAlloc(u8, .fromByteUnits(16), sftp_input_capacity);
    errdefer allocator.free(buffers.sftp_input);
    buffers.sftp_upload = try allocator.alignedAlloc(u8, .fromByteUnits(16), sftp_upload_capacity);

    @memset(buffers.client_payload, 0);
    @memset(buffers.ecdh_payload, 0);
    @memset(buffers.encrypted_payload, 0);
    @memset(buffers.plain_packet, 0);
    @memset(buffers.encrypted_packet, 0);
    @memset(buffers.packet_body, 0);
    @memset(buffers.encrypted_body, 0);
    @memset(buffers.sftp_input, 0);
    @memset(buffers.sftp_upload, 0);
    return buffers;
}

fn resetSessionBuffers(buffers: *SessionBuffers) void {
    @memset(buffers.server_kex_payload[0..], 0);
    @memset(buffers.client_payload, 0);
    @memset(buffers.ecdh_payload, 0);
    @memset(buffers.encrypted_payload, 0);
    @memset(buffers.plain_packet, 0);
    @memset(buffers.encrypted_packet, 0);
    @memset(buffers.packet_body, 0);
    @memset(buffers.encrypted_body, 0);
    @memset(buffers.preloaded_plain[0..], 0);
    buffers.preloaded_plain_pos = 0;
    buffers.preloaded_plain_len = 0;
    @memset(buffers.console_output[0..], 0);
    buffers.sftp_recipient_channel = 0;
    @memset(buffers.sftp_input, 0);
    @memset(buffers.sftp_output[0..], 0);
    @memset(buffers.sftp_upload, 0);
}

fn freeSessionBuffers(app: *const App, buffers: *SessionBuffers) void {
    const allocator = app.sys.allocator();
    allocator.free(buffers.sftp_upload);
    allocator.free(buffers.sftp_input);
    allocator.free(buffers.encrypted_body);
    allocator.free(buffers.packet_body);
    allocator.free(buffers.encrypted_packet);
    allocator.free(buffers.plain_packet);
    allocator.free(buffers.encrypted_payload);
    allocator.free(buffers.ecdh_payload);
    allocator.free(buffers.client_payload);
    allocator.destroy(buffers);
}

fn markSessionScratchInUse(stats: *ServiceStats, slot: *const SessionWorkerSlot) void {
    if (slot.buffers == null) return;
    stats.session_scratch_ready -|= 1;
    stats.session_scratch_in_use +%= 1;
}

fn releaseSessionScratchToReady(stats: *ServiceStats, slot: *const SessionWorkerSlot) void {
    if (slot.buffers == null) return;
    stats.session_scratch_in_use -|= 1;
    stats.session_scratch_ready +%= 1;
}

fn resetSessionSlotForReuse(slot: *SessionWorkerSlot) void {
    const buffers = slot.buffers;
    slot.* = .{};
    slot.buffers = buffers;
}

fn freeSessionScratch(app: *const App, stats: *ServiceStats, slot: *SessionWorkerSlot) void {
    const buffers = slot.buffers orelse return;
    freeSessionBuffers(app, buffers);
    slot.buffers = null;
    stats.session_scratch_ready -|= 1;
    stats.session_scratch_in_use -|= 1;
    stats.session_scratch_freed +%= 1;
}

fn freeAllSessionScratch(app: *const App, stats: *ServiceStats, sessions: []SessionWorkerSlot) void {
    var i: usize = 0;
    while (i < sessions.len) : (i += 1) {
        if (sessions[i].used) continue;
        freeSessionScratch(app, stats, &sessions[i]);
    }
}

fn pollSessionWorkers(app: *const App, stats: *ServiceStats, sessions: []SessionWorkerSlot, stopping: bool) void {
    const now = app.sys.ticks();
    const slow_ticks = app.sys.ticksFromMilliseconds(session_slow_warn_ms);
    const transfer_idle_ticks = app.sys.ticksFromMilliseconds(transfer_idle_timeout_ms);
    var i: usize = 0;
    while (i < sessions.len) : (i += 1) {
        var slot = &sessions[i];
        if (!slot.used) continue;
        if (!slot.slow_reported and slow_ticks != 0 and now -| slot.started_tick >= slow_ticks) {
            slot.slow_reported = true;
            stats.session_slow_clients +%= 1;
        }
        const transfer_watch_active = @atomicLoad(u32, &slot.transfer_active, .acquire) != 0;
        const last_activity = @atomicLoad(u64, &slot.last_activity_tick, .acquire);
        // 0.56.34b: -| gegen Unterlauf - slot.last_activity_tick schreibt der
        // Worker-Thread NEBENLAEUFIG; ein frischerer Wert als das hier
        // eingefrorene now liess den Watchdog sofort (falsch) abbrechen.
        if (transfer_watch_active and
            transfer_idle_ticks != 0 and
            now -| last_activity >= transfer_idle_ticks and
            @cmpxchgStrong(u32, &slot.watchdog_abort_sent, 0, 1, .acq_rel, .acquire) == null)
        {
            @atomicStore(u32, &slot.transfer_active, 0, .release);
            var abort_result: r4os.abi.NetServiceTcpResult = .{};
            const abort_rc = tcpAbortServiceResultWaitLocked(app, slot.conn_id, &abort_result, transferTcpServiceWaitTicks(app));
            const watchdog_result = if (abort_rc == 0) abort_result.result else abort_rc;
            @atomicStore(i32, &slot.watchdog_abort_result, watchdog_result, .release);
            // Publish completion only after the result. State 1 means the
            // abort call is still in progress; state 2 is a complete record.
            @atomicStore(u32, &slot.watchdog_abort_sent, 2, .release);
        }
        var exit_code: i32 = 0;
        const wait_ticks: u64 = if (stopping) session_stop_join_ticks else 0;
        const join_rc = app.sys.threadHandleJoin(&slot.thread_handle, wait_ticks, &exit_code);
        // Join cleanup can be transiently busy while an async stream worker,
        // filesystem lease, stack, or task-retire anchor is still draining.
        // The generation-safe handle remains valid and must be retried.
        if (join_rc == r4os.abi.thread_error_timeout or
            join_rc == r4os.abi.thread_error_busy)
            continue;
        if (join_rc != r4os.abi.thread_ok) {
            stats.session_worker_join_errors +%= 1;
            stats.active_sessions -|= 1;
            freeSessionScratch(app, stats, slot);
            slot.* = .{};
            continue;
        }
        slot.exit_code = exit_code;
        finishSessionWorker(app, stats, slot);
    }
}

fn stopSessionWorkers(app: *const App, stats: *ServiceStats, sessions: []SessionWorkerSlot) void {
    var i: usize = 0;
    while (i < sessions.len) : (i += 1) {
        if (sessions[i].used and sessions[i].conn_id != 0) _ = tcpAbortServiceWaitLocked(app, sessions[i].conn_id, tcpServiceCleanupWaitTicks(app));
    }
    var waited: u32 = 0;
    while (waited < 8 and stats.active_sessions != 0) : (waited += 1) {
        pollSessionWorkers(app, stats, sessions, true);
        app.sys.sleepTicks(1);
    }
}

fn finishTcpSession(app: *const App, slot: *SessionWorkerSlot, force_abort: bool) void {
    if (!force_abort) {
        var close_result: r4os.abi.NetServiceTcpResult = .{};
        const close_rc = tcpCloseServiceResultWaitLocked(app, slot.conn_id, &close_result, tcpServiceCleanupWaitTicks(app));
        slot.close_result = if (close_rc == 0) close_result.result else close_rc;
        slot.close_ok = close_rc == 0 and close_result.result == r4os.abi.tcp_result_ok;
        if (slot.close_ok) return;
    }

    var abort_result: r4os.abi.NetServiceTcpResult = .{};
    const abort_rc = tcpAbortServiceResultWaitLocked(app, slot.conn_id, &abort_result, tcpServiceCleanupWaitTicks(app));
    slot.close_result = if (abort_rc == 0) abort_result.result else abort_rc;
    slot.close_ok = abort_rc == 0 and (abort_result.result == r4os.abi.tcp_result_ok or abort_result.result == r4os.abi.tcp_result_no_connection);
}

fn finishSessionWorker(app: *const App, stats: *ServiceStats, slot: *SessionWorkerSlot) void {
    const end_tick = if (slot.finished_tick != 0) slot.finished_tick else app.sys.ticks();
    const elapsed = if (end_tick >= slot.started_tick) end_tick - slot.started_tick else 0;
    // The worker has joined and the parent-side abort publication is complete;
    // it is now safe for the parent to update this slot's ordinary statistics.
    if (@atomicLoad(u32, &slot.watchdog_abort_sent, .acquire) == 2) {
        slot.stats.transfer_aborts +%= 1;
        slot.stats.channel_idle_timeouts +%= 1;
        noteCloseReason(&slot.stats, "watchdog-transfer-idle");
        setLastProtocolError(&slot.stats, "watchdog-transfer-idle");
        const watchdog_rc = @atomicLoad(i32, &slot.watchdog_abort_result, .acquire);
        if (watchdog_rc != r4os.abi.tcp_result_ok and watchdog_rc != r4os.abi.tcp_result_no_connection) {
            slot.stats.tcp_errors +%= 1;
            slot.stats.last_tcp_result = watchdog_rc;
        }
    }
    mergeSessionStats(stats, &slot.stats);
    stats.session_worker_completed +%= 1;
    stats.session_worker_joined +%= 1;
    stats.active_sessions -|= 1;
    stats.last_worker_id = slot.session_id;
    stats.last_worker_thread = slot.thread_handle.thread_id;
    stats.last_worker_exit = slot.exit_code;
    stats.last_session_ticks = elapsed;
    if (elapsed > stats.max_session_ticks) stats.max_session_ticks = elapsed;
    releaseSessionScratchToReady(stats, slot);
    app.sys.write("SSHD session done worker=");
    app.sys.printU64(@intCast(slot.session_id));
    app.sys.write(" thread=");
    app.sys.printU64(@intCast(slot.thread_handle.thread_id));
    app.sys.write(" exit=");
    app.sys.printI32(slot.exit_code);
    app.sys.write(" ticks=");
    app.sys.printU64(elapsed);
    app.sys.println("");
    resetSessionSlotForReuse(slot);
}

fn freeSessionSlot(sessions: []SessionWorkerSlot) ?*SessionWorkerSlot {
    var i: usize = 0;
    while (i < sessions.len) : (i += 1) {
        if (!sessions[i].used) return &sessions[i];
    }
    return null;
}

fn freeSessionSlotWithScratch(sessions: []SessionWorkerSlot) ?*SessionWorkerSlot {
    var i: usize = 0;
    while (i < sessions.len) : (i += 1) {
        if (!sessions[i].used and sessions[i].buffers != null) return &sessions[i];
    }
    return null;
}

fn freeSessionSlotWithoutScratch(sessions: []SessionWorkerSlot) ?*SessionWorkerSlot {
    var i: usize = 0;
    while (i < sessions.len) : (i += 1) {
        if (!sessions[i].used and sessions[i].buffers == null) return &sessions[i];
    }
    return null;
}

fn sessionLimit(config: *const Config) u32 {
    const cap: u32 = @intCast(session_worker_slots_max);
    if (config.max_sessions == 0) return 1;
    return @min(config.max_sessions, cap);
}

fn mergeSessionStats(out: *ServiceStats, session: *const ServiceStats) void {
    out.banners_sent +%= session.banners_sent;
    out.transport_sessions +%= session.transport_sessions;
    out.kexinit_seen +%= session.kexinit_seen;
    out.newkeys +%= session.newkeys;
    out.encrypted_service_requests +%= session.encrypted_service_requests;
    out.encrypted_auth_requests +%= session.encrypted_auth_requests;
    out.auth_failures +%= session.auth_failures;
    out.auth_successes +%= session.auth_successes;
    out.channel_opens +%= session.channel_opens;
    out.shell_sessions +%= session.shell_sessions;
    out.exec_sessions +%= session.exec_sessions;
    out.sftp_sessions +%= session.sftp_sessions;
    out.sftp_opens +%= session.sftp_opens;
    out.sftp_reads +%= session.sftp_reads;
    out.sftp_writes +%= session.sftp_writes;
    out.sftp_readdirs +%= session.sftp_readdirs;
    out.sftp_removes +%= session.sftp_removes;
    out.sftp_renames +%= session.sftp_renames;
    out.sftp_bytes_in +%= session.sftp_bytes_in;
    out.sftp_bytes_out +%= session.sftp_bytes_out;
    out.scp_sessions +%= session.scp_sessions;
    out.scp_reads +%= session.scp_reads;
    out.scp_writes +%= session.scp_writes;
    out.scp_bytes_in +%= session.scp_bytes_in;
    out.scp_bytes_out +%= session.scp_bytes_out;
    out.transfer_aborts +%= session.transfer_aborts;
    out.transfer_failures +%= session.transfer_failures;
    const mutable_session = @constCast(session);
    acquireTransferRecordLock(mutable_session);
    if (session.last_transfer_sequence > out.last_transfer_sequence) {
        out.last_transfer_sequence = session.last_transfer_sequence;
        out.last_transfer_bytes = session.last_transfer_bytes;
        out.last_transfer_ticks = session.last_transfer_ticks;
        out.last_transfer_rc = session.last_transfer_rc;
        out.last_transfer_abort_rc = session.last_transfer_abort_rc;
        copyFixedZ(out.last_transfer_kind[0..], spanZ(session.last_transfer_kind[0..]));
        copyFixedZ(out.last_transfer_result[0..], spanZ(session.last_transfer_result[0..]));
        copyFixedZ(out.last_transfer_path[0..], spanZ(session.last_transfer_path[0..]));
    }
    if (session.last_sftp_write_sequence > out.last_sftp_write_sequence) {
        out.last_sftp_write_sequence = session.last_sftp_write_sequence;
        out.last_sftp_write_bytes = session.last_sftp_write_bytes;
        out.last_sftp_write_ticks = session.last_sftp_write_ticks;
        out.last_sftp_write_rc = session.last_sftp_write_rc;
        out.last_sftp_write_abort_rc = session.last_sftp_write_abort_rc;
        copyFixedZ(out.last_sftp_write_result[0..], spanZ(session.last_sftp_write_result[0..]));
        copyFixedZ(out.last_sftp_write_path[0..], spanZ(session.last_sftp_write_path[0..]));
    }
    releaseTransferRecordLock(mutable_session);
    out.channel_window_adjusts +%= session.channel_window_adjusts;
    out.channel_data_in +%= session.channel_data_in;
    out.channel_data_out +%= session.channel_data_out;
    out.channel_client_closes +%= session.channel_client_closes;
    out.channel_client_eofs +%= session.channel_client_eofs;
    out.channel_idle_timeouts +%= session.channel_idle_timeouts;
    out.chan_poll_pending +%= session.chan_poll_pending;
    out.chan_poll_transient +%= session.chan_poll_transient;
    out.chan_poll_idle +%= session.chan_poll_idle;
    out.channel_keepalives_sent +%= session.channel_keepalives_sent;
    out.channel_keepalive_replies +%= session.channel_keepalive_replies;
    out.channel_keepalive_timeouts +%= session.channel_keepalive_timeouts;
    out.channel_output_failures +%= session.channel_output_failures;
    out.last_console_state_rc = session.last_console_state_rc;
    out.last_console_state_len = session.last_console_state_len;
    out.last_console_stream_bytes = session.last_console_stream_bytes;
    out.last_console_read_len = session.last_console_read_len;
    out.last_console_send_len = session.last_console_send_len;
    out.tcp_read_transients +%= session.tcp_read_transients;
    out.tcp_write_transients +%= session.tcp_write_transients;
    out.tcp_service_transients +%= session.tcp_service_transients;
    out.tcp_write_seq_skips +%= session.tcp_write_seq_skips;
    out.client_aborts +%= session.client_aborts;
    out.session_close_errors +%= session.session_close_errors;
    out.disconnects_sent +%= session.disconnects_sent;
    out.tcp_errors +%= session.tcp_errors;
    out.protocol_errors +%= session.protocol_errors;
    out.crypto_errors +%= session.crypto_errors;
    if (spanZ(session.last_close_reason[0..]).len != 0 or spanZ(session.last_session_kind[0..]).len != 0) {
        out.last_channel_exit = session.last_channel_exit;
    }
    copyLatestZ(out.last_close_reason[0..], session.last_close_reason[0..]);
    copyLatestZ(out.last_session_kind[0..], session.last_session_kind[0..]);
    copyLatestZ(out.last_exec_command[0..], session.last_exec_command[0..]);
    if (session.last_packet_len != 0) out.last_packet_len = session.last_packet_len;
    if (session.last_payload_len != 0) out.last_payload_len = session.last_payload_len;
    if (session.last_read_want != 0 or session.last_read_got != 0) {
        out.last_read_want = session.last_read_want;
        out.last_read_got = session.last_read_got;
    }
    copyLatestZ(out.last_read_stage[0..], session.last_read_stage[0..]);
    if (session.last_fail_packet_len != 0) out.last_fail_packet_len = session.last_fail_packet_len;
    if (session.last_fail_payload_len != 0) out.last_fail_payload_len = session.last_fail_payload_len;
    if (session.last_fail_read_want != 0 or session.last_fail_read_got != 0) {
        out.last_fail_read_want = session.last_fail_read_want;
        out.last_fail_read_got = session.last_fail_read_got;
    }
    copyLatestZ(out.last_fail_read_stage[0..], session.last_fail_read_stage[0..]);
    if (session.last_tcp_pending_rx != 0) out.last_tcp_pending_rx = session.last_tcp_pending_rx;
    if (session.last_tcp_rx_window != 0) out.last_tcp_rx_window = session.last_tcp_rx_window;
    if (session.last_tcp_tx_window != 0) out.last_tcp_tx_window = session.last_tcp_tx_window;
    if (session.last_tcp_retransmits != 0) out.last_tcp_retransmits = session.last_tcp_retransmits;
    if (session.last_tcp_rx_drops != 0) out.last_tcp_rx_drops = session.last_tcp_rx_drops;
    if (session.last_tcp_flags != 0) out.last_tcp_flags = session.last_tcp_flags;
    if (session.last_tcp_service_status != 0) out.last_tcp_service_status = session.last_tcp_service_status;
    if (session.last_tcp_result != 0) out.last_tcp_result = session.last_tcp_result;
    copyLatestZ(out.last_protocol_error[0..], session.last_protocol_error[0..]);
    copyLatestZ(out.last_auth_user[0..], session.last_auth_user[0..]);
    copyLatestZ(out.last_auth_method[0..], session.last_auth_method[0..]);
    copyLatestZ(out.last_auth_password[0..], session.last_auth_password[0..]);
    mergeLatestFailedAuth(out, session);
}

fn copyLatestZ(dest: []u8, src: []const u8) void {
    if (spanZ(src).len != 0) copyFixedZ(dest, spanZ(src));
}

fn mergeLatestFailedAuth(out: *ServiceStats, session: *const ServiceStats) void {
    const failed_user = spanZ(session.last_failed_auth_user[0..]);
    const failed_password = spanZ(session.last_failed_auth_password[0..]);
    if (failed_user.len == 0) return;
    if (failed_password.len == 0 and spanZ(out.last_failed_auth_password[0..]).len != 0) return;
    copyFixedZ(out.last_failed_auth_user[0..], failed_user);
    copyLatestZ(out.last_failed_auth_method[0..], session.last_failed_auth_method[0..]);
    copyLatestZ(out.last_failed_auth_password[0..], session.last_failed_auth_password[0..]);
}

fn waitForListen(app: *const App, port: u16, stats: *ServiceStats) bool {
    var waited: u32 = 0;
    while (waited < listen_wait_ticks) : (waited += 1) {
        var result: r4os.abi.NetServiceTcpResult = .{};
        const rc = tcpListenServiceResultWaitLocked(app, port, &result, tcpServiceWaitTicks(app));
        stats.last_tcp_result = if (rc == 0) result.result else rc;
        if (rc == 0 and result.result == 0) {
            app.sys.write("SSHD listen ");
            app.sys.printU64(@intCast(port));
            app.sys.println(": ready");
            return true;
        }
        if (waited == 0) {
            app.sys.write("SSHD waiting for TCPSVC/network on port ");
            app.sys.printU64(@intCast(port));
            app.sys.println("");
        }
        app.sys.sleepTicks(1);
    }
    stats.tcp_errors +%= 1;
    return false;
}

fn closeListener(app: *const App, port: u16) void {
    _ = tcpCloseListenServiceLocked(app, port);
}

fn tcpServiceWaitTicks(app: *const App) u64 {
    return app.sys.ticksFromMilliseconds(tcp_service_wait_ms);
}

fn transferTcpServiceWaitTicks(app: *const App) u64 {
    return app.sys.ticksFromMilliseconds(transfer_tcp_service_wait_ms);
}

fn tcpAcceptServiceWaitTicks(app: *const App) u64 {
    return app.sys.ticksFromMilliseconds(tcp_accept_service_wait_ms);
}

fn tcpFastServiceWaitTicks(app: *const App) u64 {
    return app.sys.ticksFromMilliseconds(tcp_fast_service_wait_ms);
}

fn channelReadServiceWaitTicks(app: *const App) u64 {
    return app.sys.ticksFromMilliseconds(channel_read_service_wait_ms);
}

fn tcpServiceCleanupWaitTicks(app: *const App) u64 {
    return app.sys.ticksFromMilliseconds(tcp_service_cleanup_wait_ms);
}

fn channelIdlePollSleepTicks(app: *const App) u64 {
    const ticks = app.sys.ticksFromMilliseconds(channel_idle_poll_sleep_ms);
    return if (ticks == 0) 1 else ticks;
}

fn tcpServiceCallWaitTicks(app: *const App, requested: u64) u64 {
    if (requested == 0) return 0;
    const cap = app.sys.ticksFromMilliseconds(tcp_service_call_wait_ms);
    return @min(requested, if (cap == 0) 1 else cap);
}

fn acquireTcpServiceLock(app: *const App) void {
    acquireAtomicLock(app, &tcp_service_lock);
}

fn releaseTcpServiceLock() void {
    releaseAtomicLock(&tcp_service_lock);
}

fn tcpAcceptPollServiceResultWaitLocked(app: *const App, port: u16, accept: *r4os.abi.TcpAcceptResult, result: *r4os.abi.NetServiceTcpResult, wait_ticks: u64) i32 {
    // 0.56.5: eigener Accept-Lock statt tcp_service_lock (siehe Deklaration).
    // Wait ohne tcpServiceCallWaitTicks-Cap: die Accept-Kadenz wird allein
    // ueber tcp_accept_service_wait_ms gesteuert (Begruendung dort).
    acquireAtomicLock(app, &tcp_accept_lock);
    defer releaseAtomicLock(&tcp_accept_lock);
    return app.net.tcpAcceptPollServiceResultWait(port, accept, result, wait_ticks);
}

fn tcpListenServiceResultWaitLocked(app: *const App, port: u16, result: *r4os.abi.NetServiceTcpResult, wait_ticks: u64) i32 {
    acquireTcpServiceLock(app);
    defer releaseTcpServiceLock();
    return app.net.tcpListenServiceResultWait(port, result, wait_ticks);
}

fn tcpCloseListenServiceLocked(app: *const App, port: u16) i32 {
    acquireTcpServiceLock(app);
    defer releaseTcpServiceLock();
    return app.net.tcpCloseListenService(port);
}

fn tcpCloseServiceResultWaitLocked(app: *const App, conn_id: u32, result: *r4os.abi.NetServiceTcpResult, wait_ticks: u64) i32 {
    acquireTcpServiceLock(app);
    defer releaseTcpServiceLock();
    return app.net.tcpCloseServiceResultWait(conn_id, result, wait_ticks);
}

fn tcpAbortServiceResultWaitLocked(app: *const App, conn_id: u32, result: *r4os.abi.NetServiceTcpResult, wait_ticks: u64) i32 {
    acquireTcpServiceLock(app);
    defer releaseTcpServiceLock();
    return app.net.tcpAbortServiceResultWait(conn_id, result, wait_ticks);
}

fn tcpAbortServiceWaitLocked(app: *const App, conn_id: u32, wait_ticks: u64) i32 {
    acquireTcpServiceLock(app);
    defer releaseTcpServiceLock();
    return app.net.tcpAbortServiceWait(conn_id, wait_ticks);
}

fn tcpRetransmitServiceResultWaitLocked(app: *const App, conn_id: u32, result: *r4os.abi.NetServiceTcpResult, wait_ticks: u64) i32 {
    acquireTcpServiceLock(app);
    defer releaseTcpServiceLock();
    return app.net.tcpRetransmitServiceResultWait(conn_id, result, wait_ticks);
}

fn tcpPollServiceWaitLocked(app: *const App, conn_id: u32, out: *r4os.abi.NetServiceTcpResult, wait_ticks: u64) i32 {
    acquireTcpServiceLock(app);
    defer releaseTcpServiceLock();
    return app.net.tcpPollServiceWait(conn_id, out, wait_ticks);
}

fn tcpReadWaitServiceConsumeSafeLocked(app: *const App, conn_id: u32, out: []u8, wait_ticks: u64, service_wait_ticks: u64) i32 {
    acquireTcpServiceLock(app);
    defer releaseTcpServiceLock();
    // 0.57.8: Consume-sicher (0.56.39-Klasse, wie FTPSVC): der Poll bleibt
    // auf dem Service-Budget (idempotent, Retry gefahrlos), aber der
    // daten-konsumierende Read darf NIE per Service-Timeout verfallen -
    // sonst sind die Bytes aus dem Kernel-RX gezogen und still verloren
    // (mutmassliche Ursache der ssh-exec-/cmdchannel-Leerausgaben-Flakes).
    return app.net.tcpReadWaitServiceConsumeSafe(conn_id, out, wait_ticks, tcpServiceCallWaitTicks(app, service_wait_ticks));
}

fn tcpWriteChunkServiceWaitLocked(app: *const App, conn_id: u32, data: []const u8, wait_ticks: u64) i32 {
    acquireTcpServiceLock(app);
    defer releaseTcpServiceLock();
    return app.net.tcpWriteChunkServiceWait(conn_id, data, tcpServiceCallWaitTicks(app, wait_ticks));
}

fn closeTcpSession(app: *const App, conn_id: u32) void {
    if (conn_id == 0) return;
    var result: r4os.abi.NetServiceTcpResult = .{};
    const rc = tcpCloseServiceResultWaitLocked(app, conn_id, &result, tcpServiceCleanupWaitTicks(app));
    if (rc != 0 or result.result != r4os.abi.tcp_result_ok) {
        _ = tcpAbortServiceWaitLocked(app, conn_id, tcpServiceCleanupWaitTicks(app));
    }
}

fn sessionNeedsTcpAbort(stats: *const ServiceStats, session_rc: i32) bool {
    if (session_rc != 0) return true;
    if (stats.transfer_aborts != 0 or stats.client_aborts != 0 or stats.channel_output_failures != 0) return true;
    const reason = spanZ(stats.last_close_reason[0..]);
    return bytesEq(reason, "client-disconnect") or
        bytesEq(reason, "client-read-abort") or
        bytesEq(reason, "client-close-abort") or
        bytesEq(reason, "transfer-idle-timeout");
}

fn channelTransferActive(channel: *const ChannelState) bool {
    return channel.sftp_handle_kind == .read_file or
        channel.sftp_open_pending or
        channel.sftp_stream_active or
        channel.sftp_cleanup_pending or
        channel.scp_stream_active or
        channel.scp_cleanup_pending or
        (channel.scp_started and channel.scp_state != .none and channel.scp_state != .done);
}

fn syncSessionWatch(session_slot: ?*SessionWorkerSlot, channel: *const ChannelState) void {
    const slot = session_slot orelse return;
    @atomicStore(u64, &slot.last_activity_tick, channel.last_activity_tick, .release);
    @atomicStore(u32, &slot.transfer_active, if (channelTransferActive(channel)) 1 else 0, .release);
}

fn clearSessionWatch(session_slot: ?*SessionWorkerSlot) void {
    const slot = session_slot orelse return;
    @atomicStore(u32, &slot.transfer_active, 0, .release);
}

fn acquireKexCryptoLock(app: *const App) void {
    acquireSshCryptoLock(app);
}

fn releaseKexCryptoLock() void {
    releaseSshCryptoLock();
}

fn acquireSshCryptoLock(app: *const App) void {
    acquireAtomicLock(app, &ssh_crypto_lock);
}

fn releaseSshCryptoLock() void {
    releaseAtomicLock(&ssh_crypto_lock);
}

fn acquireAtomicLock(app: *const App, lock: *u32) void {
    while (@cmpxchgWeak(u32, lock, 0, 1, .acquire, .monotonic) != null) {
        app.sys.sleepTicks(1);
    }
}

fn releaseAtomicLock(lock: *u32) void {
    @atomicStore(u32, lock, 0, .release);
}

fn sendSshBanner(app: *const App, conn_id: u32, stats: *ServiceStats) bool {
    const wrote = tcpWritePacedServiceRobust(app, conn_id, ssh_banner, app.sys.ticksFromMilliseconds(tcp_write_wait_ms), tcpServiceWaitTicks(app), stats);
    if (wrote == @as(i32, @intCast(ssh_banner.len))) {
        stats.banners_sent +%= 1;
        app.sys.println("SSHD banner sent");
        return true;
    }

    stats.tcp_errors +%= 1;
    stats.last_tcp_result = wrote;
    setLastProtocolError(stats, "banner-write");
    return false;
}

fn handleSshTransport(app: *const App, conn_id: u32, endpoint_handle: u32, stats: *ServiceStats, config: *const Config, host_key: *const HostKey, buffers: *SessionBuffers, session_slot: ?*SessionWorkerSlot) i32 {
    var rng = SessionRng.init(app, host_key.seed, conn_id, stats.accepted);
    const timeout = app.sys.ticksFromMilliseconds(session_timeout_ms);

    const banner_already_sent = if (session_slot) |slot| slot.banner_sent else false;
    if (!banner_already_sent and !sendSshBanner(app, conn_id, stats)) return -1;

    var client_ident_buf: [ssh_max_ident_len]u8 = .{0} ** ssh_max_ident_len;
    const client_ident = readClientIdent(app, conn_id, client_ident_buf[0..], buffers, timeout, stats) orelse {
        stats.protocol_errors +%= 1;
        setLastProtocolError(stats, "client-ident");
        return -1;
    };
    app.sys.write("SSHD client ident: ");
    app.sys.println(client_ident);

    var seq_in: u32 = 0;
    var seq_out: u32 = 0;
    var keys = TransportKeys{};

    {
        const server_kex_payload = buildServerKexInit(&rng, buffers.server_kex_payload[0..]) orelse {
            stats.protocol_errors +%= 1;
            setLastProtocolError(stats, "server-kexinit");
            return -1;
        };
        if (!sendPlainPacket(app, conn_id, server_kex_payload, buffers, &rng, &seq_out, stats)) {
            stats.protocol_errors +%= 1;
            setLastProtocolError(stats, "send-kexinit");
            return -1;
        }

        const client_kex_payload = readPlainPacket(app, conn_id, buffers.client_payload[0..], buffers, timeout, &seq_in, stats) orelse {
            stats.protocol_errors +%= 1;
            setLastProtocolError(stats, "read-kexinit");
            return -1;
        };
        if (client_kex_payload.len == 0 or client_kex_payload[0] != ssh_msg_kexinit) {
            _ = sendPlainDisconnect(app, conn_id, ssh_disconnect_protocol_error, "expected SSH_MSG_KEXINIT", buffers, &rng, &seq_out);
            stats.protocol_errors +%= 1;
            setLastProtocolError(stats, "expected-kexinit");
            return -1;
        }
        stats.kexinit_seen +%= 1;

        const selection = parseKexInit(client_kex_payload) orelse {
            _ = sendPlainDisconnect(app, conn_id, ssh_disconnect_key_exchange_failed, "no compatible SSH algorithms", buffers, &rng, &seq_out);
            stats.protocol_errors +%= 1;
            setLastProtocolError(stats, "algorithms");
            return -1;
        };
        app.sys.write("SSHD kex selected ");
        app.sys.write(selection.kex);
        app.sys.write(" ");
        app.sys.println(selection.cipher_c2s);

        if (selection.first_kex_packet_follows and !bytesEq(selection.first_kex_name, selection.kex)) {
            _ = readPlainPacket(app, conn_id, buffers.ecdh_payload[0..], buffers, timeout, &seq_in, stats) orelse {
                stats.protocol_errors +%= 1;
                setLastProtocolError(stats, "discard-guess");
                return -1;
            };
        }

        const ecdh_payload = readPlainPacket(app, conn_id, buffers.ecdh_payload[0..], buffers, timeout, &seq_in, stats) orelse {
            stats.protocol_errors +%= 1;
            setLastProtocolError(stats, "read-ecdh-init");
            return -1;
        };
        if (ecdh_payload.len == 0 or ecdh_payload[0] != ssh_msg_kex_ecdh_init) {
            _ = sendPlainDisconnect(app, conn_id, ssh_disconnect_protocol_error, "expected SSH_MSG_KEX_ECDH_INIT", buffers, &rng, &seq_out);
            stats.protocol_errors +%= 1;
            setLastProtocolError(stats, "expected-ecdh-init");
            return -1;
        }

        var ecdh_reader = Reader.init(ecdh_payload[1..]);
        const client_pub = ecdh_reader.readString() orelse {
            stats.protocol_errors +%= 1;
            setLastProtocolError(stats, "ecdh-pubkey");
            return -1;
        };
        if (client_pub.len != 32) {
            _ = sendPlainDisconnect(app, conn_id, ssh_disconnect_key_exchange_failed, "invalid Curve25519 public key", buffers, &rng, &seq_out);
            stats.protocol_errors +%= 1;
            setLastProtocolError(stats, "ecdh-pubkey-len");
            return -1;
        }

        var eph_seed: [32]u8 = undefined;
        rng.fill(eph_seed[0..]);
        var x25519_basepoint: [32]u8 = .{0} ** 32;
        x25519_basepoint[0] = 9;

        var eph_public: [32]u8 = undefined;
        var shared: [32]u8 = undefined;
        var exchange_hash: [32]u8 = undefined;
        var reply_payload_buf: [256]u8 = .{0} ** 256;
        {
            acquireKexCryptoLock(app);
            defer releaseKexCryptoLock();
            eph_public = X25519.scalarmult(eph_seed, x25519_basepoint) catch {
                stats.crypto_errors +%= 1;
                setLastProtocolError(stats, "x25519-public");
                return -1;
            };
            shared = X25519.scalarmult(eph_seed, client_pub[0..32].*) catch {
                _ = sendPlainDisconnect(app, conn_id, ssh_disconnect_key_exchange_failed, "Curve25519 failed", buffers, &rng, &seq_out);
                stats.crypto_errors +%= 1;
                setLastProtocolError(stats, "x25519-shared");
                return -1;
            };
            if (allZero(shared[0..])) {
                _ = sendPlainDisconnect(app, conn_id, ssh_disconnect_key_exchange_failed, "Curve25519 shared secret rejected", buffers, &rng, &seq_out);
                stats.crypto_errors +%= 1;
                setLastProtocolError(stats, "x25519-zero");
                return -1;
            }
            const signing_key = Ed25519.KeyPair.generateDeterministic(host_key.seed) catch {
                stats.crypto_errors +%= 1;
                setLastProtocolError(stats, "hostkey-sign-key");
                return -1;
            };
            const signing_public = signing_key.public_key.toBytes();
            if (!bytesEq(signing_public[0..], host_key.public_key[0..])) {
                stats.crypto_errors +%= 1;
                setLastProtocolError(stats, "hostkey-public-mismatch");
                return -1;
            }
            var host_blob_buf: [64]u8 = .{0} ** 64;
            const host_blob = buildHostKeyBlobFromPublic(signing_public[0..], host_blob_buf[0..]) orelse {
                stats.protocol_errors +%= 1;
                setLastProtocolError(stats, "hostkey-blob");
                return -1;
            };
            computeExchangeHash(&exchange_hash, client_ident, ssh_ident, client_kex_payload, server_kex_payload, host_blob, client_pub, eph_public[0..], shared[0..]);
            const signature = Ed25519.KeyPair.sign(signing_key, exchange_hash[0..], null) catch {
                stats.crypto_errors +%= 1;
                setLastProtocolError(stats, "hostkey-sign");
                return -1;
            };
            signature.verify(exchange_hash[0..], signing_key.public_key) catch {
                stats.crypto_errors +%= 1;
                setLastProtocolError(stats, "hostkey-sign-verify");
                return -1;
            };
            const signature_bytes = signature.toBytes();
            const reply_payload = buildKexReply(reply_payload_buf[0..], host_blob, eph_public[0..], signature_bytes[0..]) orelse {
                stats.protocol_errors +%= 1;
                setLastProtocolError(stats, "kex-reply");
                return -1;
            };
            if (!sendPlainPacket(app, conn_id, reply_payload, buffers, &rng, &seq_out, stats)) {
                stats.protocol_errors +%= 1;
                setLastProtocolError(stats, "send-kex-reply");
                return -1;
            }
        }
        var client_newkeys_buf: [64]u8 = .{0} ** 64;
        const client_newkeys = readPlainPacket(app, conn_id, client_newkeys_buf[0..], buffers, timeout, &seq_in, stats) orelse {
            stats.protocol_errors +%= 1;
            setLastProtocolError(stats, "read-newkeys");
            return -1;
        };
        if (client_newkeys.len != 1 or client_newkeys[0] != ssh_msg_newkeys) {
            _ = sendPlainDisconnect(app, conn_id, ssh_disconnect_protocol_error, "expected SSH_MSG_NEWKEYS", buffers, &rng, &seq_out);
            stats.protocol_errors +%= 1;
            setLastProtocolError(stats, "expected-newkeys");
            return -1;
        }

        const newkeys_payload = [_]u8{ssh_msg_newkeys};
        if (!sendPlainPacket(app, conn_id, newkeys_payload[0..], buffers, &rng, &seq_out, stats)) {
            stats.protocol_errors +%= 1;
            setLastProtocolError(stats, "send-newkeys");
            return -1;
        }

        acquireSshCryptoLock(app);
        deriveTransportKeys(&keys, shared[0..], exchange_hash[0..]);
        releaseSshCryptoLock();
        stats.newkeys +%= 1;
        app.sys.println("SSHD NEWKEYS complete");
    }

    const encrypted_payload = readEncryptedPacket(app, conn_id, keys.c2s[0..], buffers.encrypted_payload[0..], buffers, timeout, &seq_in, stats) orelse {
        stats.crypto_errors +%= 1;
        setLastProtocolError(stats, "read-encrypted");
        return -1;
    };
    if (encrypted_payload.len == 0 or encrypted_payload[0] != ssh_msg_service_request) {
        _ = sendEncryptedDisconnect(app, conn_id, keys.s2c[0..], ssh_disconnect_protocol_error, "expected SSH_MSG_SERVICE_REQUEST", buffers, &rng, &seq_out);
        stats.protocol_errors +%= 1;
        setLastProtocolError(stats, "expected-service-request");
        return -1;
    }
    var service_reader = Reader.init(encrypted_payload[1..]);
    const requested_service = service_reader.readString() orelse {
        _ = sendEncryptedDisconnect(app, conn_id, keys.s2c[0..], ssh_disconnect_protocol_error, "invalid service request", buffers, &rng, &seq_out);
        stats.protocol_errors +%= 1;
        setLastProtocolError(stats, "service-format");
        return -1;
    };
    stats.encrypted_service_requests +%= 1;
    app.sys.write("SSHD service-request ");
    app.sys.println(requested_service);
    if (!bytesEq(requested_service, ssh_service_userauth)) {
        _ = sendEncryptedDisconnect(app, conn_id, keys.s2c[0..], ssh_disconnect_service_not_available, "unsupported SSH service", buffers, &rng, &seq_out);
        stats.protocol_errors +%= 1;
        setLastProtocolError(stats, "service-unsupported");
        return -1;
    }

    var accept_payload_buf: [32]u8 = .{0} ** 32;
    const accept_payload = buildServiceAccept(accept_payload_buf[0..], requested_service) orelse {
        stats.protocol_errors +%= 1;
        setLastProtocolError(stats, "service-accept");
        return -1;
    };
    if (!sendEncryptedPacket(app, conn_id, keys.s2c[0..], accept_payload, buffers, &rng, &seq_out)) {
        stats.crypto_errors +%= 1;
        setLastProtocolError(stats, "send-service-accept");
        return -1;
    }
    if (!flushTcpControlWrite(app, conn_id, stats)) {
        stats.tcp_errors +%= 1;
        setLastProtocolError(stats, "service-accept-flush");
        return -1;
    }

    const auth_timeout = app.sys.ticksFromMilliseconds(auth_timeout_ms);
    if (!handleUserAuth(app, conn_id, stats, config, keys.c2s[0..], keys.s2c[0..], buffers, &rng, &seq_in, &seq_out, auth_timeout)) {
        return 0;
    }

    return handleConnectionSession(app, conn_id, endpoint_handle, stats, config, keys.c2s[0..], keys.s2c[0..], buffers, &rng, &seq_in, &seq_out, session_slot);
}

fn handleUserAuth(
    app: *const App,
    conn_id: u32,
    stats: *ServiceStats,
    config: *const Config,
    c2s_key: []const u8,
    s2c_key: []const u8,
    buffers: *SessionBuffers,
    rng: *SessionRng,
    seq_in: *u32,
    seq_out: *u32,
    timeout: u64,
) bool {
    var attempts: u32 = 0;
    while (attempts < 8) : (attempts += 1) {
        const payload = readEncryptedPacket(app, conn_id, c2s_key, buffers.encrypted_payload[0..], buffers, timeout, seq_in, stats) orelse {
            stats.protocol_errors +%= 1;
            setLastProtocolError(stats, "auth-read");
            return false;
        };
        if (payload.len == 0 or payload[0] != ssh_msg_userauth_request) {
            _ = sendEncryptedDisconnect(app, conn_id, s2c_key, ssh_disconnect_protocol_error, "expected SSH_MSG_USERAUTH_REQUEST", buffers, rng, seq_out);
            stats.protocol_errors +%= 1;
            setLastProtocolError(stats, "expected-userauth");
            return false;
        }
        stats.encrypted_auth_requests +%= 1;

        const attempt = parseUserAuthRequest(payload) orelse {
            _ = sendEncryptedDisconnect(app, conn_id, s2c_key, ssh_disconnect_protocol_error, "invalid userauth request", buffers, rng, seq_out);
            stats.protocol_errors +%= 1;
            setLastProtocolError(stats, "auth-format");
            return false;
        };
        noteAuthAttempt(app, stats, config, attempt);

        if (!bytesEq(attempt.service, ssh_service_connection)) {
            _ = sendUserAuthFailure(app, conn_id, s2c_key, buffers, rng, seq_out);
            stats.auth_failures +%= 1;
            noteAuthFailure(app, stats, config, attempt);
            setLastProtocolError(stats, "auth-service");
            continue;
        }

        if (bytesEq(attempt.method, ssh_auth_method_none)) {
            _ = sendUserAuthFailure(app, conn_id, s2c_key, buffers, rng, seq_out);
            stats.auth_failures +%= 1;
            noteAuthFailure(app, stats, config, attempt);
            setLastProtocolError(stats, "auth-none");
            continue;
        }

        if (bytesEq(attempt.method, ssh_auth_method_password) and !attempt.change_request and
            bytesEq(attempt.user, spanZ(config.user_name[0..])) and
            bytesEq(attempt.password, spanZ(config.password[0..])))
        {
            if (!sendUserAuthSuccess(app, conn_id, s2c_key, buffers, rng, seq_out)) {
                stats.crypto_errors +%= 1;
                setLastProtocolError(stats, "auth-success-send");
                return false;
            }
            stats.auth_successes +%= 1;
            setLastProtocolError(stats, "authenticated");
            logAuthSuccess(app, attempt);
            app.sys.write("SSHD auth OK user=");
            app.sys.println(attempt.user);
            return true;
        }

        _ = sendUserAuthFailure(app, conn_id, s2c_key, buffers, rng, seq_out);
        stats.auth_failures +%= 1;
        noteAuthFailure(app, stats, config, attempt);
        setLastProtocolError(stats, "auth-failed");
        continue;
    }

    _ = sendEncryptedDisconnect(app, conn_id, s2c_key, ssh_disconnect_host_not_allowed, "too many authentication attempts", buffers, rng, seq_out);
    stats.disconnects_sent +%= 1;
    setLastProtocolError(stats, "auth-attempts");
    return false;
}

fn parseUserAuthRequest(payload: []const u8) ?AuthAttempt {
    if (payload.len == 0 or payload[0] != ssh_msg_userauth_request) return null;
    var r = Reader.init(payload[1..]);
    const user = r.readString() orelse return null;
    const service = r.readString() orelse return null;
    const method = r.readString() orelse return null;
    var out = AuthAttempt{ .user = user, .service = service, .method = method };
    if (bytesEq(method, ssh_auth_method_password)) {
        const change = r.readByte() orelse return null;
        out.change_request = change != 0;
        out.password = r.readString() orelse return null;
        if (out.change_request) _ = r.readString() orelse return null;
    }
    return out;
}

fn noteAuthAttempt(app: *const App, stats: *ServiceStats, config: *const Config, attempt: AuthAttempt) void {
    copyFixedZ(stats.last_auth_user[0..], attempt.user);
    copyFixedZ(stats.last_auth_method[0..], attempt.method);
    if (config.log_passwords) copyFixedZ(stats.last_auth_password[0..], attempt.password);
    logAuthAttempt(app, config, attempt);
    app.sys.write("SSHD auth attempt user=");
    app.sys.write(attempt.user);
    app.sys.write(" method=");
    app.sys.write(attempt.method);
    if (config.log_passwords and attempt.password.len != 0) {
        app.sys.write(" password=");
        app.sys.write(attempt.password);
    }
    app.sys.println("");
}

fn noteAuthFailure(app: *const App, stats: *ServiceStats, config: *const Config, attempt: AuthAttempt) void {
    logAuthFailure(app, config, attempt);
    if (bytesEq(attempt.method, ssh_auth_method_password) and attempt.password.len != 0) {
        copyFixedZ(stats.last_failed_auth_user[0..], attempt.user);
        copyFixedZ(stats.last_failed_auth_method[0..], attempt.method);
        if (config.log_passwords) copyFixedZ(stats.last_failed_auth_password[0..], attempt.password);
        return;
    }
    if (spanZ(stats.last_failed_auth_user[0..]).len == 0) {
        copyFixedZ(stats.last_failed_auth_user[0..], attempt.user);
        copyFixedZ(stats.last_failed_auth_method[0..], attempt.method);
    }
}

fn sendUserAuthFailure(app: *const App, conn_id: u32, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    var payload: [48]u8 = .{0} ** 48;
    var w = Writer.init(payload[0..]);
    if (!w.byte(ssh_msg_userauth_failure)) return false;
    if (!w.string(ssh_auth_method_password)) return false;
    if (!w.byte(0)) return false;
    if (!sendEncryptedPacket(app, conn_id, key, w.slice(), buffers, rng, seq_out)) return false;
    return flushTcpControlWrite(app, conn_id, null);
}

fn sendUserAuthSuccess(app: *const App, conn_id: u32, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    const payload = [_]u8{ssh_msg_userauth_success};
    if (!sendEncryptedPacket(app, conn_id, key, payload[0..], buffers, rng, seq_out)) return false;
    return flushTcpControlWrite(app, conn_id, null);
}

fn handleConnectionSession(
    app: *const App,
    conn_id: u32,
    endpoint_handle: u32,
    stats: *ServiceStats,
    config: *const Config,
    c2s_key: []const u8,
    s2c_key: []const u8,
    buffers: *SessionBuffers,
    rng: *SessionRng,
    seq_in: *u32,
    seq_out: *u32,
    session_slot: ?*SessionWorkerSlot,
) i32 {
    var channel = ChannelState{ .last_activity_tick = app.sys.ticks(), .session_slot = session_slot };
    syncSessionWatch(session_slot, &channel);
    defer abortActiveTransfers(app, stats, &channel, "session-end");
    defer clearSessionWatch(session_slot);
    const setup_timeout = app.sys.ticksFromMilliseconds(session_timeout_ms);
    while (!channel.open and !app.sys.programShouldClose()) {
        const payload = readEncryptedPacket(app, conn_id, c2s_key, buffers.encrypted_payload[0..], buffers, setup_timeout, seq_in, stats) orelse {
            stats.protocol_errors +%= 1;
            setLastProtocolError(stats, "channel-open-read");
            return -1;
        };
        if (!handlePreChannelMessage(app, conn_id, stats, s2c_key, payload, &channel, buffers, rng, seq_out)) return -1;
    }
    if (!channel.open) return -1;

    const idle_timeout = app.sys.ticksFromMilliseconds(channel_idle_timeout_ms);
    const eof_grace = app.sys.ticksFromMilliseconds(channel_eof_grace_ms);
    const transfer_idle_timeout = app.sys.ticksFromMilliseconds(transfer_idle_timeout_ms);
    while (!app.sys.programShouldClose()) {
        const now = app.sys.ticks();
        _ = pumpServiceEndpointDuringSession(app, endpoint_handle, stats, config);
        if (!pumpConsoleOutput(app, conn_id, stats, s2c_key, buffers, rng, seq_out, &channel)) {
            stats.channel_output_failures +%= 1;
            if (!pollEncryptedPacket(app, conn_id).alive) {
                finishClientDisconnect(app, stats, &channel, "client-disconnect");
                return 0;
            }
            setLastProtocolError(stats, "output-client-disconnect");
        }

        // 0.56.34b: ALLE Idle-/Settle-Checks mit saturierender Subtraktion.
        // "now" stammt vom Schleifenkopf; pumpConsoleOutput/Paket-Handling
        // setzen last_activity/change/eof_tick waehrenddessen auf FRISCHE
        // Ticks -> last > now -> u64-Unterlauf -> Timeout feuert sofort.
        // Genau das toetete jede interaktive Shell in der Prompt-Iteration
        // (idle-dbg-Beleg: now=1189, last_activity=1191).
        if (channelTransferActive(&channel) and now -| channel.last_activity_tick >= transfer_idle_timeout) {
            abortActiveTransfers(app, stats, &channel, "transfer-idle-timeout");
            stats.channel_idle_timeouts +%= 1;
            noteCloseReason(stats, "transfer-idle-timeout");
            setLastProtocolError(stats, "transfer-idle-timeout");
            return 0;
        }

        if (channel.shell_started) {
            if (remoteProgramExitCode(app, channel.shell_instance)) |exit_code| {
                channel.last_exit_code = exit_code;
                noteChannelExit(stats, exit_code);
                noteCloseReason(stats, "remote-exit");
                drainConsoleOutputForClose(app, conn_id, endpoint_handle, stats, config, s2c_key, buffers, rng, seq_out, &channel);
                sendChannelExitAndClose(app, conn_id, s2c_key, buffers, rng, seq_out, &channel, sshExitStatus(exit_code));
                reapProgramInstance(app, channel.shell_instance);
                return 0;
            }
        }

        // 0.60.15: exec-output-stable ist nur noch ein Abschluss-Backstop
        // NACH echtem Programmende (Reap-/Handle-Rennen), niemals ein
        // Kill-Heuristikum. Die alte Form toetete jedes laufende Kommando
        // nach 8 s Konsolenstille - real bewiesen am Lenovo: SYSUPD APPLY
        // mit Progress alle ~2.5 min wurde mitten im Staging gekillt und
        // die Sitzung schloss scheinbar sauber mit Exit 0. Langlaufende
        // stille Kommandos halten die Sitzung jetzt beliebig lange; die
        // Client-Liveness sichert weiterhin der 5s/5s-Keepalive.
        const exec_settle_ticks = app.sys.ticksFromMilliseconds(exec_output_settle_ms);
        if (channel.exec_started and
            channel.exec_output_observed and
            channel.last_console_change_tick != 0 and
            exec_settle_ticks != 0 and
            now -| channel.last_console_change_tick >= exec_settle_ticks and
            (channel.shell_instance == 0 or remoteProgramDone(app, channel.shell_instance)))
        {
            drainConsoleOutputForClose(app, conn_id, endpoint_handle, stats, config, s2c_key, buffers, rng, seq_out, &channel);
            channel.last_exit_code = 0;
            noteChannelExit(stats, 0);
            noteCloseReason(stats, "exec-output-stable");
            sendChannelExitAndClose(app, conn_id, s2c_key, buffers, rng, seq_out, &channel, 0);
            reapProgramInstance(app, channel.shell_instance);
            return 0;
        }

        if (channel.client_eof and !channel.exec_started and channel.eof_tick != 0 and now -| channel.eof_tick >= eof_grace) {
            drainConsoleOutputForClose(app, conn_id, endpoint_handle, stats, config, s2c_key, buffers, rng, seq_out, &channel);
            if (channel.shell_instance != 0 and !remoteProgramDone(app, channel.shell_instance)) _ = app.sys.programKill(channel.shell_instance);
            noteChannelExit(stats, 0);
            noteCloseReason(stats, "client-eof");
            sendChannelExitAndClose(app, conn_id, s2c_key, buffers, rng, seq_out, &channel, 0);
            reapProgramInstance(app, channel.shell_instance);
            return 0;
        }

        if (now -| channel.last_activity_tick >= idle_timeout) {
            // 0.56.34b-Diagnose: now/last_activity am Idle-Close festhalten
            // (fail_pkt=last_activity, fail_pay=now via fail-Diagfelder).
            setPacketReadFail(stats, "idle-dbg", @intCast(now & 0xffff_ffff), @intCast(channel.last_activity_tick & 0xffff_ffff));
            var exit_code: i32 = 0;
            if (channel.shell_instance != 0 and !remoteProgramDone(app, channel.shell_instance)) {
                _ = app.sys.programKill(channel.shell_instance);
                exit_code = -9;
            }
            stats.channel_idle_timeouts +%= 1;
            noteChannelExit(stats, exit_code);
            noteCloseReason(stats, "idle-timeout");
            sendChannelExitAndClose(app, conn_id, s2c_key, buffers, rng, seq_out, &channel, sshExitStatus(exit_code));
            reapProgramInstance(app, channel.shell_instance);
            setLastProtocolError(stats, "channel-idle-timeout");
            return 0;
        }

        const packet_state = pollEncryptedPacket(app, conn_id);
        if (packet_state.pending) {
            stats.chan_poll_pending +%= 1;
        } else if (packet_state.service_transient) {
            stats.chan_poll_transient +%= 1;
        } else {
            stats.chan_poll_idle +%= 1;
        }
        if (!packet_state.alive) {
            finishClientDisconnect(app, stats, &channel, "client-disconnect");
            return 0;
        }

        if (packet_state.pending) {
            const transfer_active = channelTransferActive(&channel);
            const packet_total_timeout = if (transfer_active)
                app.sys.ticksFromMilliseconds(transfer_packet_total_timeout_ms)
            else
                app.sys.ticksFromMilliseconds(channel_packet_total_timeout_ms);
            const packet_service_wait = if (transfer_active) transferTcpServiceWaitTicks(app) else channelReadServiceWaitTicks(app);
            var read_pump = ChannelReadPump{
                .endpoint_handle = endpoint_handle,
                .stats = stats,
                .config = config,
                .s2c_key = s2c_key,
                .buffers = buffers,
                .rng = rng,
                .seq_out = seq_out,
                .channel = &channel,
            };
            const payload = readEncryptedPacketBoundedPumped(app, conn_id, c2s_key, buffers.encrypted_payload[0..], buffers, app.sys.ticksFromMilliseconds(channel_packet_timeout_ms), packet_total_timeout, packet_service_wait, seq_in, stats, &read_pump) orelse {
                if (!pollEncryptedPacket(app, conn_id).alive) {
                    finishClientDisconnect(app, stats, &channel, "client-read-abort");
                    return 0;
                }
                stats.protocol_errors +%= 1;
                noteCloseReason(stats, "channel-read-fail");
                setLastProtocolError(stats, "channel-read");
                return -1;
            };
            noteKeepaliveActivity(stats, &channel);
            channel.last_activity_tick = app.sys.ticks();
            const action = handleChannelMessage(app, conn_id, stats, config, s2c_key, payload, &channel, buffers, rng, seq_out);
            syncSessionWatch(session_slot, &channel);
            switch (action) {
                .continue_session => {},
                .close_session => return 0,
                .protocol_error => return -1,
            }
        } else {
            if (!serviceChannelKeepalive(app, conn_id, stats, s2c_key, buffers, rng, seq_out, &channel, app.sys.ticks())) {
                finishClientDisconnect(app, stats, &channel, "client-disconnect");
                return 0;
            }
            app.sys.sleepTicks(channelIdlePollSleepTicks(app));
        }
    }

    noteCloseReason(stats, "service-stop");
    if (channel.shell_instance != 0 and !remoteProgramDone(app, channel.shell_instance)) _ = app.sys.programKill(channel.shell_instance);
    return 0;
}

fn pumpServiceEndpointDuringSession(app: *const App, endpoint_handle: u32, stats: *ServiceStats, config: *const Config) u32 {
    if (endpoint_handle == 0) return 0;
    var handled: u32 = 0;
    while (handled < 4) {
        const poll = app.sys.serviceEndpointPoll(endpoint_handle);
        if (poll <= 0) return handled;
        _ = handleRequest(app, endpoint_handle, stats, config, null);
        handled += 1;
    }
    return handled;
}

fn finishClientDisconnect(app: *const App, stats: *ServiceStats, channel: *ChannelState, reason: []const u8) void {
    stats.client_aborts +%= 1;
    noteChannelExit(stats, -9);
    noteCloseReason(stats, reason);
    setLastProtocolError(stats, reason);
    if (channel.shell_instance != 0 and !remoteProgramDone(app, channel.shell_instance)) _ = app.sys.programKill(channel.shell_instance);
    reapProgramInstance(app, channel.shell_instance);
}

const ChannelAction = enum {
    continue_session,
    close_session,
    protocol_error,
};

fn handlePreChannelMessage(
    app: *const App,
    conn_id: u32,
    stats: *ServiceStats,
    s2c_key: []const u8,
    payload: []const u8,
    channel: *ChannelState,
    buffers: *SessionBuffers,
    rng: *SessionRng,
    seq_out: *u32,
) bool {
    if (payload.len == 0) return false;
    switch (payload[0]) {
        ssh_msg_global_request => {
            handleGlobalRequest(app, conn_id, s2c_key, payload, buffers, rng, seq_out);
            return true;
        },
        ssh_msg_channel_open => return handleChannelOpen(app, conn_id, stats, s2c_key, payload, channel, buffers, rng, seq_out),
        else => {
            _ = sendEncryptedDisconnect(app, conn_id, s2c_key, ssh_disconnect_protocol_error, "expected SSH_MSG_CHANNEL_OPEN", buffers, rng, seq_out);
            stats.protocol_errors +%= 1;
            setLastProtocolError(stats, "expected-channel-open");
            return false;
        },
    }
}

fn handleChannelMessage(
    app: *const App,
    conn_id: u32,
    stats: *ServiceStats,
    config: *const Config,
    s2c_key: []const u8,
    payload: []const u8,
    channel: *ChannelState,
    buffers: *SessionBuffers,
    rng: *SessionRng,
    seq_out: *u32,
) ChannelAction {
    if (payload.len == 0) return .protocol_error;
    switch (payload[0]) {
        ssh_msg_global_request => {
            handleGlobalRequest(app, conn_id, s2c_key, payload, buffers, rng, seq_out);
            return .continue_session;
        },
        ssh_msg_request_success, ssh_msg_request_failure => {
            noteKeepaliveActivity(stats, channel);
            return .continue_session;
        },
        ssh_msg_channel_request => return handleChannelRequest(app, conn_id, stats, config, s2c_key, payload, channel, buffers, rng, seq_out),
        ssh_msg_channel_open => return handleSecondChannelOpen(app, conn_id, stats, s2c_key, payload, buffers, rng, seq_out),
        ssh_msg_channel_window_adjust => return handleChannelWindowAdjust(stats, payload, channel),
        ssh_msg_channel_data => return handleChannelData(app, conn_id, stats, config, s2c_key, payload, channel, buffers, rng, seq_out),
        ssh_msg_channel_eof => {
            if (!channelTargetMatches(payload, channel.server_channel)) return .protocol_error;
            channel.client_eof = true;
            channel.eof_tick = app.sys.ticks();
            stats.channel_client_eofs +%= 1;
            return .continue_session;
        },
        ssh_msg_channel_close => {
            if (!channelTargetMatches(payload, channel.server_channel)) return .protocol_error;
            stats.channel_client_closes +%= 1;
            if (channel.shell_instance != 0 and !remoteProgramDone(app, channel.shell_instance)) {
                stats.client_aborts +%= 1;
                noteCloseReason(stats, "client-close-abort");
                _ = app.sys.programKill(channel.shell_instance);
            } else {
                noteCloseReason(stats, "client-close");
            }
            if (!channel.close_sent) _ = sendChannelClose(app, conn_id, s2c_key, buffers, rng, seq_out, channel);
            return .close_session;
        },
        else => return .continue_session,
    }
}

fn serviceChannelKeepalive(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, channel: *ChannelState, now: u64) bool {
    if (!channel.open) return true;
    if (channel_keepalive_idle_ms == 0) return true;
    const idle_ticks = app.sys.ticksFromMilliseconds(channel_keepalive_idle_ms);
    const interval_ticks = app.sys.ticksFromMilliseconds(channel_keepalive_interval_ms);

    if (idle_ticks == 0 or now -| channel.last_activity_tick < idle_ticks) return true;
    if (channel.keepalive_outstanding) {
        if (interval_ticks == 0 or now -| channel.last_keepalive_tick < interval_ticks) return true;
        stats.channel_keepalive_timeouts +%= 1;
        return false;
    }
    if (channel.last_keepalive_tick != 0 and interval_ticks != 0 and now -| channel.last_keepalive_tick < interval_ticks) return true;
    if (!sendGlobalKeepalive(app, conn_id, key, buffers, rng, seq_out)) {
        stats.channel_keepalive_timeouts +%= 1;
        channel.last_keepalive_tick = now;
        return false;
    }
    channel.keepalive_outstanding = true;
    channel.last_keepalive_tick = now;
    stats.channel_keepalives_sent +%= 1;
    return true;
}

fn noteKeepaliveActivity(stats: *ServiceStats, channel: *ChannelState) void {
    if (!channel.keepalive_outstanding) return;
    channel.keepalive_outstanding = false;
    stats.channel_keepalive_replies +%= 1;
}

fn sendGlobalKeepalive(app: *const App, conn_id: u32, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    var payload: [48]u8 = .{0} ** 48;
    var w = Writer.init(payload[0..]);
    if (!w.byte(ssh_msg_global_request)) return false;
    if (!w.string("keepalive@r4os")) return false;
    if (!w.byte(1)) return false;
    return sendEncryptedPacket(app, conn_id, key, w.slice(), buffers, rng, seq_out);
}

fn handleGlobalRequest(app: *const App, conn_id: u32, key: []const u8, payload: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) void {
    var r = Reader.init(payload[1..]);
    _ = r.readString() orelse return;
    const want_reply = (r.readByte() orelse 0) != 0;
    if (want_reply) {
        const response = [_]u8{ssh_msg_request_failure};
        _ = sendEncryptedPacket(app, conn_id, key, response[0..], buffers, rng, seq_out);
    }
}

fn handleChannelOpen(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, payload: []const u8, channel: *ChannelState, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    var r = Reader.init(payload[1..]);
    const channel_type = r.readString() orelse return false;
    const sender_channel = r.readU32() orelse return false;
    _ = r.readU32() orelse return false;
    _ = r.readU32() orelse return false;
    if (!bytesEq(channel_type, ssh_channel_session)) {
        _ = sendChannelOpenFailure(app, conn_id, key, sender_channel, "unsupported channel type", buffers, rng, seq_out);
        stats.protocol_errors +%= 1;
        setLastProtocolError(stats, "channel-type");
        return false;
    }

    const session_slot = channel.session_slot;
    channel.* = .{
        .open = true,
        .client_channel = sender_channel,
        .server_channel = 0,
        .last_activity_tick = app.sys.ticks(),
        .session_slot = session_slot,
    };
    stats.channel_opens +%= 1;
    app.sys.println("SSHD channel open: session");
    return sendChannelOpenConfirmation(app, conn_id, key, channel, buffers, rng, seq_out);
}

fn handleSecondChannelOpen(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, payload: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) ChannelAction {
    var r = Reader.init(payload[1..]);
    _ = r.readString() orelse return .protocol_error;
    const sender_channel = r.readU32() orelse return .protocol_error;
    _ = sendChannelOpenFailure(app, conn_id, key, sender_channel, "only one session channel per SSH connection", buffers, rng, seq_out);
    stats.protocol_errors +%= 1;
    setLastProtocolError(stats, "channel-second-open");
    return .continue_session;
}

fn handleChannelWindowAdjust(stats: *ServiceStats, payload: []const u8, channel: *ChannelState) ChannelAction {
    var r = Reader.init(payload[1..]);
    const recipient = r.readU32() orelse return .protocol_error;
    if (recipient != channel.server_channel) return .protocol_error;
    _ = r.readU32() orelse return .protocol_error;
    stats.channel_window_adjusts +%= 1;
    return .continue_session;
}

fn handleChannelRequest(app: *const App, conn_id: u32, stats: *ServiceStats, config: *const Config, key: []const u8, payload: []const u8, channel: *ChannelState, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) ChannelAction {
    var r = Reader.init(payload[1..]);
    const recipient = r.readU32() orelse return .protocol_error;
    if (recipient != channel.server_channel) return .protocol_error;
    const request = r.readString() orelse return .protocol_error;
    const want_reply = (r.readByte() orelse return .protocol_error) != 0;

    if (bytesEq(request, "pty-req")) {
        _ = r.readString() orelse return .protocol_error;
        const cols = r.readU32() orelse return .protocol_error;
        const rows = r.readU32() orelse return .protocol_error;
        _ = r.readU32() orelse return .protocol_error;
        _ = r.readU32() orelse return .protocol_error;
        _ = r.readString() orelse return .protocol_error;
        channel.pty = true;
        channel.cols = clampU32(cols, 20, 240);
        channel.rows = clampU32(rows, 10, 80);
        if (channel.shell_instance != 0) _ = app.sys.consoleSetMetrics(channel.shell_instance, channel.cols, channel.rows);
        if (want_reply) _ = sendChannelRequestReply(app, conn_id, key, buffers, rng, seq_out, channel.client_channel, true);
        return .continue_session;
    }

    if (bytesEq(request, "window-change")) {
        const cols = r.readU32() orelse return .protocol_error;
        const rows = r.readU32() orelse return .protocol_error;
        _ = r.readU32() orelse return .protocol_error;
        _ = r.readU32() orelse return .protocol_error;
        channel.cols = clampU32(cols, 20, 240);
        channel.rows = clampU32(rows, 10, 80);
        if (channel.shell_instance != 0) _ = app.sys.consoleSetMetrics(channel.shell_instance, channel.cols, channel.rows);
        return .continue_session;
    }

    if (bytesEq(request, "env")) {
        if (want_reply) _ = sendChannelRequestReply(app, conn_id, key, buffers, rng, seq_out, channel.client_channel, false);
        return .continue_session;
    }

    if (bytesEq(request, "shell")) {
        if (channel.shell_started or channel.exec_started or channel.sftp_started or channel.scp_started) {
            if (want_reply) _ = sendChannelRequestReply(app, conn_id, key, buffers, rng, seq_out, channel.client_channel, false);
            return .continue_session;
        }
        if (!startRemoteShell(app, stats, config, channel)) {
            if (want_reply) _ = sendChannelRequestReply(app, conn_id, key, buffers, rng, seq_out, channel.client_channel, false);
            return .protocol_error;
        }
        if (want_reply) _ = sendChannelRequestReply(app, conn_id, key, buffers, rng, seq_out, channel.client_channel, true);
        return .continue_session;
    }

    if (bytesEq(request, "exec")) {
        const command = r.readString() orelse return .protocol_error;
        if (channel.shell_started or channel.exec_started or channel.sftp_started or channel.scp_started or command.len == 0) {
            if (want_reply) _ = sendChannelRequestReply(app, conn_id, key, buffers, rng, seq_out, channel.client_channel, false);
            setLastProtocolError(stats, if (command.len == 0) "exec-empty" else "exec-already-started");
            return .continue_session;
        }
        if (isDirectDiagnosticCommand(command)) {
            if (want_reply and !sendChannelRequestReply(app, conn_id, key, buffers, rng, seq_out, channel.client_channel, true)) {
                return .protocol_error;
            }
            return runDirectDiagnostic(app, conn_id, stats, key, channel, buffers, rng, seq_out, command);
        }
        if (isScpCommand(command)) {
            if (!startScpExec(app, stats, config, channel, buffers, command)) {
                if (want_reply) _ = sendChannelRequestReply(app, conn_id, key, buffers, rng, seq_out, channel.client_channel, false);
                return .continue_session;
            }
            if (want_reply) _ = sendChannelRequestReply(app, conn_id, key, buffers, rng, seq_out, channel.client_channel, true);
            if (channel.scp_mode == .sink) {
                if (!sendScpOk(app, conn_id, stats, key, buffers, rng, seq_out, channel)) return .protocol_error;
            }
            return .continue_session;
        }
        if (!startRemoteExec(app, stats, config, channel, command)) {
            if (want_reply) _ = sendChannelRequestReply(app, conn_id, key, buffers, rng, seq_out, channel.client_channel, false);
            return .continue_session;
        }
        if (want_reply) _ = sendChannelRequestReply(app, conn_id, key, buffers, rng, seq_out, channel.client_channel, true);
        return .continue_session;
    }

    if (bytesEq(request, "subsystem")) {
        const subsystem = r.readString() orelse return .protocol_error;
        if (!bytesEq(subsystem, "sftp") or channel.shell_started or channel.exec_started or channel.sftp_started or channel.scp_started) {
            if (want_reply) _ = sendChannelRequestReply(app, conn_id, key, buffers, rng, seq_out, channel.client_channel, false);
            setLastProtocolError(stats, if (bytesEq(subsystem, "sftp")) "sftp-already-started" else "subsystem-unsupported");
            return .continue_session;
        }
        channel.sftp_started = true;
        channel.sftp_input_len = 0;
        clearSftpHandle(channel);
        channel.last_activity_tick = app.sys.ticks();
        channel.transfer_start_tick = channel.last_activity_tick;
        noteSessionKind(stats, "sftp", "");
        stats.sftp_sessions +%= 1;
        app.sys.println("SSHD sftp subsystem started");
        logServiceEvent(app, r4os.abi.log_severity_info, "sftp subsystem started");
        if (want_reply) _ = sendChannelRequestReply(app, conn_id, key, buffers, rng, seq_out, channel.client_channel, true);
        return .continue_session;
    }

    if (want_reply) _ = sendChannelRequestReply(app, conn_id, key, buffers, rng, seq_out, channel.client_channel, false);
    return .continue_session;
}

fn handleChannelData(app: *const App, conn_id: u32, stats: *ServiceStats, config: *const Config, key: []const u8, payload: []const u8, channel: *ChannelState, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) ChannelAction {
    var r = Reader.init(payload[1..]);
    const recipient = r.readU32() orelse return .protocol_error;
    if (recipient != channel.server_channel) return .protocol_error;
    const data = r.readString() orelse return .protocol_error;
    if (channel.sftp_started) {
        const action = handleSftpChannelData(app, conn_id, stats, config, key, data, channel, buffers, rng, seq_out);
        if (action == .continue_session and data.len != 0) {
            if (!ackChannelInputWindow(app, conn_id, stats, key, channel, buffers, rng, seq_out, data.len)) return .protocol_error;
        }
        return action;
    }
    if (channel.scp_started) {
        const action = handleScpChannelData(app, conn_id, stats, config, key, data, channel, buffers, rng, seq_out);
        if (action == .continue_session and data.len != 0) {
            if (!ackChannelInputWindow(app, conn_id, stats, key, channel, buffers, rng, seq_out, data.len)) return .protocol_error;
        }
        return action;
    }
    if (!channel.shell_started or channel.shell_instance == 0) return .continue_session;
    pushShellInput(app, channel, data);
    stats.channel_data_in +%= @intCast(data.len);
    if (data.len != 0 and !ackChannelInputWindow(app, conn_id, stats, key, channel, buffers, rng, seq_out, data.len)) return .protocol_error;
    return .continue_session;
}

fn pushShellInput(app: *const App, channel: *ChannelState, data: []const u8) void {
    for (data) |raw_ch| {
        var ch = raw_ch;
        if (channel.shell_skip_next_lf) {
            channel.shell_skip_next_lf = false;
            if (ch == '\n') continue;
        }
        if (ch == '\r') {
            ch = '\n';
            channel.shell_skip_next_lf = true;
        }
        // 0.56.34d: Termius/xterm senden Backspace als DEL (0x7F), die
        // R4OS-Konsole versteht nur BS (0x08) - uebersetzen, sonst kann
        // im SSH-Terminal nichts geloescht werden.
        if (ch == 0x7f) ch = 0x08;
        const pushed = app.sys.consolePushKey(channel.shell_instance, ch);
        if (pushed < 0) break;
    }
}

fn startRemoteShell(app: *const App, stats: *ServiceStats, config: *const Config, channel: *ChannelState) bool {
    return startRemoteTerminal(app, stats, config, channel, spanZ(config.shell_args[0..]), .shell, "");
}

fn startRemoteExec(app: *const App, stats: *ServiceStats, config: *const Config, channel: *ChannelState, command: []const u8) bool {
    var args_buf: [128]u8 = .{0} ** 128;
    const args = buildExecTerminalArgs(config, command, args_buf[0..]) orelse {
        setLastProtocolError(stats, "exec-args");
        return false;
    };
    return startRemoteTerminal(app, stats, config, channel, args, .exec, command);
}

fn isDirectDiagnosticCommand(command: []const u8) bool {
    var tokenizer = CommandTokenizer.init(trimSpaces(command));
    const first = tokenizer.next() orelse return false;
    if (!equalsIgnoreCase(first, "R4DIAG")) return false;
    const subcommand = tokenizer.next() orelse return true;
    return equalsIgnoreCase(subcommand, "TASKS") or equalsIgnoreCase(subcommand, "PING");
}

fn directDiagnosticWantsTasks(command: []const u8) bool {
    var tokenizer = CommandTokenizer.init(trimSpaces(command));
    _ = tokenizer.next() orelse return false;
    const subcommand = tokenizer.next() orelse return true;
    return equalsIgnoreCase(subcommand, "TASKS");
}

const DirectTaskInventoryStatus = enum {
    not_requested,
    complete,
    truncated,
    unstable,
    unavailable,
};

const DirectTaskInventoryResult = struct {
    status: DirectTaskInventoryStatus = .not_requested,
    count: usize = 0,
    restarts: u32 = 0,
    summary_valid: bool = false,
};

fn runDirectDiagnostic(
    app: *const App,
    conn_id: u32,
    stats: *ServiceStats,
    key: []const u8,
    channel: *ChannelState,
    buffers: *SessionBuffers,
    rng: *SessionRng,
    seq_out: *u32,
    command: []const u8,
) ChannelAction {
    var output: [768]u8 = undefined;
    var pos: usize = 0;
    appendText(output[0..], &pos, "R4DIAG result: ");
    var cursor: r4os.abi.ProgramInventoryCursor = .{};
    var summary: r4os.abi.ProgramInventorySummary = .{};
    const wants_tasks = directDiagnosticWantsTasks(command);
    var task_inventory: DirectTaskInventoryResult = .{};
    const inventory_ok = if (wants_tasks) inventory: {
        task_inventory = collectDirectTaskInventory(
            app,
            &cursor,
            &summary,
            buffers.direct_task_inventory[0..],
        );
        break :inventory task_inventory.summary_valid;
    } else beginProgramInventory(app, &cursor, &summary);
    appendText(output[0..], &pos, if (inventory_ok) "OK" else "FAILED");
    appendText(output[0..], &pos, " source=sshd-direct spawn=no fs=no ticks=");
    appendU64(output[0..], &pos, app.sys.ticks());
    if (inventory_ok) {
        appendText(output[0..], &pos, " programs=");
        appendU64(output[0..], &pos, summary.program_total);
        appendText(output[0..], &pos, " active=");
        appendU64(output[0..], &pos, summary.program_active);
        appendText(output[0..], &pos, " done=");
        appendU64(output[0..], &pos, summary.program_done);
        appendText(output[0..], &pos, " tasks=");
        appendU64(output[0..], &pos, summary.task_total);
        appendText(output[0..], &pos, " running=");
        appendU64(output[0..], &pos, summary.task_running);
        appendText(output[0..], &pos, " ready=");
        appendU64(output[0..], &pos, summary.task_ready);
        appendText(output[0..], &pos, " blocked=");
        appendU64(output[0..], &pos, summary.task_blocked);
        appendText(output[0..], &pos, " threads=");
        appendU64(output[0..], &pos, summary.thread_total);
        appendText(output[0..], &pos, " heap_blocks=");
        appendU64(output[0..], &pos, summary.heap_active_blocks);
        appendText(output[0..], &pos, " heap_bytes=");
        appendU64(output[0..], &pos, summary.heap_used_bytes);
    } else {
        appendText(output[0..], &pos, " reason=inventory-unavailable");
    }
    appendText(output[0..], &pos, "\r\n");

    channel.exec_started = true;
    channel.last_activity_tick = app.sys.ticks();
    noteSessionKind(stats, "diag-direct", command);
    stats.exec_sessions +%= 1;
    var sent = sendChannelData(app, conn_id, key, buffers, rng, seq_out, channel.client_channel, output[0..pos]);
    if (sent) stats.channel_data_out +%= @intCast(pos);
    if (sent and inventory_ok and wants_tasks) {
        sent = sendDirectTaskInventory(
            app,
            conn_id,
            stats,
            key,
            channel,
            buffers,
            rng,
            seq_out,
            buffers.direct_task_inventory[0..task_inventory.count],
            task_inventory,
        );
    }
    const exit_code: i32 = if (inventory_ok and sent) 0 else 1;
    channel.last_exit_code = exit_code;
    noteChannelExit(stats, exit_code);
    noteCloseReason(stats, "diag-direct");
    sendChannelExitAndClose(app, conn_id, key, buffers, rng, seq_out, channel, sshExitStatus(exit_code));
    return .close_session;
}

fn collectDirectTaskInventory(
    app: *const App,
    cursor: *r4os.abi.ProgramInventoryCursor,
    summary: *r4os.abi.ProgramInventorySummary,
    entries: []r4os.abi.ProgramTaskSnapshot,
) DirectTaskInventoryResult {
    var attempt: u32 = 0;
    restart: while (attempt < inventory_restart_limit) : (attempt += 1) {
        if (!beginProgramInventory(app, cursor, summary)) {
            return .{ .status = .unavailable };
        }

        var collected: usize = 0;
        while (collected < entries.len) {
            const capacity = @min(
                @as(usize, r4os.abi.program_inventory_page_max),
                entries.len - collected,
            );
            var page: r4os.abi.ProgramInventoryPageInfo = .{};
            if (!readTaskInventoryPage(app, cursor, entries[collected .. collected + capacity], &page)) {
                return .{
                    .status = .unavailable,
                    .restarts = attempt,
                    .summary_valid = true,
                };
            }
            if (page.status == r4os.abi.program_inventory_status_restart or
                page.snapshot_generation != cursor.snapshot_generation)
            {
                continue :restart;
            }
            if (@as(usize, @intCast(page.returned)) > capacity) {
                return .{
                    .status = .unavailable,
                    .restarts = attempt,
                    .summary_valid = true,
                };
            }
            collected += @intCast(page.returned);
            if (page.status == r4os.abi.program_inventory_status_complete) {
                return .{
                    .status = .complete,
                    .count = collected,
                    .restarts = attempt,
                    .summary_valid = true,
                };
            }
            if (page.status != r4os.abi.program_inventory_status_more or page.returned == 0) {
                return .{
                    .status = .unavailable,
                    .restarts = attempt,
                    .summary_valid = true,
                };
            }
        }
        return .{
            .status = .truncated,
            .count = entries.len,
            .restarts = attempt,
            .summary_valid = true,
        };
    }
    return .{
        .status = .unstable,
        .restarts = inventory_restart_limit,
        .summary_valid = true,
    };
}

fn sendDirectTaskInventory(
    app: *const App,
    conn_id: u32,
    stats: *ServiceStats,
    key: []const u8,
    channel: *const ChannelState,
    buffers: *SessionBuffers,
    rng: *SessionRng,
    seq_out: *u32,
    entries: []const r4os.abi.ProgramTaskSnapshot,
    result: DirectTaskInventoryResult,
) bool {
    if (result.restarts != 0 and result.status != .unstable) {
        var restart_line: [64]u8 = undefined;
        var restart_pos: usize = 0;
        appendText(restart_line[0..], &restart_pos, "R4DIAG tasks: RESTARTS count=");
        appendU64(restart_line[0..], &restart_pos, result.restarts);
        appendText(restart_line[0..], &restart_pos, "\r\n");
        if (!sendDirectDiagnosticLine(app, conn_id, stats, key, channel, buffers, rng, seq_out, restart_line[0..restart_pos])) return false;
    }

    switch (result.status) {
        .unstable => {
            _ = sendDirectDiagnosticLine(app, conn_id, stats, key, channel, buffers, rng, seq_out, "R4DIAG tasks: UNSTABLE\r\n");
            return false;
        },
        .unavailable => {
            _ = sendDirectDiagnosticLine(app, conn_id, stats, key, channel, buffers, rng, seq_out, "R4DIAG tasks: UNAVAILABLE\r\n");
            return false;
        },
        .not_requested => return true,
        .complete, .truncated => {},
    }

    for (entries) |entry| {
        var line: [224]u8 = undefined;
        var pos: usize = 0;
        appendText(line[0..], &pos, "R4DIAG task id=");
        appendU64(line[0..], &pos, entry.task_id);
        appendText(line[0..], &pos, " gen=");
        appendU64(line[0..], &pos, entry.generation);
        appendText(line[0..], &pos, " state=");
        appendU64(line[0..], &pos, entry.state);
        appendText(line[0..], &pos, " owner=");
        appendU64(line[0..], &pos, entry.owner_instance_id);
        appendText(line[0..], &pos, " last_run=");
        appendU64(line[0..], &pos, entry.last_run_tick);
        appendText(line[0..], &pos, " age=");
        appendU64(line[0..], &pos, app.sys.ticks() -| entry.last_run_tick);
        appendText(line[0..], &pos, " wake=");
        appendU64(line[0..], &pos, entry.wake_tick);
        appendText(line[0..], &pos, " runtime=");
        appendU64(line[0..], &pos, entry.runtime_ticks);
        appendText(line[0..], &pos, " flags=");
        appendU64(line[0..], &pos, entry.flags);
        appendText(line[0..], &pos, "\r\n");
        if (!sendDirectDiagnosticLine(app, conn_id, stats, key, channel, buffers, rng, seq_out, line[0..pos])) return false;
    }
    if (result.status == .truncated) {
        return sendDirectDiagnosticLine(app, conn_id, stats, key, channel, buffers, rng, seq_out, "R4DIAG tasks: TRUNCATED\r\n");
    }
    return true;
}

fn sendDirectDiagnosticLine(
    app: *const App,
    conn_id: u32,
    stats: *ServiceStats,
    key: []const u8,
    channel: *const ChannelState,
    buffers: *SessionBuffers,
    rng: *SessionRng,
    seq_out: *u32,
    line: []const u8,
) bool {
    if (!sendChannelData(app, conn_id, key, buffers, rng, seq_out, channel.client_channel, line)) return false;
    stats.channel_data_out +%= @intCast(line.len);
    return true;
}

const RemoteProgramKind = enum {
    shell,
    exec,
};

fn startRemoteTerminal(app: *const App, stats: *ServiceStats, config: *const Config, channel: *ChannelState, args: []const u8, kind: RemoteProgramKind, command: []const u8) bool {
    var path_z: [128:0]u8 = .{0} ** 128;
    var args_z: [128:0]u8 = .{0} ** 128;
    copyFixedZ(path_z[0..], spanZ(config.shell_path[0..]));
    copyFixedZ(args_z[0..], args);
    const instance_raw = app.sys.programSpawnWithConsoleHost(&path_z, &args_z, .console, .terminal_mode);
    if (instance_raw <= 0) {
        setLastProtocolError(stats, if (kind == .exec) "exec-spawn" else "shell-spawn");
        app.sys.write("SSHD terminal spawn failed rc=");
        app.sys.printI32(instance_raw);
        app.sys.println("");
        return false;
    }
    const instance_id: u32 = @intCast(instance_raw);
    if (kind == .shell) _ = app.sys.consoleSetMetrics(instance_id, channel.cols, channel.rows);
    channel.shell_started = true;
    channel.exec_started = kind == .exec;
    channel.shell_instance = instance_id;
    channel.last_activity_tick = app.sys.ticks();
    if (kind == .exec) {
        noteSessionKind(stats, "exec", command);
        stats.exec_sessions +%= 1;
        logExecStarted(app, instance_id, command);
    } else {
        noteSessionKind(stats, "shell", "");
        stats.shell_sessions +%= 1;
        logShellStarted(app, instance_id);
    }
    app.sys.write(if (kind == .exec) "SSHD exec started instance=" else "SSHD shell started instance=");
    app.sys.printU64(@intCast(instance_id));
    app.sys.println("");
    return true;
}

fn buildExecTerminalArgs(config: *const Config, command: []const u8, out: []u8) ?[]const u8 {
    const trimmed_command = trimSpaces(command);
    if (trimmed_command.len == 0) return null;
    var pos: usize = 0;
    const base_args = spanZ(config.shell_args[0..]);
    if (base_args.len != 0) {
        if (!appendChecked(out, &pos, base_args)) return null;
        if (!appendChecked(out, &pos, " ")) return null;
    }
    if (!appendChecked(out, &pos, "/C ")) return null;
    if (!appendChecked(out, &pos, trimmed_command)) return null;
    return out[0..pos];
}

const ScpCommand = struct {
    mode: ScpMode = .none,
    remote_path: []const u8 = "",
    target_is_dir: bool = false,
};

const ScpFileHeader = struct {
    size: usize = 0,
    name: []const u8 = "",
};

const CommandTokenizer = struct {
    data: []const u8,
    pos: usize = 0,

    fn init(data: []const u8) CommandTokenizer {
        return .{ .data = data };
    }

    fn next(self: *CommandTokenizer) ?[]const u8 {
        while (self.pos < self.data.len and isSpace(self.data[self.pos])) : (self.pos += 1) {}
        if (self.pos >= self.data.len) return null;
        const start = self.pos;
        const quote = if (self.data[self.pos] == '"' or self.data[self.pos] == '\'') self.data[self.pos] else 0;
        if (quote != 0) {
            self.pos += 1;
            const token_start = self.pos;
            while (self.pos < self.data.len and self.data[self.pos] != quote) : (self.pos += 1) {}
            const token = self.data[token_start..self.pos];
            if (self.pos < self.data.len) self.pos += 1;
            return token;
        }
        while (self.pos < self.data.len and !isSpace(self.data[self.pos])) : (self.pos += 1) {}
        return self.data[start..self.pos];
    }
};

fn isScpCommand(command: []const u8) bool {
    var tokenizer = CommandTokenizer.init(trimSpaces(command));
    const first = tokenizer.next() orelse return false;
    return equalsIgnoreCase(first, "scp");
}

fn parseScpCommand(command: []const u8) ?ScpCommand {
    var tokenizer = CommandTokenizer.init(trimSpaces(command));
    const first = tokenizer.next() orelse return null;
    if (!equalsIgnoreCase(first, "scp")) return null;

    var parsed = ScpCommand{};
    while (tokenizer.next()) |token| {
        if (token.len > 1 and token[0] == '-') {
            var i: usize = 1;
            while (i < token.len) : (i += 1) {
                switch (token[i]) {
                    'f' => {
                        if (parsed.mode != .none and parsed.mode != .source) return null;
                        parsed.mode = .source;
                    },
                    't' => {
                        if (parsed.mode != .none and parsed.mode != .sink) return null;
                        parsed.mode = .sink;
                    },
                    'd' => parsed.target_is_dir = true,
                    'p', 'v' => {},
                    else => return null,
                }
            }
            continue;
        }
        if (parsed.remote_path.len != 0) return null;
        parsed.remote_path = token;
    }

    if (parsed.mode == .none or parsed.remote_path.len == 0) return null;
    return parsed;
}

fn startScpExec(app: *const App, stats: *ServiceStats, config: *const Config, channel: *ChannelState, buffers: *SessionBuffers, command: []const u8) bool {
    const parsed = parseScpCommand(command) orelse {
        setLastProtocolError(stats, "scp-args");
        return false;
    };
    clearScpState(channel);
    return switch (parsed.mode) {
        .source => startScpSource(app, stats, config, channel, buffers, parsed, command),
        .sink => startScpSink(app, stats, config, channel, parsed, command),
        .none => false,
    };
}

fn startScpSource(app: *const App, stats: *ServiceStats, config: *const Config, channel: *ChannelState, buffers: *SessionBuffers, parsed: ScpCommand, command: []const u8) bool {
    _ = buffers;
    var path_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    const path = resolveSshFilePath(config, parsed.remote_path, path_z[0..]) orelse {
        setLastProtocolError(stats, "scp-source-path");
        return false;
    };
    const info = app.sys.fileInfo(&path_z) orelse {
        setLastProtocolError(stats, "scp-source-missing");
        return false;
    };
    if (info.exists == 0 or info.is_dir != 0) {
        setLastProtocolError(stats, if (info.is_dir != 0) "scp-source-dir" else "scp-source-missing");
        return false;
    }
    if (info.size > @as(u64, @intCast(scp_max_file_size))) {
        setLastProtocolError(stats, "scp-source-large");
        return false;
    }

    const size: usize = @intCast(info.size);
    const info_name = spanZ(info.name[0..]);
    const file_name = if (info_name.len != 0) info_name else sftpBaseName(path);
    if (!copyScpFileName(channel.scp_name[0..], file_name)) {
        setLastProtocolError(stats, "scp-source-name");
        return false;
    }
    copyFixedZ(channel.scp_path[0..], path);
    channel.scp_started = true;
    channel.exec_started = true;
    channel.scp_mode = .source;
    channel.scp_state = .source_wait_initial_ack;
    channel.scp_expected_len = size;
    channel.scp_received_len = 0;
    channel.scp_stream_active = false;
    channel.scp_cleanup_pending = false;
    channel.scp_abort_rc = 0;
    channel.last_activity_tick = app.sys.ticks();
    channel.transfer_start_tick = channel.last_activity_tick;
    noteTransfer(stats, "scp-source", path, 0, 0, "ready");
    noteSessionKind(stats, "scp-source", command);
    stats.exec_sessions +%= 1;
    stats.scp_sessions +%= 1;
    logScpStarted(app, .source, command);
    app.sys.println("SSHD scp source started");
    return true;
}

fn startScpSink(app: *const App, stats: *ServiceStats, config: *const Config, channel: *ChannelState, parsed: ScpCommand, command: []const u8) bool {
    var path_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    const path = resolveSshFilePath(config, parsed.remote_path, path_z[0..]) orelse {
        setLastProtocolError(stats, "scp-sink-path");
        return false;
    };
    var info: r4os.abi.FileInfo = .{};
    const info_rc = app.sys.fileInfoRaw(&path_z, &info);
    if (info_rc < 0 or (info_rc > 0 and info.exists == 0)) {
        setLastProtocolError(stats, "scp-sink-lookup");
        return false;
    }
    const target_exists = info_rc > 0 and info.exists != 0;
    const target_is_dir = parsed.target_is_dir or
        pathEndsWithSeparator(parsed.remote_path) or
        (target_exists and info.is_dir != 0);
    if (target_is_dir and (!target_exists or info.is_dir == 0)) {
        setLastProtocolError(stats, "scp-sink-dir");
        return false;
    }

    copyFixedZ(channel.scp_path[0..], path);
    channel.scp_target_is_dir = target_is_dir;
    channel.scp_started = true;
    channel.exec_started = true;
    channel.scp_mode = .sink;
    channel.scp_state = .sink_wait_command;
    channel.scp_input_len = 0;
    channel.scp_expected_len = 0;
    channel.scp_received_len = 0;
    channel.scp_stream_active = false;
    channel.scp_cleanup_pending = false;
    channel.scp_failure_rc = 0;
    channel.scp_abort_rc = 0;
    channel.last_activity_tick = app.sys.ticks();
    channel.transfer_start_tick = channel.last_activity_tick;
    noteSessionKind(stats, "scp-sink", command);
    stats.exec_sessions +%= 1;
    stats.scp_sessions +%= 1;
    logScpStarted(app, .sink, command);
    app.sys.println("SSHD scp sink started");
    return true;
}

fn handleScpChannelData(app: *const App, conn_id: u32, stats: *ServiceStats, config: *const Config, key: []const u8, data: []const u8, channel: *ChannelState, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) ChannelAction {
    _ = config;
    if (data.len == 0) return .continue_session;
    stats.channel_data_in +%= @intCast(data.len);
    stats.scp_bytes_in +%= @intCast(data.len);
    channel.last_activity_tick = app.sys.ticks();
    return switch (channel.scp_mode) {
        .source => handleScpSourceData(app, conn_id, stats, key, data, channel, buffers, rng, seq_out),
        .sink => handleScpSinkData(app, conn_id, stats, key, data, channel, buffers, rng, seq_out),
        .none => .protocol_error,
    };
}

fn handleScpSourceData(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, data: []const u8, channel: *ChannelState, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) ChannelAction {
    for (data) |byte| {
        if (byte != 0) return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "client rejected scp data");
        switch (channel.scp_state) {
            .source_wait_initial_ack => {
                if (!sendScpFileHeader(app, conn_id, stats, key, buffers, rng, seq_out, channel)) return .protocol_error;
                channel.scp_state = .source_wait_header_ack;
            },
            .source_wait_header_ack => {
                if (!sendScpFileData(app, conn_id, stats, key, buffers, rng, seq_out, channel)) {
                    return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "scp source read failed");
                }
                channel.scp_state = .source_wait_final_ack;
            },
            .source_wait_final_ack => {
                stats.scp_reads +%= 1;
                channel.scp_state = .done;
                sendChannelExitAndClose(app, conn_id, key, buffers, rng, seq_out, channel, 0);
                return .close_session;
            },
            else => return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "bad scp source state"),
        }
    }
    return .continue_session;
}

fn handleScpSinkData(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, data: []const u8, channel: *ChannelState, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) ChannelAction {
    if (channel.scp_input_len + data.len > buffers.sftp_input.len) {
        return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "scp input too large");
    }
    @memcpy(buffers.sftp_input[channel.scp_input_len .. channel.scp_input_len + data.len], data);
    channel.scp_input_len += data.len;

    while (true) {
        switch (channel.scp_state) {
            .sink_wait_command => {
                const line_end = indexOfByte(buffers.sftp_input[0..channel.scp_input_len], '\n') orelse return .continue_session;
                const line = buffers.sftp_input[0..line_end];
                consumeScpInput(channel, buffers, line_end + 1);
                if (line.len == 0) continue;
                if (line[0] == 'T') {
                    if (!sendScpOk(app, conn_id, stats, key, buffers, rng, seq_out, channel)) return .protocol_error;
                    continue;
                }
                if (line[0] == 'D') {
                    return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "scp directories unsupported");
                }
                if (line[0] == 1 or line[0] == 2) {
                    return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "scp client error");
                }
                if (line[0] != 'C') {
                    return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "scp header unsupported");
                }
                const header = parseScpFileHeader(line) orelse {
                    return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "scp header invalid");
                };
                if (header.size > scp_max_file_size) {
                    return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "scp file too large");
                }
                var final_path_buf: [sftp_path_capacity]u8 = .{0} ** sftp_path_capacity;
                const final_path = buildScpTargetPath(spanZ(channel.scp_path[0..]), channel.scp_target_is_dir, header.name, final_path_buf[0..]) orelse {
                    return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "scp target invalid");
                };
                if (!copyScpFileName(channel.scp_name[0..], header.name)) {
                    return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "scp filename invalid");
                }
                noteTransfer(stats, "scp-sink", final_path, @intCast(header.size), 0, "header");
                if (isDirectSystemWriteBlocked(final_path)) {
                    noteTransfer(stats, "scp-sink", final_path, 0, 0, "blocked-system-path");
                    return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "use update inbox");
                }
                var final_path_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
                var final_info: r4os.abi.FileInfo = .{};
                copyFixedZ(final_path_z[0..], final_path);
                const final_info_rc = app.sys.fileInfoRaw(&final_path_z, &final_info);
                if (final_info_rc < 0) {
                    stats.transfer_failures +%= 1;
                    noteTransferFailure(stats, "scp-sink", final_path, 0, 0, "target-info-failed", final_info_rc, 0);
                    return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "scp target lookup failed");
                }
                // SCP sink writes are deliberately create-only. Replacing an
                // existing target would require the durable backup journal
                // owned by SYSUPD, not a compatibility-mode SCP session.
                if (final_info_rc > 0 and final_info.exists != 0) {
                    noteTransfer(stats, "scp-sink", final_path, 0, 0, "target-exists");
                    return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "scp target exists");
                }
                if (final_info_rc > 0) {
                    stats.transfer_failures +%= 1;
                    noteTransferFailure(stats, "scp-sink", final_path, 0, 0, "target-info-invalid", r4os.abi.file_stream_error_io, 0);
                    return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "scp target lookup invalid");
                }
                copyFixedZ(channel.scp_path[0..], final_path);
                const staging_rc = prepareScpStagingPaths(app, channel, final_path, conn_id);
                if (staging_rc != r4os.abi.file_stream_result_ok) {
                    stats.transfer_failures +%= 1;
                    noteTransferFailure(stats, "scp-sink", final_path, 0, 0, "stage-name-unavailable", staging_rc, 0);
                    return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "scp staging unavailable");
                }
                channel.scp_expected_len = header.size;
                channel.scp_received_len = 0;
                channel.scp_stream_active = false;
                // Arm cleanup before Begin: an I/O result may be an ambiguous
                // completion with a caller-owned StreamSlot already present.
                channel.scp_cleanup_pending = true;
                channel.scp_failure_rc = 0;
                channel.scp_abort_rc = 0;
                channel.transfer_start_tick = app.sys.ticks();
                syncSessionWatch(channel.session_slot, channel);
                var staged_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
                copyFixedZ(staged_z[0..], spanZ(channel.scp_staged_path[0..]));
                const begin_rc = app.sys.fileStreamBegin(&staged_z, r4os.abi.file_stream_open_create);
                if (begin_rc == r4os.abi.file_stream_result_ok) {
                    declareUploadPublish(app, spanZ(channel.scp_path[0..]), spanZ(channel.scp_staged_path[0..]), spanZ(channel.scp_backup_path[0..]), r4os.r4sys.file_stream_publish_protocol_scp);
                }
                if (begin_rc != r4os.abi.file_stream_result_ok) {
                    stats.transfer_failures +%= 1;
                    channel.scp_failure_rc = begin_rc;
                    if (begin_rc != r4os.abi.file_stream_error_io) {
                        channel.scp_cleanup_pending = false;
                    } else {
                        _ = cleanupScpSinkStream(app, stats, channel);
                    }
                    logTransferFailure(app, "scp-sink", final_path, 0, @intCast(channel.scp_expected_len), begin_rc, "stream-begin");
                    noteTransferFailure(stats, "scp-sink", final_path, 0, app.sys.ticks() - channel.transfer_start_tick, "stream-begin-failed", begin_rc, channel.scp_abort_rc);
                    return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "scp stream begin failed");
                }
                channel.scp_stream_active = true;
                channel.scp_cleanup_pending = true;
                markTransferProgress(app, channel);
                channel.scp_state = if (header.size == 0) .sink_wait_final_ack else .sink_read_data;
                noteTransfer(stats, "scp-sink", final_path, 0, 0, "open");
                if (!sendScpOk(app, conn_id, stats, key, buffers, rng, seq_out, channel)) return .protocol_error;
                continue;
            },
            .sink_read_data => {
                const need = channel.scp_expected_len - channel.scp_received_len;
                if (need == 0) {
                    channel.scp_state = .sink_wait_final_ack;
                    continue;
                }
                if (channel.scp_input_len == 0) return .continue_session;
                const take = @min(need, channel.scp_input_len);
                if (!channel.scp_stream_active) {
                    stats.transfer_failures +%= 1;
                    channel.scp_failure_rc = r4os.abi.file_stream_error_not_found;
                    return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "scp stream inactive");
                }
                var staged_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
                copyFixedZ(staged_z[0..], spanZ(channel.scp_staged_path[0..]));
                var stream_rc: i32 = r4os.abi.file_stream_result_ok;
                const written = writeTransferChunks(app, channel, &staged_z, @intCast(channel.scp_received_len), buffers.sftp_input[0..take], &stream_rc);
                if (written != take) {
                    stats.transfer_failures +%= 1;
                    channel.scp_received_len += written;
                    channel.scp_failure_rc = stream_rc;
                    logTransferFailure(app, "scp-sink", spanZ(channel.scp_path[0..]), @intCast(channel.scp_received_len), @intCast(take), stream_rc, "stream-write");
                    const abort_rc = cleanupScpSinkStream(app, stats, channel);
                    noteTransferFailure(stats, "scp-sink", spanZ(channel.scp_path[0..]), @intCast(channel.scp_received_len), app.sys.ticks() - channel.transfer_start_tick, "stream-write-failed", stream_rc, abort_rc);
                    return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "scp stream write failed");
                }
                channel.scp_received_len += written;
                consumeScpInput(channel, buffers, take);
                noteTransfer(stats, "scp-sink", spanZ(channel.scp_path[0..]), @intCast(channel.scp_received_len), app.sys.ticks() - channel.transfer_start_tick, "streaming");
                if (channel.scp_received_len == channel.scp_expected_len) {
                    channel.scp_state = .sink_wait_final_ack;
                    continue;
                }
                return .continue_session;
            },
            .sink_wait_final_ack => {
                if (channel.scp_input_len == 0) return .continue_session;
                const marker = buffers.sftp_input[0];
                consumeScpInput(channel, buffers, 1);
                if (marker != 0) {
                    return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "scp data not confirmed");
                }
                if (!channel.scp_stream_active or channel.scp_received_len != channel.scp_expected_len) {
                    stats.transfer_failures +%= 1;
                    channel.scp_failure_rc = r4os.abi.file_stream_error_offset_mismatch;
                    return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "scp stream inactive");
                }
                var target_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
                var staged_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
                var backup_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
                copyFixedZ(target_z[0..], spanZ(channel.scp_path[0..]));
                copyFixedZ(staged_z[0..], spanZ(channel.scp_staged_path[0..]));
                copyFixedZ(backup_z[0..], spanZ(channel.scp_backup_path[0..]));
                markTransferProgress(app, channel);
                const finish_rc = app.sys.fileStreamFinish(
                    &staged_z,
                    @intCast(channel.scp_received_len),
                    r4os.r4sys.file_stream_finish_keep_ownership,
                );
                markTransferProgress(app, channel);
                if (finish_rc != r4os.abi.file_stream_result_ok) {
                    stats.transfer_failures +%= 1;
                    channel.scp_failure_rc = finish_rc;
                    const abort_rc = cleanupScpSinkStream(app, stats, channel);
                    noteTransferFailure(stats, "scp-sink", spanZ(channel.scp_path[0..]), @intCast(channel.scp_received_len), app.sys.ticks() - channel.transfer_start_tick, "stream-finish-failed", finish_rc, abort_rc);
                    return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "scp stream finish failed");
                }
                channel.scp_cleanup_pending = true;

                const publish_flags =
                    r4os.r4sys.file_replace_atomic_flag_consume_stage |
                    r4os.r4sys.file_replace_atomic_flag_require_target_absent |
                    r4os.r4sys.file_replace_atomic_flag_require_owned_stage;
                var publish_rc = app.sys.fileReplaceAtomic(
                    &target_z,
                    &staged_z,
                    &backup_z,
                    publish_flags,
                );
                markTransferProgress(app, channel);
                if (publish_rc == r4os.r4sys.file_replace_atomic_error_io) {
                    // The kernel retains the exact StreamSlot/target tuple.
                    // One service-level retry covers an acknowledgement lost
                    // after the backend's own bounded reconciliation.
                    publish_rc = app.sys.fileReplaceAtomic(
                        &target_z,
                        &staged_z,
                        &backup_z,
                        publish_flags,
                    );
                    markTransferProgress(app, channel);
                }
                if (publish_rc != r4os.r4sys.file_replace_atomic_result_ok) {
                    channel.scp_failure_rc = publish_rc;
                    const abort_rc = cleanupScpSinkStream(app, stats, channel);
                    if (publish_rc == r4os.r4sys.file_replace_atomic_error_io and
                        abort_rc == r4os.abi.file_stream_result_ok)
                    {
                        // Ownership-aware Abort completes, rather than
                        // removes, a publication that may have crossed its
                        // visibility point.
                        noteTransfer(stats, "scp-sink", spanZ(channel.scp_path[0..]), @intCast(channel.scp_received_len), app.sys.ticks() - channel.transfer_start_tick, "ok-reconciled");
                    } else {
                        stats.transfer_failures +%= 1;
                        noteTransferFailure(
                            stats,
                            "scp-sink",
                            spanZ(channel.scp_path[0..]),
                            @intCast(channel.scp_received_len),
                            app.sys.ticks() - channel.transfer_start_tick,
                            "publish-failed",
                            publish_rc,
                            abort_rc,
                        );
                        return sendScpErrorAndClose(
                            app,
                            conn_id,
                            stats,
                            key,
                            buffers,
                            rng,
                            seq_out,
                            channel,
                            if (publish_rc == r4os.r4sys.file_replace_atomic_error_conflict) "scp target exists" else "scp atomic publish failed",
                        );
                    }
                }

                channel.scp_stream_active = false;
                channel.scp_cleanup_pending = false;
                channel.scp_failure_rc = 0;
                channel.scp_abort_rc = 0;
                copyFixedZ(channel.scp_staged_path[0..], "");
                copyFixedZ(channel.scp_backup_path[0..], "");
                stats.scp_writes +%= 1;
                noteTransfer(stats, "scp-sink", spanZ(channel.scp_path[0..]), @intCast(channel.scp_received_len), app.sys.ticks() - channel.transfer_start_tick, "ok");
                channel.scp_state = .done;
                if (!sendScpOk(app, conn_id, stats, key, buffers, rng, seq_out, channel)) return .protocol_error;
                sendChannelExitAndClose(app, conn_id, key, buffers, rng, seq_out, channel, 0);
                return .close_session;
            },
            else => return sendScpErrorAndClose(app, conn_id, stats, key, buffers, rng, seq_out, channel, "bad scp sink state"),
        }
    }
}

fn sendScpFileHeader(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, channel: *const ChannelState) bool {
    // mode + space + 20-digit size + space + maximum ABI component + LF.
    // Keep explicit slack so appendText cannot silently truncate a legal
    // long SCP filename into a different remote name.
    var header: [scp_header_capacity]u8 = .{0} ** scp_header_capacity;
    var pos: usize = 0;
    appendText(header[0..], &pos, "C0644 ");
    appendU64(header[0..], &pos, @intCast(channel.scp_expected_len));
    appendText(header[0..], &pos, " ");
    appendText(header[0..], &pos, spanZ(channel.scp_name[0..]));
    appendText(header[0..], &pos, "\n");
    return sendScpBytes(app, conn_id, stats, key, buffers, rng, seq_out, channel.client_channel, header[0..pos]);
}

fn sendScpFileData(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, channel: *ChannelState) bool {
    var path_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    copyFixedZ(path_z[0..], spanZ(channel.scp_path[0..]));
    if (channel.scp_expected_len == 0) {
        noteTransfer(stats, "scp-source", spanZ(channel.scp_path[0..]), 0, app.sys.ticks() - channel.transfer_start_tick, "ok");
        return sendScpOk(app, conn_id, stats, key, buffers, rng, seq_out, channel);
    }

    var offset: usize = 0;
    while (offset < channel.scp_expected_len) {
        const remaining = channel.scp_expected_len - offset;
        const want = @min(@min(buffers.sftp_upload.len, scp_source_data_chunk_max), remaining);
        const got_raw = app.sys.fileReadAt(&path_z, @intCast(offset), buffers.sftp_upload[0..want]);
        if (got_raw <= 0) {
            stats.transfer_failures +%= 1;
            logTransferFailure(app, "scp-source", spanZ(channel.scp_path[0..]), @intCast(offset), @intCast(want), got_raw, "read");
            noteTransfer(stats, "scp-source", spanZ(channel.scp_path[0..]), @intCast(offset), app.sys.ticks() - channel.transfer_start_tick, "read-failed");
            return false;
        }
        const got: usize = @intCast(got_raw);
        const final_chunk = offset + got >= channel.scp_expected_len;
        if (final_chunk) {
            var final_payload: [ssh_channel_output_chunk_max]u8 = .{0} ** ssh_channel_output_chunk_max;
            @memcpy(final_payload[0..got], buffers.sftp_upload[0..got]);
            final_payload[got] = 0;
            if (!sendScpBytes(app, conn_id, stats, key, buffers, rng, seq_out, channel.client_channel, final_payload[0 .. got + 1])) return false;
        } else {
            if (!sendScpBytes(app, conn_id, stats, key, buffers, rng, seq_out, channel.client_channel, buffers.sftp_upload[0..got])) return false;
        }
        offset += got;
        channel.scp_received_len = offset;
        noteTransfer(stats, "scp-source", spanZ(channel.scp_path[0..]), @intCast(offset), app.sys.ticks() - channel.transfer_start_tick, "streaming");
    }
    noteTransfer(stats, "scp-source", spanZ(channel.scp_path[0..]), @intCast(offset), app.sys.ticks() - channel.transfer_start_tick, "ok");
    return true;
}

fn sendScpOk(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, channel: *const ChannelState) bool {
    const ok = [_]u8{0};
    return sendScpBytes(app, conn_id, stats, key, buffers, rng, seq_out, channel.client_channel, ok[0..]);
}

fn sendScpErrorAndClose(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, channel: *ChannelState, message: []const u8) ChannelAction {
    setLastProtocolError(stats, message);
    abortActiveTransfers(app, stats, channel, message);
    var out: [160]u8 = .{0} ** 160;
    var pos: usize = 0;
    out[pos] = 1;
    pos += 1;
    appendText(out[0..], &pos, message);
    appendText(out[0..], &pos, "\n");
    _ = sendScpBytes(app, conn_id, stats, key, buffers, rng, seq_out, channel.client_channel, out[0..pos]);
    sendChannelExitAndClose(app, conn_id, key, buffers, rng, seq_out, channel, 1);
    channel.scp_state = .done;
    return .close_session;
}

fn sendScpBytes(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, recipient: u32, data: []const u8) bool {
    var pos: usize = 0;
    while (pos < data.len) {
        const chunk_len = @min(ssh_channel_output_chunk_max, data.len - pos);
        if (!sendChannelData(app, conn_id, key, buffers, rng, seq_out, recipient, data[pos .. pos + chunk_len])) return false;
        stats.channel_data_out +%= @intCast(chunk_len);
        stats.scp_bytes_out +%= @intCast(chunk_len);
        pos += chunk_len;
    }
    return true;
}

fn parseScpFileHeader(line: []const u8) ?ScpFileHeader {
    if (line.len < 8 or line[0] != 'C') return null;
    var i: usize = 1;
    while (i < line.len and line[i] != ' ') : (i += 1) {}
    if (i == 1 or i >= line.len) return null;
    i += 1;
    const size_start = i;
    while (i < line.len and line[i] != ' ') : (i += 1) {}
    if (i == size_start or i >= line.len) return null;
    const size = parseDecimalUsize(line[size_start..i]) orelse return null;
    i += 1;
    const name = line[i..];
    if (name.len == 0) return null;
    return .{ .size = size, .name = name };
}

fn buildScpTargetPath(base: []const u8, target_is_dir: bool, name: []const u8, out: []u8) ?[]const u8 {
    if (base.len == 0) return null;
    if (!isValidScpFileName(name)) return null;
    var pos: usize = 0;
    if (!appendChecked(out, &pos, base)) return null;
    if (target_is_dir) {
        if (pos != 0 and !isPathSeparator(out[pos - 1])) {
            if (!appendChecked(out, &pos, "\\")) return null;
        }
        if (!appendChecked(out, &pos, name)) return null;
    }
    return out[0..pos];
}

fn consumeScpInput(channel: *ChannelState, buffers: *SessionBuffers, len: usize) void {
    if (len >= channel.scp_input_len) {
        channel.scp_input_len = 0;
        return;
    }
    const remaining = channel.scp_input_len - len;
    std.mem.copyForwards(u8, buffers.sftp_input[0..remaining], buffers.sftp_input[len .. len + remaining]);
    channel.scp_input_len = remaining;
}

fn clearScpState(channel: *ChannelState) void {
    channel.scp_started = false;
    channel.scp_mode = .none;
    channel.scp_state = .none;
    channel.scp_input_len = 0;
    channel.scp_expected_len = 0;
    channel.scp_received_len = 0;
    channel.scp_stream_active = false;
    channel.scp_cleanup_pending = false;
    channel.scp_failure_rc = 0;
    channel.scp_abort_rc = 0;
    channel.scp_target_is_dir = false;
    copyFixedZ(channel.scp_path[0..], "");
    copyFixedZ(channel.scp_staged_path[0..], "");
    copyFixedZ(channel.scp_backup_path[0..], "");
    copyFixedZ(channel.scp_name[0..], "");
}

fn copyScpFileName(out: []u8, name: []const u8) bool {
    if (!isValidScpFileName(name) or name.len + 1 > out.len) return false;
    @memset(out, 0);
    @memcpy(out[0..name.len], name);
    return true;
}

fn isValidScpFileName(name: []const u8) bool {
    if (name.len == 0 or name.len >= scp_filename_capacity) return false;
    for (name) |ch| {
        if (ch == 0 or ch == '\r' or ch == '\n' or ch == ':' or isPathSeparator(ch)) return false;
    }
    return true;
}

fn pathEndsWithSeparator(path: []const u8) bool {
    const trimmed = trimSpaces(path);
    return trimmed.len != 0 and isPathSeparator(trimmed[trimmed.len - 1]);
}

fn parseDecimalUsize(text: []const u8) ?usize {
    if (text.len == 0) return null;
    var value: usize = 0;
    for (text) |ch| {
        if (ch < '0' or ch > '9') return null;
        const digit: usize = @intCast(ch - '0');
        if (value > (std.math.maxInt(usize) - digit) / 10) return null;
        value = value * 10 + digit;
    }
    return value;
}

fn indexOfByte(data: []const u8, needle: u8) ?usize {
    var i: usize = 0;
    while (i < data.len) : (i += 1) {
        if (data[i] == needle) return i;
    }
    return null;
}

fn pumpConsoleOutput(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, channel: *ChannelState) bool {
    if (!channel.shell_started or channel.shell_instance == 0) return true;
    var state: r4os.abi.ConsoleState = .{};
    const state_rc = app.sys.consoleState(channel.shell_instance, &state);
    stats.last_console_state_rc = state_rc;
    stats.last_console_state_len = state.output_len;
    stats.last_console_stream_bytes = state.stdout_bytes +% state.stderr_bytes;
    if (state_rc < 0) return false;
    const got_raw = app.sys.consoleOutput(channel.shell_instance, buffers.console_output[0..]);
    if (got_raw < 0) {
        stats.last_console_read_len = 0;
        return false;
    }
    const got: usize = @intCast(got_raw);
    stats.last_console_read_len = @intCast(@min(got, std.math.maxInt(u32)));
    const stream_bytes = state.stdout_bytes +% state.stderr_bytes;
    const stream_delta = stream_bytes -% channel.last_console_stream_bytes;
    const dropped_delta = state.output_dropped_bytes -% channel.last_output_dropped_bytes;
    const output_changed = state.clear_count != channel.last_clear_count or
        state.output_len != channel.last_output_len or
        stream_delta != 0 or
        dropped_delta != 0;
    var start: usize = @min(@as(usize, @intCast(channel.last_output_len)), got);
    var backspace_count: usize = 0;
    if (state.clear_count != channel.last_clear_count) {
        channel.last_clear_count = state.clear_count;
        start = 0;
    } else if (state.output_len < channel.last_output_len) {
        // 0.56.34e: Backspace-Echo. Der Konsolenpuffer ist GESCHRUMPFT
        // (Zeilen-Editing); frueher wurde der komplette Puffer erneut
        // gesendet und der Client haengte ihn hinten an (Termius zeigte
        // "C:\>DIRC:\>DI"). Reines Schrumpfen um N Zeichen wird jetzt als
        // N x "\b \b" (xterm-Loeschsequenz) uebertragen; nur im Mischfall
        // (gleichzeitig neue Stream-Bytes) bleibt der konservative
        // Voll-Resend.
        if (stream_delta == 0 and dropped_delta == 0) {
            backspace_count = @intCast(channel.last_output_len - state.output_len);
            start = @min(@as(usize, @intCast(state.output_len)), got);
        } else {
            start = 0;
        }
    } else if (stream_delta != 0) {
        const fresh = @min(@as(usize, @intCast(stream_delta)), got);
        const tail_start = got - fresh;
        if (tail_start < start or dropped_delta != 0) start = tail_start;
    } else if (dropped_delta != 0) {
        const fresh = @min(@as(usize, @intCast(dropped_delta)), got);
        start = got - fresh;
    }
    var pos = start;
    var sent_any = false;
    var sent_len: usize = 0;
    if (backspace_count != 0) {
        var bs_buf: [48]u8 = undefined;
        var remaining = backspace_count;
        while (remaining != 0) {
            const n = @min(remaining, bs_buf.len / 3);
            var i: usize = 0;
            while (i < n) : (i += 1) {
                bs_buf[i * 3] = 0x08;
                bs_buf[i * 3 + 1] = ' ';
                bs_buf[i * 3 + 2] = 0x08;
            }
            if (!sendChannelData(app, conn_id, key, buffers, rng, seq_out, channel.client_channel, bs_buf[0 .. n * 3])) return false;
            stats.channel_data_out +%= @intCast(n * 3);
            sent_len += n * 3;
            remaining -= n;
            sent_any = true;
        }
    }
    while (pos < got) {
        const chunk_len = @min(ssh_channel_output_chunk_max, got - pos);
        if (!sendChannelData(app, conn_id, key, buffers, rng, seq_out, channel.client_channel, buffers.console_output[pos .. pos + chunk_len])) return false;
        stats.channel_data_out +%= @intCast(chunk_len);
        sent_len += chunk_len;
        pos += chunk_len;
        sent_any = true;
    }
    stats.last_console_send_len = @intCast(@min(sent_len, std.math.maxInt(u32)));
    if (output_changed or sent_any) {
        const now = app.sys.ticks();
        channel.last_console_change_tick = now;
        channel.last_activity_tick = now;
        if (channel.exec_started and (stream_bytes != 0 or sent_any)) channel.exec_output_observed = true;
    }
    channel.last_output_len = @intCast(got);
    channel.last_console_revision = app.sys.consoleRevision(channel.shell_instance);
    channel.last_console_stream_bytes = stream_bytes;
    channel.last_output_dropped_bytes = state.output_dropped_bytes;
    return true;
}

fn drainConsoleOutput(app: *const App, conn_id: u32, endpoint_handle: u32, stats: *ServiceStats, config: *const Config, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, channel: *ChannelState) void {
    var stable: u8 = 0;
    var loops: u16 = 0;
    var last_len = channel.last_output_len;
    var last_revision = channel.last_console_revision;
    while (loops < 160 and stable < 8) : (loops += 1) {
        const endpoint_work = pumpServiceEndpointDuringSession(app, endpoint_handle, stats, config);
        if (endpoint_work != 0) app.sys.sleepTicks(1);
        const output_ok = pumpConsoleOutput(app, conn_id, stats, key, buffers, rng, seq_out, channel);
        if (!output_ok) {
            if (!pollEncryptedPacket(app, conn_id).alive) {
                stats.channel_output_failures +%= 1;
                setLastProtocolError(stats, "drain-client-disconnect");
            }
            stable = 0;
            app.sys.sleepTicks(1);
            continue;
        }
        if (endpoint_work != 0 or channel.last_output_len != last_len or channel.last_console_revision != last_revision) {
            last_len = channel.last_output_len;
            last_revision = channel.last_console_revision;
            stable = 0;
        } else {
            stable += 1;
        }
        app.sys.sleepTicks(1);
    }
    _ = pumpServiceEndpointDuringSession(app, endpoint_handle, stats, config);
    _ = pumpConsoleOutput(app, conn_id, stats, key, buffers, rng, seq_out, channel);
}

fn drainConsoleOutputForClose(app: *const App, conn_id: u32, endpoint_handle: u32, stats: *ServiceStats, config: *const Config, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, channel: *ChannelState) void {
    drainConsoleOutput(app, conn_id, endpoint_handle, stats, config, key, buffers, rng, seq_out, channel);
    var waited: u64 = 0;
    while (waited < client_flush_ticks) : (waited += 1) {
        _ = pumpServiceEndpointDuringSession(app, endpoint_handle, stats, config);
        _ = pumpConsoleOutput(app, conn_id, stats, key, buffers, rng, seq_out, channel);
        app.sys.sleepTicks(1);
    }
}

fn handleSftpChannelData(app: *const App, conn_id: u32, stats: *ServiceStats, config: *const Config, key: []const u8, data: []const u8, channel: *ChannelState, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) ChannelAction {
    if (data.len == 0) return .continue_session;
    buffers.sftp_recipient_channel = channel.client_channel;
    if (channel.sftp_input_len + data.len > buffers.sftp_input.len) {
        stats.protocol_errors +%= 1;
        setLastProtocolError(stats, "sftp-input-overflow");
        return .protocol_error;
    }
    @memcpy(buffers.sftp_input[channel.sftp_input_len .. channel.sftp_input_len + data.len], data);
    channel.sftp_input_len += data.len;
    stats.channel_data_in +%= @intCast(data.len);
    stats.sftp_bytes_in +%= @intCast(data.len);

    while (channel.sftp_input_len >= 4) {
        const packet_len_u32 = readBeU32(buffers.sftp_input[0..]);
        if (packet_len_u32 == 0 or packet_len_u32 > buffers.sftp_input.len - 4) {
            stats.protocol_errors +%= 1;
            setLastProtocolError(stats, "sftp-packet-size");
            return .protocol_error;
        }
        const packet_len: usize = @intCast(packet_len_u32);
        const total_len = 4 + packet_len;
        if (channel.sftp_input_len < total_len) break;
        const packet = buffers.sftp_input[4..total_len];
        if (!handleSftpPacket(app, conn_id, stats, config, key, packet, channel, buffers, rng, seq_out)) {
            return .protocol_error;
        }
        app.sys.taskYield();
        const remaining = channel.sftp_input_len - total_len;
        if (remaining != 0) {
            std.mem.copyForwards(u8, buffers.sftp_input[0..remaining], buffers.sftp_input[total_len .. total_len + remaining]);
        }
        channel.sftp_input_len = remaining;
    }

    channel.last_activity_tick = app.sys.ticks();
    return .continue_session;
}

fn handleSftpPacket(app: *const App, conn_id: u32, stats: *ServiceStats, config: *const Config, key: []const u8, packet: []const u8, channel: *ChannelState, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    if (packet.len == 0) {
        setLastProtocolError(stats, "sftp-empty");
        return false;
    }

    const msg = packet[0];
    var r = Reader.init(packet[1..]);
    if (msg == sftp_msg_init) {
        _ = r.readU32() orelse {
            setLastProtocolError(stats, "sftp-init");
            return false;
        };
        return sendSftpVersion(app, conn_id, stats, key, buffers, rng, seq_out);
    }

    const id = r.readU32() orelse {
        setLastProtocolError(stats, "sftp-id");
        return false;
    };

    return switch (msg) {
        sftp_msg_open => handleSftpOpen(app, conn_id, stats, config, key, &r, id, channel, buffers, rng, seq_out),
        sftp_msg_close => handleSftpClose(app, conn_id, stats, key, &r, id, channel, buffers, rng, seq_out),
        sftp_msg_read => handleSftpRead(app, conn_id, stats, key, &r, id, channel, buffers, rng, seq_out),
        sftp_msg_write => handleSftpWrite(app, conn_id, stats, key, &r, id, channel, buffers, rng, seq_out),
        sftp_msg_lstat, sftp_msg_stat => handleSftpStat(app, conn_id, stats, config, key, &r, id, buffers, rng, seq_out),
        sftp_msg_fstat => handleSftpFStat(app, conn_id, stats, key, &r, id, channel, buffers, rng, seq_out),
        sftp_msg_opendir => handleSftpOpenDir(app, conn_id, stats, config, key, &r, id, channel, buffers, rng, seq_out),
        sftp_msg_readdir => handleSftpReadDir(app, conn_id, stats, key, &r, id, channel, buffers, rng, seq_out),
        sftp_msg_remove => handleSftpRemove(app, conn_id, stats, config, key, &r, id, buffers, rng, seq_out),
        sftp_msg_realpath => handleSftpRealPath(app, conn_id, stats, config, key, &r, id, buffers, rng, seq_out),
        sftp_msg_mkdir => handleSftpMkDir(app, conn_id, stats, config, key, &r, id, buffers, rng, seq_out),
        sftp_msg_rmdir => handleSftpRmDir(app, conn_id, stats, config, key, &r, id, buffers, rng, seq_out),
        sftp_msg_rename => handleSftpRename(app, conn_id, stats, config, key, &r, id, buffers, rng, seq_out),
        sftp_msg_setstat, sftp_msg_fsetstat => sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_ok, "ignored"),
        else => sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_op_unsupported, "unsupported"),
    };
}

fn handleSftpOpen(app: *const App, conn_id: u32, stats: *ServiceStats, config: *const Config, key: []const u8, r: *Reader, id: u32, channel: *ChannelState, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    const remote_path = r.readString() orelse return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_bad_message, "bad path");
    const pflags = r.readU32() orelse return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_bad_message, "bad flags");
    if (channel.sftp_handle_kind != .none) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "handle busy");
    }

    var path_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    const path = resolveSshFilePath(config, remote_path, path_z[0..]) orelse {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_no_such_file, "bad path");
    };
    const wants_write = (pflags & sftp_pflag_write) != 0;
    const wants_read = (pflags & sftp_pflag_read) != 0;

    if (wants_write) {
        if (!sftp_write_policy.supportsSequentialWriteOpen(pflags)) {
            return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_op_unsupported, "sequential create+truncate required");
        }
        beginSftpOpenWatch(app, channel);
        defer endSftpOpenWatch(channel);
        var info: r4os.abi.FileInfo = .{};
        const info_rc = app.sys.fileInfoRaw(&path_z, &info);
        if (info_rc < 0) {
            stats.transfer_failures +%= 1;
            noteTransferFailure(stats, "sftp-write", path, 0, 0, "target-info-failed", info_rc, 0);
            return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "target lookup failed");
        }
        // SFTP uploads are deliberately create-only.  Overwrite would need a
        // durable transaction journal across the target->backup->stage chain;
        // SYSUPD owns that richer recovery contract.
        if (info_rc > 0 and info.exists != 0) {
            return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "exists");
        }
        if (info_rc > 0) {
            stats.transfer_failures +%= 1;
            noteTransferFailure(stats, "sftp-write", path, 0, 0, "target-info-invalid", r4os.abi.file_stream_error_io, 0);
            return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "target lookup invalid");
        }
        if (info.is_dir != 0) {
            return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "is directory");
        }
        if (isDirectSystemWriteBlocked(path)) {
            noteTransfer(stats, "sftp-write", path, 0, 0, "blocked-system-path");
            return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_permission_denied, "use update inbox");
        }
        copyFixedZ(channel.sftp_path[0..], path);
        const staging_rc = prepareSftpStagingPaths(app, channel, path, conn_id);
        if (staging_rc != r4os.abi.file_stream_result_ok) {
            stats.transfer_failures +%= 1;
            noteTransferFailure(stats, "sftp-write", path, 0, 0, "stage-name-unavailable", staging_rc, 0);
            clearSftpHandle(channel);
            return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "staging unavailable");
        }
        channel.sftp_handle_kind = .write_file;
        channel.sftp_upload_len = 0;
        channel.sftp_write_offset = 0;
        channel.sftp_file_size = 0;
        channel.sftp_stream_active = false;
        channel.sftp_publish_pending = false;
        channel.sftp_write_failed = false;
        // Reserve and create the private stage at OPEN, not at the first
        // WRITE/CLOSE. This closes the fileInfo-to-Begin race between SSH
        // sessions and arms the parent watchdog before storage can block.
        channel.sftp_cleanup_pending = true;
        channel.sftp_failure_rc = 0;
        channel.sftp_abort_rc = 0;
        channel.transfer_start_tick = app.sys.ticks();
        syncSessionWatch(channel.session_slot, channel);
        var staged_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
        copyFixedZ(staged_z[0..], spanZ(channel.sftp_staged_path[0..]));
        const begin_rc = app.sys.fileStreamBegin(&staged_z, r4os.abi.file_stream_open_create);
        if (begin_rc == r4os.abi.file_stream_result_ok) {
            declareUploadPublish(app, spanZ(channel.sftp_path[0..]), spanZ(channel.sftp_staged_path[0..]), spanZ(channel.sftp_backup_path[0..]), r4os.r4sys.file_stream_publish_protocol_sftp);
        }
        if (begin_rc != r4os.abi.file_stream_result_ok) {
            stats.transfer_failures +%= 1;
            if (begin_rc != r4os.abi.file_stream_error_io) channel.sftp_cleanup_pending = false;
            failSftpWrite(
                app,
                stats,
                channel,
                begin_rc,
                "stream-begin-failed",
                begin_rc == r4os.abi.file_stream_error_io,
            );
            // If Abort itself was ambiguous, retain the internal busy handle
            // and stage path. A later CLOSE/session teardown can retry, and
            // this ProgramThread's lifecycle sweep is the final backstop.
            if (!channel.sftp_cleanup_pending) clearSftpHandle(channel);
            syncSessionWatch(channel.session_slot, channel);
            return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "stream begin failed");
        }
        channel.sftp_stream_active = true;
        channel.sftp_cleanup_pending = true;
        markTransferProgress(app, channel);
        syncSessionWatch(channel.session_slot, channel);
        noteTransfer(stats, "sftp-write", path, 0, 0, "ready");
        stats.sftp_opens +%= 1;
        return sendSftpHandle(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_handle_file);
    }

    if (wants_read) {
        if (!sftp_write_policy.supportsReadOpen(pflags)) {
            return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_op_unsupported, "read-only flags required");
        }
        beginSftpOpenWatch(app, channel);
        defer endSftpOpenWatch(channel);
        var info: r4os.abi.FileInfo = .{};
        const info_rc = app.sys.fileInfoRaw(&path_z, &info);
        if (info_rc < 0) {
            return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "lookup failed");
        }
        if (info_rc == 0 or info.exists == 0) {
            return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_no_such_file, "not found");
        }
        if (info.is_dir != 0) {
            return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "is directory");
        }
        copyFixedZ(channel.sftp_path[0..], path);
        channel.sftp_handle_kind = .read_file;
        channel.sftp_upload_len = 0;
        channel.sftp_write_offset = 0;
        channel.sftp_file_size = info.size;
        channel.sftp_stream_active = false;
        channel.transfer_start_tick = app.sys.ticks();
        noteTransfer(stats, "sftp-read", path, 0, 0, "open");
        stats.sftp_opens +%= 1;
        return sendSftpHandle(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_handle_file);
    }

    return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_op_unsupported, "open flags");
}

fn handleSftpClose(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, r: *Reader, id: u32, channel: *ChannelState, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    const handle = r.readString() orelse return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_bad_message, "bad handle");
    if (!sftpHandleMatches(channel, handle)) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "bad handle");
    }

    if (channel.sftp_handle_kind == .write_file) {
        if (channel.sftp_write_failed) {
            var cleanup_rc: i32 = r4os.abi.file_stream_result_ok;
            if (sftp_write_policy.failedCloseNeedsCleanup(channel.sftp_stream_active, channel.sftp_cleanup_pending)) {
                cleanup_rc = cleanupSftpWriteStage(app, stats, channel);
            }
            if (cleanup_rc != r4os.abi.file_stream_result_ok) {
                if (!channel.sftp_cleanup_pending) clearSftpHandle(channel);
                return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "stage cleanup failed");
            }
            if (channel.sftp_abort_rc != r4os.abi.file_stream_result_ok) {
                if (!channel.sftp_cleanup_pending) clearSftpHandle(channel);
                return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "stage retained");
            }
            // WRITE already carried the primary error. A clean CLOSE must
            // retire the still-valid handle without adding a misleading
            // second "bad handle" failure.
            clearSftpHandle(channel);
            return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_ok, "failed write cleaned");
        }

        var target_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
        var staged_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
        var backup_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
        copyFixedZ(target_z[0..], spanZ(channel.sftp_path[0..]));
        copyFixedZ(staged_z[0..], spanZ(channel.sftp_staged_path[0..]));
        copyFixedZ(backup_z[0..], spanZ(channel.sftp_backup_path[0..]));
        if (!channel.sftp_publish_pending) {
            if (!channel.sftp_stream_active) {
                const begin_rc = app.sys.fileStreamBegin(&staged_z, r4os.abi.file_stream_open_create);
                if (begin_rc == r4os.abi.file_stream_result_ok) {
                    declareUploadPublish(app, spanZ(channel.sftp_path[0..]), spanZ(channel.sftp_staged_path[0..]), spanZ(channel.sftp_backup_path[0..]), r4os.r4sys.file_stream_publish_protocol_sftp);
                }
                if (begin_rc != r4os.abi.file_stream_result_ok) {
                    stats.transfer_failures +%= 1;
                    // Only an I/O ambiguity can have reserved or published this
                    // caller's stage. A deterministic EXISTS belongs to another
                    // session (or a stale file) and must never trigger Abort.
                    failSftpWrite(app, stats, channel, begin_rc, "stream-begin-failed", begin_rc == r4os.abi.file_stream_error_io);
                    if (!channel.sftp_cleanup_pending) clearSftpHandle(channel);
                    return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "stream begin failed");
                }
                channel.sftp_stream_active = true;
                channel.sftp_cleanup_pending = true;
                noteTransfer(stats, "sftp-write", spanZ(channel.sftp_path[0..]), channel.sftp_write_offset, app.sys.ticks() - channel.transfer_start_tick, "open-empty");
            }
            markTransferProgress(app, channel);
            const finish_rc = app.sys.fileStreamFinish(
                &staged_z,
                channel.sftp_write_offset,
                r4os.r4sys.file_stream_finish_keep_ownership,
            );
            markTransferProgress(app, channel);
            if (finish_rc != r4os.abi.file_stream_result_ok) {
                stats.transfer_failures +%= 1;
                failSftpWrite(app, stats, channel, finish_rc, "stream-finish-failed", true);
                if (!channel.sftp_cleanup_pending) clearSftpHandle(channel);
                return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "stream finish failed");
            }
            channel.sftp_cleanup_pending = true;
            channel.sftp_publish_pending = true;
        }

        const publish_flags =
            r4os.r4sys.file_replace_atomic_flag_consume_stage |
            r4os.r4sys.file_replace_atomic_flag_require_target_absent |
            r4os.r4sys.file_replace_atomic_flag_require_owned_stage;
        const publish_rc = app.sys.fileReplaceAtomic(
            &target_z,
            &staged_z,
            &backup_z,
            publish_flags,
        );
        if (publish_rc == r4os.r4sys.file_replace_atomic_result_ok) {
            channel.sftp_stream_active = false;
            channel.sftp_publish_pending = false;
            channel.sftp_cleanup_pending = false;
            noteTransfer(stats, "sftp-write", spanZ(channel.sftp_path[0..]), channel.sftp_write_offset, app.sys.ticks() - channel.transfer_start_tick, "ok");
            clearSftpHandle(channel);
            return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_ok, "ok");
        }

        channel.sftp_failure_rc = publish_rc;
        if (publish_rc == r4os.r4sys.file_replace_atomic_error_io) {
            // `fileStreamAbort` settles a publication whose visibility point
            // may already have been crossed. If that exact reconciliation
            // reaches its durability boundary, the CLOSE itself succeeded
            // despite the lost first acknowledgement.
            const reconcile_rc = cleanupSftpWriteStage(app, stats, channel);
            if (reconcile_rc == r4os.abi.file_stream_result_ok) {
                noteTransfer(stats, "sftp-write", spanZ(channel.sftp_path[0..]), channel.sftp_write_offset, app.sys.ticks() - channel.transfer_start_tick, "ok-reconciled");
                clearSftpHandle(channel);
                return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_ok, "ok");
            }
            stats.transfer_failures +%= 1;
            // Keep the finished StreamSlot and its exact target tuple. A
            // repeated CLOSE resumes the same backend transition.
            noteTransferFailure(
                stats,
                "sftp-write",
                spanZ(channel.sftp_path[0..]),
                channel.sftp_write_offset,
                app.sys.ticks() - channel.transfer_start_tick,
                "publish-pending",
                publish_rc,
                reconcile_rc,
            );
            syncSessionWatch(channel.session_slot, channel);
            return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "atomic publish pending");
        }
        stats.transfer_failures +%= 1;
        channel.sftp_write_failed = true;
        _ = cleanupSftpWriteStage(app, stats, channel);
        noteTransferFailure(
            stats,
            "sftp-write",
            spanZ(channel.sftp_path[0..]),
            channel.sftp_write_offset,
            app.sys.ticks() - channel.transfer_start_tick,
            "publish-failed",
            channel.sftp_failure_rc,
            channel.sftp_abort_rc,
        );
        if (!channel.sftp_cleanup_pending) clearSftpHandle(channel);
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "atomic publish failed");
    }

    clearSftpHandle(channel);
    return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_ok, "ok");
}

fn handleSftpRead(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, r: *Reader, id: u32, channel: *ChannelState, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    const handle = r.readString() orelse return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_bad_message, "bad handle");
    const offset = r.readU64() orelse return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_bad_message, "bad offset");
    const len = r.readU32() orelse return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_bad_message, "bad len");
    if (channel.sftp_handle_kind != .read_file or !bytesEq(handle, sftp_handle_file)) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "bad handle");
    }
    if (offset > std.math.maxInt(u32)) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_eof, "eof");
    }

    var path_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    copyFixedZ(path_z[0..], spanZ(channel.sftp_path[0..]));
    if (offset >= channel.sftp_file_size) return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_eof, "eof");
    const want: usize = @min(@as(usize, @intCast(len)), sftp_read_chunk_max);
    if (want == 0) return sendSftpData(app, conn_id, stats, key, buffers, rng, seq_out, id, "");
    const got_raw = app.sys.fileReadAt(&path_z, @intCast(offset), buffers.sftp_upload[0..want]);
    if (got_raw < 0) return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "read failed");
    if (got_raw == 0) return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_eof, "eof");
    const got: usize = @intCast(got_raw);
    stats.sftp_reads +%= 1;
    noteTransfer(stats, "sftp-read", spanZ(channel.sftp_path[0..]), offset + @as(u64, @intCast(got)), app.sys.ticks() - channel.transfer_start_tick, "ok");
    return sendSftpData(app, conn_id, stats, key, buffers, rng, seq_out, id, buffers.sftp_upload[0..got]);
}

fn handleSftpWrite(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, r: *Reader, id: u32, channel: *ChannelState, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    const handle = r.readString() orelse return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_bad_message, "bad handle");
    const offset = r.readU64() orelse return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_bad_message, "bad offset");
    const data = r.readString() orelse return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_bad_message, "bad data");
    if (channel.sftp_handle_kind != .write_file or !bytesEq(handle, sftp_handle_file)) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "bad handle");
    }
    if (channel.sftp_write_failed) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "write already failed");
    }
    if (channel.sftp_publish_pending) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "publish pending; close again");
    }
    if (offset != channel.sftp_write_offset) {
        stats.transfer_failures +%= 1;
        failSftpWrite(app, stats, channel, r4os.abi.file_stream_error_offset_mismatch, "offset-mismatch", sftp_write_policy.validationFailureNeedsCleanup(channel.sftp_stream_active, channel.sftp_cleanup_pending));
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "non-sequential write");
    }
    if (data.len > sftp_write_data_max) {
        stats.transfer_failures +%= 1;
        setLastProtocolError(stats, "sftp-write-too-large");
        failSftpWrite(app, stats, channel, r4os.abi.file_stream_error_too_large, "write-too-large", sftp_write_policy.validationFailureNeedsCleanup(channel.sftp_stream_active, channel.sftp_cleanup_pending));
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "write chunk too large");
    }
    if (data.len > std.math.maxInt(u32) or offset > transfer_max_file_size or @as(u64, @intCast(data.len)) > transfer_max_file_size - offset) {
        stats.transfer_failures +%= 1;
        failSftpWrite(app, stats, channel, r4os.abi.file_stream_error_too_large, "file-too-large", sftp_write_policy.validationFailureNeedsCleanup(channel.sftp_stream_active, channel.sftp_cleanup_pending));
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "file too large");
    }
    var staged_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    copyFixedZ(staged_z[0..], spanZ(channel.sftp_staged_path[0..]));
    if (!channel.sftp_stream_active) {
        const begin_rc = app.sys.fileStreamBegin(&staged_z, r4os.abi.file_stream_open_create);
        if (begin_rc == r4os.abi.file_stream_result_ok) {
            declareUploadPublish(app, spanZ(channel.sftp_path[0..]), spanZ(channel.sftp_staged_path[0..]), spanZ(channel.sftp_backup_path[0..]), r4os.r4sys.file_stream_publish_protocol_sftp);
        }
        if (begin_rc != r4os.abi.file_stream_result_ok) {
            stats.transfer_failures +%= 1;
            logTransferFailure(app, "sftp-write", spanZ(channel.sftp_path[0..]), channel.sftp_write_offset, @intCast(data.len), begin_rc, "stream-begin");
            failSftpWrite(app, stats, channel, begin_rc, "stream-begin-failed", begin_rc == r4os.abi.file_stream_error_io);
            return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "stream begin failed");
        }
        channel.sftp_stream_active = true;
        channel.sftp_cleanup_pending = true;
        noteTransfer(stats, "sftp-write", spanZ(channel.sftp_path[0..]), channel.sftp_write_offset, app.sys.ticks() - channel.transfer_start_tick, "open");
    }
    var stream_rc: i32 = r4os.abi.file_stream_result_ok;
    const written = writeTransferChunks(app, channel, &staged_z, offset, data, &stream_rc);
    if (written != data.len) {
        stats.transfer_failures +%= 1;
        channel.sftp_write_offset += @intCast(written);
        logTransferFailure(app, "sftp-write", spanZ(channel.sftp_path[0..]), channel.sftp_write_offset, @intCast(data.len), stream_rc, "stream-write");
        failSftpWrite(app, stats, channel, stream_rc, "stream-write-failed", true);
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "stream write failed");
    }
    channel.sftp_write_offset += @intCast(written);
    channel.sftp_upload_len = @intCast(@min(channel.sftp_write_offset, @as(u64, @intCast(std.math.maxInt(usize)))));
    stats.sftp_writes +%= 1;
    noteTransfer(stats, "sftp-write", spanZ(channel.sftp_path[0..]), channel.sftp_write_offset, app.sys.ticks() - channel.transfer_start_tick, "streaming");
    return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_ok, "ok");
}

fn handleSftpStat(app: *const App, conn_id: u32, stats: *ServiceStats, config: *const Config, key: []const u8, r: *Reader, id: u32, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    const remote_path = r.readString() orelse return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_bad_message, "bad path");
    var path_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    const path = resolveSshFilePath(config, remote_path, path_z[0..]) orelse {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_no_such_file, "bad path");
    };
    _ = path;
    var info: r4os.abi.FileInfo = .{};
    const info_rc = app.sys.fileInfoRaw(&path_z, &info);
    if (info_rc < 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "lookup failed");
    }
    if (info_rc == 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_no_such_file, "not found");
    }
    if (info.exists == 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "lookup invalid");
    }
    return sendSftpAttrsResponse(app, conn_id, stats, key, buffers, rng, seq_out, id, info, false);
}

fn handleSftpFStat(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, r: *Reader, id: u32, channel: *ChannelState, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    const handle = r.readString() orelse return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_bad_message, "bad handle");
    if (!sftpHandleMatches(channel, handle)) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "bad handle");
    }
    if (channel.sftp_handle_kind == .write_file) {
        var info = r4os.abi.FileInfo{ .exists = 1, .is_dir = 0, .size = channel.sftp_write_offset };
        copyFixedZ(info.name[0..], sftpBaseName(spanZ(channel.sftp_path[0..])));
        return sendSftpAttrsResponse(app, conn_id, stats, key, buffers, rng, seq_out, id, info, false);
    }
    var path_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    copyFixedZ(path_z[0..], spanZ(channel.sftp_path[0..]));
    var info: r4os.abi.FileInfo = .{};
    const info_rc = app.sys.fileInfoRaw(&path_z, &info);
    if (info_rc < 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "lookup failed");
    }
    if (info_rc == 0 or info.exists == 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_no_such_file, "not found");
    }
    return sendSftpAttrsResponse(app, conn_id, stats, key, buffers, rng, seq_out, id, info, channel.sftp_handle_kind == .dir);
}

fn handleSftpOpenDir(app: *const App, conn_id: u32, stats: *ServiceStats, config: *const Config, key: []const u8, r: *Reader, id: u32, channel: *ChannelState, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    const remote_path = r.readString() orelse return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_bad_message, "bad path");
    if (channel.sftp_handle_kind != .none) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "handle busy");
    }
    var path_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    const path = resolveSshFilePath(config, remote_path, path_z[0..]) orelse {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_no_such_file, "bad path");
    };
    var info: r4os.abi.FileInfo = .{};
    const info_rc = app.sys.fileInfoRaw(&path_z, &info);
    if (info_rc < 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "lookup failed");
    }
    if (info_rc == 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_no_such_file, "not found");
    }
    if (info.exists == 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "lookup invalid");
    }
    if (info.is_dir == 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_no_such_file, "not directory");
    }
    copyFixedZ(channel.sftp_path[0..], path);
    channel.sftp_handle_kind = .dir;
    channel.sftp_dir_index = 2;
    stats.sftp_opens +%= 1;
    return sendSftpHandle(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_handle_dir);
}

fn handleSftpReadDir(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, r: *Reader, id: u32, channel: *ChannelState, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    const handle = r.readString() orelse return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_bad_message, "bad handle");
    if (channel.sftp_handle_kind != .dir or !bytesEq(handle, sftp_handle_dir)) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "bad handle");
    }

    var path_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    copyFixedZ(path_z[0..], spanZ(channel.sftp_path[0..]));
    stats.sftp_readdirs +%= 1;

    var w = Writer.init(buffers.sftp_output[4..]);
    if (!w.byte(sftp_msg_name)) return false;
    if (!w.beU32(id)) return false;
    const count_pos = w.pos;
    if (!w.beU32(0)) return false;

    var index = channel.sftp_dir_index;
    var count: u32 = 0;
    while (count < sftp_readdir_batch_max) {
        var entry_path_buf: [sftp_path_capacity]u8 = .{0} ** sftp_path_capacity;
        const kind = app.sys.dirEntry(&path_z, index, entry_path_buf[0 .. entry_path_buf.len - 1]);
        if (kind == r4os.r4sys.dir_entry_result_end) break;
        if (kind < 0) {
            return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "directory read failed");
        }
        const next_index = index + 1;
        const entry_path = spanZ(entry_path_buf[0..]);
        const name = sftpBaseName(entry_path);
        if (name.len == 0) {
            index = next_index;
            continue;
        }

        var entry_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
        copyFixedZ(entry_z[0..], entry_path);
        var info: r4os.abi.FileInfo = .{};
        const info_rc = app.sys.fileInfoRaw(&entry_z, &info);
        if (info_rc < 0) {
            return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "entry lookup failed");
        }
        if (info_rc == 0 or info.exists == 0) {
            // A sibling can disappear between enumeration and metadata lookup.
            // Skip it, but never turn a storage error into fabricated attrs.
            index = next_index;
            continue;
        }
        if (info.name[0] == 0) copyFixedZ(info.name[0..], name);

        var long_buf: [192]u8 = .{0} ** 192;
        const long_name = buildSftpLongName(name, info, kind == 1, long_buf[0..]);
        var entry_buf: [512]u8 = .{0} ** 512;
        var entry_w = Writer.init(entry_buf[0..]);
        if (!entry_w.string(name)) return false;
        if (!entry_w.string(long_name)) return false;
        if (!writeSftpAttrs(&entry_w, info, kind == 1)) return false;
        if (w.pos + entry_w.pos > w.buf.len) break;
        if (!w.bytes(entry_w.slice())) return false;

        index = next_index;
        count += 1;
    }

    channel.sftp_dir_index = index;
    if (count == 0) return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_eof, "eof");
    writeBeU32(w.buf[count_pos..], count);
    return sendSftpPrepared(app, conn_id, stats, key, buffers, rng, seq_out, w.pos);
}

fn handleSftpRealPath(app: *const App, conn_id: u32, stats: *ServiceStats, config: *const Config, key: []const u8, r: *Reader, id: u32, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    const remote_path = r.readString() orelse return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_bad_message, "bad path");
    var path_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    const path = resolveSshFilePath(config, remote_path, path_z[0..]) orelse {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_no_such_file, "bad path");
    };
    var canonical_buf: [sftp_path_capacity]u8 = .{0} ** sftp_path_capacity;
    const canonical = r4PathToSftpPath(path, canonical_buf[0..]) orelse default_sftp_root;
    var info: r4os.abi.FileInfo = .{};
    const info_rc = app.sys.fileInfoRaw(&path_z, &info);
    if (info_rc < 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "lookup failed");
    }
    if (info_rc == 0 or info.exists == 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_no_such_file, "not found");
    }
    return sendSftpNameOne(app, conn_id, stats, key, buffers, rng, seq_out, id, canonical, info, info.is_dir != 0);
}

fn handleSftpMkDir(app: *const App, conn_id: u32, stats: *ServiceStats, config: *const Config, key: []const u8, r: *Reader, id: u32, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    const remote_path = r.readString() orelse return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_bad_message, "bad path");
    _ = r.readU32() orelse 0;
    var path_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    const path = resolveSshFilePath(config, remote_path, path_z[0..]) orelse {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_no_such_file, "bad path");
    };
    if (isDirectoryCreateBlocked(path)) {
        noteTransfer(stats, "sftp-mkdir", path, 0, 0, "blocked-system-path");
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_permission_denied, "use update inbox");
    }
    const rc = app.sys.dirCreate(&path_z);
    noteTransfer(stats, "sftp-mkdir", path, 0, 0, if (rc > 0) "ok" else "failed");
    return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, if (rc > 0) sftp_status_ok else sftp_status_failure, if (rc > 0) "ok" else "mkdir failed");
}

fn handleSftpRemove(app: *const App, conn_id: u32, stats: *ServiceStats, config: *const Config, key: []const u8, r: *Reader, id: u32, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    const remote_path = r.readString() orelse return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_bad_message, "bad path");
    var path_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    const path = resolveSshFilePath(config, remote_path, path_z[0..]) orelse {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_no_such_file, "bad path");
    };
    if (isDirectSystemWriteBlocked(path)) {
        noteTransfer(stats, "sftp-remove", path, 0, 0, "blocked-system-path");
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_permission_denied, "use update inbox");
    }
    var info: r4os.abi.FileInfo = .{};
    const info_rc = app.sys.fileInfoRaw(&path_z, &info);
    if (info_rc < 0) {
        noteTransferFailure(stats, "sftp-remove", path, 0, 0, "lookup-failed", info_rc, 0);
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "lookup failed");
    }
    if (info_rc == 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_no_such_file, "not found");
    }
    if (info.exists == 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "lookup invalid");
    }
    if (info.is_dir != 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "is directory");
    }
    const rc = app.sys.fileDelete(&path_z);
    if (rc > 0) stats.sftp_removes +%= 1;
    noteTransfer(stats, "sftp-remove", path, 0, 0, if (rc > 0) "ok" else "failed");
    return sendSftpStatus(
        app,
        conn_id,
        stats,
        key,
        buffers,
        rng,
        seq_out,
        id,
        if (rc > 0) sftp_status_ok else if (rc == 0) sftp_status_no_such_file else sftp_status_failure,
        if (rc > 0) "ok" else if (rc == 0) "not found" else "remove failed",
    );
}

fn handleSftpRmDir(app: *const App, conn_id: u32, stats: *ServiceStats, config: *const Config, key: []const u8, r: *Reader, id: u32, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    const remote_path = r.readString() orelse return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_bad_message, "bad path");
    var path_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    const path = resolveSshFilePath(config, remote_path, path_z[0..]) orelse {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_no_such_file, "bad path");
    };
    if (isDirectSystemWriteBlocked(path)) {
        noteTransfer(stats, "sftp-rmdir", path, 0, 0, "blocked-system-path");
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_permission_denied, "use update inbox");
    }
    var info: r4os.abi.FileInfo = .{};
    const info_rc = app.sys.fileInfoRaw(&path_z, &info);
    if (info_rc < 0) {
        noteTransferFailure(stats, "sftp-rmdir", path, 0, 0, "lookup-failed", info_rc, 0);
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "lookup failed");
    }
    if (info_rc == 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_no_such_file, "not found");
    }
    if (info.exists == 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "lookup invalid");
    }
    if (info.is_dir == 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "not directory");
    }
    const rc = app.sys.dirDelete(&path_z);
    if (rc > 0) stats.sftp_removes +%= 1;
    noteTransfer(stats, "sftp-rmdir", path, 0, 0, if (rc > 0) "ok" else "failed");
    return sendSftpStatus(
        app,
        conn_id,
        stats,
        key,
        buffers,
        rng,
        seq_out,
        id,
        if (rc > 0) sftp_status_ok else if (rc == 0) sftp_status_no_such_file else sftp_status_failure,
        if (rc > 0) "ok" else if (rc == 0) "not found" else "rmdir failed",
    );
}

fn handleSftpRename(app: *const App, conn_id: u32, stats: *ServiceStats, config: *const Config, key: []const u8, r: *Reader, id: u32, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    const old_remote = r.readString() orelse return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_bad_message, "bad old path");
    const new_remote = r.readString() orelse return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_bad_message, "bad new path");
    var old_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    var new_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    const old_path = resolveSshFilePath(config, old_remote, old_z[0..]) orelse {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_no_such_file, "bad old path");
    };
    const new_path = resolveSshFilePath(config, new_remote, new_z[0..]) orelse {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_no_such_file, "bad new path");
    };
    if (isDirectSystemWriteBlocked(old_path) or isDirectSystemWriteBlocked(new_path)) {
        noteTransfer(stats, "sftp-rename", new_path, 0, 0, "blocked-system-path");
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_permission_denied, "use update inbox");
    }
    var old_info: r4os.abi.FileInfo = .{};
    const old_info_rc = app.sys.fileInfoRaw(&old_z, &old_info);
    if (old_info_rc < 0) {
        noteTransferFailure(stats, "sftp-rename", old_path, 0, 0, "source-lookup-failed", old_info_rc, 0);
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "source lookup failed");
    }
    if (old_info_rc == 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_no_such_file, "source not found");
    }
    if (old_info.exists == 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "source lookup invalid");
    }
    var new_info: r4os.abi.FileInfo = .{};
    const new_info_rc = app.sys.fileInfoRaw(&new_z, &new_info);
    if (new_info_rc < 0) {
        noteTransferFailure(stats, "sftp-rename", new_path, 0, 0, "target-lookup-failed", new_info_rc, 0);
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "target lookup failed");
    }
    if (new_info_rc > 0 and new_info.exists != 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "target exists");
    }
    if (new_info_rc > 0) {
        return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, sftp_status_failure, "target lookup invalid");
    }
    const rc = app.sys.fileRename(&old_z, &new_z);
    if (rc > 0) stats.sftp_renames +%= 1;
    noteTransfer(stats, "sftp-rename", new_path, 0, 0, if (rc > 0) "ok" else "failed");
    return sendSftpStatus(app, conn_id, stats, key, buffers, rng, seq_out, id, if (rc > 0) sftp_status_ok else sftp_status_failure, if (rc > 0) "ok" else "rename failed");
}

fn sendSftpVersion(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    var w = Writer.init(buffers.sftp_output[4..]);
    if (!w.byte(sftp_msg_version)) return false;
    if (!w.beU32(sftp_version)) return false;
    return sendSftpPrepared(app, conn_id, stats, key, buffers, rng, seq_out, w.pos);
}

fn sendSftpStatus(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, id: u32, code: u32, message: []const u8) bool {
    var w = Writer.init(buffers.sftp_output[4..]);
    if (!w.byte(sftp_msg_status)) return false;
    if (!w.beU32(id)) return false;
    if (!w.beU32(code)) return false;
    if (!w.string(message)) return false;
    if (!w.string("")) return false;
    return sendSftpPrepared(app, conn_id, stats, key, buffers, rng, seq_out, w.pos);
}

fn sendSftpHandle(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, id: u32, handle: []const u8) bool {
    var w = Writer.init(buffers.sftp_output[4..]);
    if (!w.byte(sftp_msg_handle)) return false;
    if (!w.beU32(id)) return false;
    if (!w.string(handle)) return false;
    return sendSftpPrepared(app, conn_id, stats, key, buffers, rng, seq_out, w.pos);
}

fn sendSftpData(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, id: u32, data: []const u8) bool {
    var w = Writer.init(buffers.sftp_output[4..]);
    if (!w.byte(sftp_msg_data)) return false;
    if (!w.beU32(id)) return false;
    if (!w.string(data)) return false;
    return sendSftpPrepared(app, conn_id, stats, key, buffers, rng, seq_out, w.pos);
}

fn sendSftpAttrsResponse(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, id: u32, info: r4os.abi.FileInfo, synth_dir: bool) bool {
    var w = Writer.init(buffers.sftp_output[4..]);
    if (!w.byte(sftp_msg_attrs)) return false;
    if (!w.beU32(id)) return false;
    if (!writeSftpAttrs(&w, info, synth_dir)) return false;
    return sendSftpPrepared(app, conn_id, stats, key, buffers, rng, seq_out, w.pos);
}

fn sendSftpNameOne(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, id: u32, name: []const u8, info: r4os.abi.FileInfo, synth_dir: bool) bool {
    var long_buf: [192]u8 = .{0} ** 192;
    const long_name = buildSftpLongName(name, info, synth_dir, long_buf[0..]);
    var w = Writer.init(buffers.sftp_output[4..]);
    if (!w.byte(sftp_msg_name)) return false;
    if (!w.beU32(id)) return false;
    if (!w.beU32(1)) return false;
    if (!w.string(name)) return false;
    if (!w.string(long_name)) return false;
    if (!writeSftpAttrs(&w, info, synth_dir)) return false;
    return sendSftpPrepared(app, conn_id, stats, key, buffers, rng, seq_out, w.pos);
}

fn sendSftpPrepared(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, body_len: usize) bool {
    if (body_len + 4 > buffers.sftp_output.len or body_len > std.math.maxInt(u32)) {
        setLastProtocolError(stats, "sftp-out-size");
        return false;
    }
    writeBeU32(buffers.sftp_output[0..], @intCast(body_len));
    const packet = buffers.sftp_output[0 .. body_len + 4];
    var pos: usize = 0;
    while (pos < packet.len) {
        const chunk_len = @min(ssh_channel_output_chunk_max, packet.len - pos);
        if (!sendChannelData(app, conn_id, key, buffers, rng, seq_out, buffers.sftp_recipient_channel, packet[pos .. pos + chunk_len])) {
            setLastProtocolError(stats, "sftp-send");
            return false;
        }
        stats.channel_data_out +%= @intCast(chunk_len);
        stats.sftp_bytes_out +%= @intCast(chunk_len);
        pos += chunk_len;
    }
    return true;
}

fn writeSftpAttrs(w: *Writer, info: r4os.abi.FileInfo, synth_dir: bool) bool {
    const is_dir = synth_dir or info.is_dir != 0;
    if (!w.beU32(sftp_attr_size | sftp_attr_permissions | sftp_attr_acmodtime)) return false;
    if (!w.beU64(if (is_dir) 0 else info.size)) return false;
    if (!w.beU32(if (is_dir) sftp_perm_dir else sftp_perm_file)) return false;
    if (!w.beU32(0)) return false;
    if (!w.beU32(0)) return false;
    return true;
}

fn buildSftpLongName(name: []const u8, info: r4os.abi.FileInfo, synth_dir: bool, out: []u8) []const u8 {
    var pos: usize = 0;
    const is_dir = synth_dir or info.is_dir != 0;
    appendText(out, &pos, if (is_dir) "drwxrwxrwx" else "-rw-rw-rw-");
    appendText(out, &pos, " 1 r4os r4os ");
    appendU64(out, &pos, if (is_dir) 0 else info.size);
    appendText(out, &pos, " Jan 01  1980 ");
    appendText(out, &pos, name);
    return out[0..pos];
}

fn sftpHandleMatches(channel: *const ChannelState, handle: []const u8) bool {
    return switch (channel.sftp_handle_kind) {
        .read_file, .write_file => bytesEq(handle, sftp_handle_file),
        .dir => bytesEq(handle, sftp_handle_dir),
        .none => false,
    };
}

fn beginSftpOpenWatch(app: *const App, channel: *ChannelState) void {
    channel.sftp_open_pending = true;
    channel.last_activity_tick = app.sys.ticks();
    syncSessionWatch(channel.session_slot, channel);
}

fn endSftpOpenWatch(channel: *ChannelState) void {
    channel.sftp_open_pending = false;
    syncSessionWatch(channel.session_slot, channel);
}

/// Declares the create-only publish intent right after the stage stream was
/// opened (0.60.30), so the durable claim brackets the WHOLE transfer.
///
/// Before this the claim only appeared at the final hand-over, which meant a
/// reset while the payload was still streaming left a stage file that nothing
/// could attribute or remove.
///
/// Deliberately FAIL-SOFT: if the declaration cannot be made the upload still
/// proceeds exactly as it did before, just without the recovery bracket.  A
/// hard failure here would turn a hygiene improvement into an outage of the
/// upload path.
fn declareUploadPublish(
    app: *const App,
    target: []const u8,
    staged: []const u8,
    backup: []const u8,
    protocol: u32,
) void {
    if (target.len == 0 or staged.len == 0 or backup.len == 0) return;
    var target_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    var staged_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    var backup_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    copyFixedZ(target_z[0..], target);
    copyFixedZ(staged_z[0..], staged);
    copyFixedZ(backup_z[0..], backup);
    _ = app.sys.fileStreamDeclarePublish(&staged_z, &target_z, &backup_z, protocol);
}

fn prepareSftpStagingPaths(app: *const App, channel: *ChannelState, target: []const u8, conn_id: u32) i32 {
    var attempt: u32 = 0;
    while (attempt < 16) : (attempt += 1) {
        const nonce = nextSftpStageNonce(app, conn_id);
        if (!buildSftpSiblingPath(target, 'S', nonce, "TMP", channel.sftp_staged_path[0..])) continue;
        if (!buildSftpSiblingPath(target, 'B', nonce, "BAK", channel.sftp_backup_path[0..])) continue;
        const staged = spanZ(channel.sftp_staged_path[0..]);
        const backup = spanZ(channel.sftp_backup_path[0..]);
        if (equalsIgnoreCase(target, staged) or equalsIgnoreCase(target, backup)) continue;

        var staged_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
        var backup_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
        var info: r4os.abi.FileInfo = .{};
        copyFixedZ(staged_z[0..], staged);
        const staged_rc = app.sys.fileInfoRaw(&staged_z, &info);
        if (staged_rc < 0) {
            copyFixedZ(channel.sftp_staged_path[0..], "");
            copyFixedZ(channel.sftp_backup_path[0..], "");
            return staged_rc;
        }
        if (staged_rc != 0) continue;
        info = .{};
        copyFixedZ(backup_z[0..], backup);
        const backup_rc = app.sys.fileInfoRaw(&backup_z, &info);
        if (backup_rc < 0) {
            copyFixedZ(channel.sftp_staged_path[0..], "");
            copyFixedZ(channel.sftp_backup_path[0..], "");
            return backup_rc;
        }
        if (backup_rc != 0) continue;
        return r4os.abi.file_stream_result_ok;
    }
    copyFixedZ(channel.sftp_staged_path[0..], "");
    copyFixedZ(channel.sftp_backup_path[0..], "");
    return r4os.abi.file_stream_error_io;
}

fn prepareScpStagingPaths(app: *const App, channel: *ChannelState, target: []const u8, conn_id: u32) i32 {
    var attempt: u32 = 0;
    while (attempt < 16) : (attempt += 1) {
        const nonce = nextSftpStageNonce(app, conn_id);
        if (!buildSftpSiblingPath(target, 'P', nonce, "TMP", channel.scp_staged_path[0..])) continue;
        if (!buildSftpSiblingPath(target, 'Q', nonce, "BAK", channel.scp_backup_path[0..])) continue;
        const staged = spanZ(channel.scp_staged_path[0..]);
        const backup = spanZ(channel.scp_backup_path[0..]);
        if (equalsIgnoreCase(target, staged) or
            equalsIgnoreCase(target, backup) or
            equalsIgnoreCase(staged, backup))
            continue;

        var staged_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
        var backup_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
        var info: r4os.abi.FileInfo = .{};
        copyFixedZ(staged_z[0..], staged);
        const staged_rc = app.sys.fileInfoRaw(&staged_z, &info);
        if (staged_rc < 0) {
            copyFixedZ(channel.scp_staged_path[0..], "");
            copyFixedZ(channel.scp_backup_path[0..], "");
            return staged_rc;
        }
        if (staged_rc != 0) continue;
        info = .{};
        copyFixedZ(backup_z[0..], backup);
        const backup_rc = app.sys.fileInfoRaw(&backup_z, &info);
        if (backup_rc < 0) {
            copyFixedZ(channel.scp_staged_path[0..], "");
            copyFixedZ(channel.scp_backup_path[0..], "");
            return backup_rc;
        }
        if (backup_rc != 0) continue;
        return r4os.abi.file_stream_result_ok;
    }
    copyFixedZ(channel.scp_staged_path[0..], "");
    copyFixedZ(channel.scp_backup_path[0..], "");
    return r4os.abi.file_stream_error_io;
}

fn nextSftpStageNonce(app: *const App, conn_id: u32) u32 {
    acquireAtomicLock(app, &sftp_stage_nonce_lock);
    sftp_stage_nonce +%= 1;
    if (sftp_stage_nonce == 0) sftp_stage_nonce = 1;
    const sequence = sftp_stage_nonce;
    releaseAtomicLock(&sftp_stage_nonce_lock);
    var out = (sequence ^ (conn_id *% 0x09E3_779B)) & 0x0FFF_FFFF;
    if (out == 0) out = 1;
    return out;
}

fn buildSftpSiblingPath(target: []const u8, prefix: u8, nonce: u32, extension: []const u8, out: []u8) bool {
    if (extension.len != 3 or out.len == 0) return false;
    var parent_len: usize = 0;
    for (target, 0..) |ch, index| {
        if (ch == '\\' or ch == '/') parent_len = index + 1;
    }
    const short_name_len: usize = 12; // Sxxxxxxx.TMP
    if (parent_len == 0 or parent_len + short_name_len >= out.len) return false;
    @memset(out, 0);
    @memcpy(out[0..parent_len], target[0..parent_len]);
    var pos = parent_len;
    out[pos] = prefix;
    pos += 1;
    const digits = "0123456789ABCDEF";
    var value = nonce & 0x0FFF_FFFF;
    var hex_pos: usize = 7;
    while (hex_pos > 0) {
        hex_pos -= 1;
        out[pos + hex_pos] = digits[@intCast(value & 0x0F)];
        value >>= 4;
    }
    pos += 7;
    out[pos] = '.';
    pos += 1;
    @memcpy(out[pos .. pos + extension.len], extension);
    return true;
}

fn cleanupSftpWriteStage(app: *const App, stats: *ServiceStats, channel: *ChannelState) i32 {
    if (!channel.sftp_stream_active and !channel.sftp_cleanup_pending) return r4os.abi.file_stream_result_ok;
    const staged = spanZ(channel.sftp_staged_path[0..]);
    if (staged.len == 0) {
        channel.sftp_stream_active = false;
        channel.sftp_publish_pending = false;
        channel.sftp_cleanup_pending = false;
        return r4os.abi.file_stream_result_ok;
    }

    var staged_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    copyFixedZ(staged_z[0..], staged);
    stats.transfer_aborts +%= 1;
    channel.sftp_abort_rc = app.sys.fileStreamAbort(&staged_z);
    // Abort is the sole cleanup authority. It either removes the exact owned
    // stage or, after an ambiguous publish, relinquishes only the in-memory
    // slot and deliberately leaves private aliases for diagnosis.
    if (channel.sftp_abort_rc == r4os.abi.file_stream_result_ok or
        channel.sftp_abort_rc == r4os.abi.file_stream_error_not_found)
    {
        channel.sftp_stream_active = false;
        channel.sftp_publish_pending = false;
        channel.sftp_cleanup_pending = false;
        // NOT_FOUND means there is no caller-owned StreamSlot left. Treat it
        // as idempotent cleanup success rather than retaining a dead handle.
        channel.sftp_abort_rc = r4os.abi.file_stream_result_ok;
        return r4os.abi.file_stream_result_ok;
    }
    // An early R4SYS I/O failure may have happened before the slot was
    // inspected. Keep the exact path and ownership state retryable.
    channel.sftp_cleanup_pending = true;
    return channel.sftp_abort_rc;
}

fn failSftpWrite(app: *const App, stats: *ServiceStats, channel: *ChannelState, failure_rc: i32, reason: []const u8, stage_may_exist: bool) void {
    channel.sftp_write_failed = true;
    channel.sftp_failure_rc = failure_rc;
    channel.sftp_abort_rc = 0;
    if (stage_may_exist) channel.sftp_cleanup_pending = true;
    if (channel.sftp_stream_active or channel.sftp_cleanup_pending) {
        _ = cleanupSftpWriteStage(app, stats, channel);
    }
    noteTransferFailure(
        stats,
        "sftp-write",
        spanZ(channel.sftp_path[0..]),
        channel.sftp_write_offset,
        app.sys.ticks() - channel.transfer_start_tick,
        reason,
        failure_rc,
        channel.sftp_abort_rc,
    );
}

fn clearSftpHandle(channel: *ChannelState) void {
    channel.sftp_handle_kind = .none;
    channel.sftp_upload_len = 0;
    channel.sftp_write_offset = 0;
    channel.sftp_file_size = 0;
    channel.sftp_open_pending = false;
    channel.sftp_stream_active = false;
    channel.sftp_publish_pending = false;
    channel.sftp_write_failed = false;
    channel.sftp_cleanup_pending = false;
    channel.sftp_failure_rc = 0;
    channel.sftp_abort_rc = 0;
    channel.sftp_dir_index = 0;
    copyFixedZ(channel.sftp_path[0..], "");
    copyFixedZ(channel.sftp_staged_path[0..], "");
    copyFixedZ(channel.sftp_backup_path[0..], "");
}

fn cleanupScpSinkStream(app: *const App, stats: *ServiceStats, channel: *ChannelState) i32 {
    if (!channel.scp_stream_active and !channel.scp_cleanup_pending) return r4os.abi.file_stream_result_ok;
    const staged = spanZ(channel.scp_staged_path[0..]);
    if (staged.len == 0) {
        channel.scp_cleanup_pending = true;
        channel.scp_abort_rc = r4os.abi.file_stream_error_io;
        return channel.scp_abort_rc;
    }

    var staged_z: [sftp_path_capacity:0]u8 = .{0} ** sftp_path_capacity;
    copyFixedZ(staged_z[0..], staged);
    stats.transfer_aborts +%= 1;
    markTransferProgress(app, channel);
    channel.scp_abort_rc = app.sys.fileStreamAbort(&staged_z);
    markTransferProgress(app, channel);
    if (channel.scp_abort_rc == r4os.abi.file_stream_result_ok or
        channel.scp_abort_rc == r4os.abi.file_stream_error_not_found)
    {
        channel.scp_stream_active = false;
        channel.scp_cleanup_pending = false;
        channel.scp_abort_rc = r4os.abi.file_stream_result_ok;
        return r4os.abi.file_stream_result_ok;
    }

    // Preserve the exact path and retry claim. Session teardown retries an
    // ambiguous abort; ProgramThread retirement remains the final owner sweep.
    channel.scp_cleanup_pending = true;
    return channel.scp_abort_rc;
}

fn abortActiveTransfers(app: *const App, stats: *ServiceStats, channel: *ChannelState, reason: []const u8) void {
    if (channel.sftp_stream_active or channel.sftp_cleanup_pending) {
        const cleanup_rc = cleanupSftpWriteStage(app, stats, channel);
        noteTransferFailure(
            stats,
            "sftp-write",
            spanZ(channel.sftp_path[0..]),
            channel.sftp_write_offset,
            app.sys.ticks() - channel.transfer_start_tick,
            reason,
            if (channel.sftp_failure_rc != 0) channel.sftp_failure_rc else cleanup_rc,
            channel.sftp_abort_rc,
        );
        if (cleanup_rc != r4os.abi.file_stream_result_ok) stats.transfer_failures +%= 1;
    }
    if (channel.scp_stream_active or channel.scp_cleanup_pending) {
        const cleanup_rc = cleanupScpSinkStream(app, stats, channel);
        noteTransferFailure(
            stats,
            "scp-sink",
            spanZ(channel.scp_path[0..]),
            @intCast(channel.scp_received_len),
            app.sys.ticks() - channel.transfer_start_tick,
            reason,
            if (channel.scp_failure_rc != 0) channel.scp_failure_rc else cleanup_rc,
            channel.scp_abort_rc,
        );
        if (cleanup_rc != r4os.abi.file_stream_result_ok) stats.transfer_failures +%= 1;
    } else if (channel.scp_started and channel.scp_mode == .sink and channel.scp_state != .none and channel.scp_state != .done) {
        stats.transfer_aborts +%= 1;
        noteTransfer(stats, "scp-sink", spanZ(channel.scp_path[0..]), @intCast(channel.scp_received_len), app.sys.ticks() - channel.transfer_start_tick, reason);
        channel.scp_state = .done;
    }
}

fn writeTransferChunks(app: *const App, channel: *ChannelState, path: [*:0]const u8, start_offset: u64, data: []const u8, last_rc: *i32) usize {
    var pos: usize = 0;
    last_rc.* = r4os.abi.file_stream_result_ok;
    while (pos < data.len) {
        markTransferProgress(app, channel);
        app.sys.taskYield();
        const chunk_len = @min(transfer_stream_chunk_max, data.len - pos);
        const rc = app.sys.fileStreamWrite(path, start_offset + @as(u64, @intCast(pos)), data[pos .. pos + chunk_len], 0);
        markTransferProgress(app, channel);
        last_rc.* = rc;
        if (rc < 0) return pos;
        const written: usize = @intCast(rc);
        if (written != chunk_len) {
            last_rc.* = r4os.abi.file_stream_error_io;
            return pos + @min(written, chunk_len);
        }
        pos += chunk_len;
        cooperateAfterTransferChunk(app, start_offset + @as(u64, @intCast(pos)));
    }
    return pos;
}

fn cooperateAfterTransferChunk(app: *const App, next_offset: u64) void {
    if (next_offset != 0 and next_offset % transfer_sleep_stride == 0) {
        app.sys.sleepTicks(1);
    } else {
        app.sys.taskYield();
    }
}

fn markTransferProgress(app: *const App, channel: *ChannelState) void {
    const now = app.sys.ticks();
    channel.last_activity_tick = now;
    if (channel.session_slot) |slot| {
        @atomicStore(u64, &slot.last_activity_tick, now, .release);
    }
}

fn logTransferFailure(app: *const App, kind: []const u8, path: []const u8, offset: u64, len: u64, rc: i32, reason: []const u8) void {
    app.sys.write("SSHD transfer fail kind=");
    app.sys.write(kind);
    app.sys.write(" reason=");
    app.sys.write(reason);
    app.sys.write(" rc=");
    app.sys.printI32(rc);
    app.sys.write(" offset=");
    app.sys.printU64(offset);
    app.sys.write(" len=");
    app.sys.printU64(len);
    app.sys.write(" path=");
    app.sys.println(path);
}

fn noteTransfer(stats: *ServiceStats, kind: []const u8, path: []const u8, bytes: u64, ticks: u64, result: []const u8) void {
    noteTransferResult(stats, kind, path, bytes, ticks, result, 0, 0);
}

fn noteTransferResult(
    stats: *ServiceStats,
    kind: []const u8,
    path: []const u8,
    bytes: u64,
    ticks: u64,
    result: []const u8,
    failure_rc: i32,
    abort_rc: i32,
) void {
    const sequence = @atomicRmw(u64, &transfer_event_sequence, .Add, 1, .acq_rel) +% 1;
    acquireTransferRecordLock(stats);
    defer releaseTransferRecordLock(stats);
    copyFixedZ(stats.last_transfer_kind[0..], kind);
    copyFixedZ(stats.last_transfer_path[0..], path);
    copyFixedZ(stats.last_transfer_result[0..], result);
    stats.last_transfer_bytes = bytes;
    stats.last_transfer_ticks = ticks;
    stats.last_transfer_rc = failure_rc;
    stats.last_transfer_abort_rc = abort_rc;
    if (bytesEq(kind, "sftp-write")) {
        stats.last_sftp_write_bytes = bytes;
        stats.last_sftp_write_ticks = ticks;
        stats.last_sftp_write_rc = failure_rc;
        stats.last_sftp_write_abort_rc = abort_rc;
        copyFixedZ(stats.last_sftp_write_result[0..], result);
        copyFixedZ(stats.last_sftp_write_path[0..], path);
        // Publish only after every field in the latched record is complete.
        stats.last_sftp_write_sequence = sequence;
    }
    // Session aggregation compares the sequence before copying the record.
    // Publish it last so a concurrent STATUS snapshot cannot select a
    // half-written transfer.
    stats.last_transfer_sequence = sequence;
}

fn acquireTransferRecordLock(stats: *ServiceStats) void {
    // The protected copy is bounded to a few fixed-size fields and never
    // performs I/O.  Atomic spinning avoids sleeping in telemetry code and
    // makes the non-atomic string/scalar snapshot data-race-free.
    while (@cmpxchgWeak(u32, &stats.transfer_record_lock, 0, 1, .acquire, .monotonic) != null) {}
}

fn releaseTransferRecordLock(stats: *ServiceStats) void {
    @atomicStore(u32, &stats.transfer_record_lock, 0, .release);
}

fn noteTransferFailure(
    stats: *ServiceStats,
    kind: []const u8,
    path: []const u8,
    bytes: u64,
    ticks: u64,
    result: []const u8,
    failure_rc: i32,
    abort_rc: i32,
) void {
    noteTransferResult(stats, kind, path, bytes, ticks, result, failure_rc, abort_rc);
}

fn isDirectSystemWriteBlocked(path: []const u8) bool {
    if (isUpdateInboxFilePath(path)) return false;
    return isPathAtOrBelow(path, "C:\\R4OS") or
        isPathAtOrBelow(path, "C:\\BOOT") or
        isPathAtOrBelow(path, "C:\\EFI") or
        isPathAtOrBelow(path, "C:\\LIMINE") or
        // create-system exposes the FAT32 boot volume as D:, while the
        // updater addresses the same volume through its private /boot mount.
        isPathAtOrBelow(path, "D:\\BOOT") or
        isPathAtOrBelow(path, "D:\\EFI") or
        isPathAtOrBelow(path, "D:\\LIMINE");
}

fn isDirectoryCreateBlocked(path: []const u8) bool {
    if (isUpdateDirectoryPath(path)) return false;
    return isDirectSystemWriteBlocked(path);
}

fn isUpdateInboxFilePath(path: []const u8) bool {
    return startsWithIgnoreCase(path, "C:\\R4OS\\UPDATE\\INBOX\\");
}

fn isUpdateDirectoryPath(path: []const u8) bool {
    return equalsIgnoreCase(path, "C:\\R4OS\\UPDATE") or
        equalsIgnoreCase(path, "C:\\R4OS\\UPDATE\\INBOX") or
        startsWithIgnoreCase(path, "C:\\R4OS\\UPDATE\\INBOX\\");
}

fn startsWithIgnoreCase(value: []const u8, prefix: []const u8) bool {
    if (value.len < prefix.len) return false;
    var i: usize = 0;
    while (i < prefix.len) : (i += 1) {
        if (upper(value[i]) != upper(prefix[i])) return false;
    }
    return true;
}

fn isPathAtOrBelow(path: []const u8, root: []const u8) bool {
    if (equalsIgnoreCase(path, root)) return true;
    return path.len > root.len and
        path[root.len] == '\\' and
        startsWithIgnoreCase(path, root);
}

fn resolveSshFilePath(config: ?*const Config, remote_raw: []const u8, out: []u8) ?[]const u8 {
    if (out.len < 4) return null;
    @memset(out, 0);
    const remote = trimSpaces(remote_raw);
    if (remote.len == 0 or bytesEq(remote, ".") or bytesEq(remote, "/")) {
        const root = if (config) |cfg| spanZ(cfg.sftp_root[0..]) else default_sftp_root;
        if (!bytesEq(root, remote_raw)) return resolveSshFilePath(null, root, out);
    }

    var drive: u8 = 0;
    var tail_start: usize = 0;
    if (remote.len >= 2 and isDriveLetter(remote[0]) and remote[1] == ':') {
        drive = upper(remote[0]);
        tail_start = 2;
    } else if (remote.len >= 2 and (remote[0] == '/' or remote[0] == '\\') and isDriveLetter(remote[1])) {
        drive = upper(remote[1]);
        tail_start = 2;
        if (remote.len > 2 and remote[2] == ':') tail_start = 3;
    } else {
        var root_buf: [sftp_path_capacity]u8 = .{0} ** sftp_path_capacity;
        const root = if (config) |cfg| spanZ(cfg.sftp_root[0..]) else default_sftp_root;
        const root_path = resolveSshFilePath(null, root, root_buf[0..]) orelse return null;
        var pos: usize = 0;
        if (!appendChecked(out, &pos, root_path)) return null;
        // A relative path is confined to the configured SFTP root even when
        // the client sends "." or ".." components. Policy checks later in
        // the request therefore see the same canonical target as R4SYS.
        const root_floor = pos;
        if (!appendCanonicalTail(out, &pos, root_floor, remote)) return null;
        if (pos == 2) {
            if (!appendChecked(out, &pos, "\\")) return null;
        }
        return out[0..pos];
    }

    var pos: usize = 0;
    out[pos] = drive;
    pos += 1;
    out[pos] = ':';
    pos += 1;
    out[pos] = '\\';
    pos += 1;
    while (tail_start < remote.len and isPathSeparator(remote[tail_start])) : (tail_start += 1) {}
    const drive_floor = pos;
    if (!appendCanonicalTail(out, &pos, drive_floor, remote[tail_start..])) return null;
    return out[0..pos];
}

fn appendCanonicalTail(out: []u8, pos: *usize, floor: usize, tail: []const u8) bool {
    if (floor > pos.* or pos.* > out.len) return false;
    var cursor: usize = 0;
    while (cursor < tail.len) {
        while (cursor < tail.len and isPathSeparator(tail[cursor])) : (cursor += 1) {}
        if (cursor == tail.len) break;
        const component_start = cursor;
        while (cursor < tail.len and !isPathSeparator(tail[cursor])) : (cursor += 1) {}
        const component = tail[component_start..cursor];
        if (bytesEq(component, ".")) continue;
        if (bytesEq(component, "..")) {
            // Never permit a relative client path to escape the configured
            // root, nor an absolute path to escape its drive root.
            if (pos.* <= floor) return false;
            while (pos.* > floor and out[pos.* - 1] != '\\') pos.* -= 1;
            if (pos.* > floor and out[pos.* - 1] == '\\') pos.* -= 1;
            continue;
        }
        if (pos.* > 0 and out[pos.* - 1] != '\\') {
            if (pos.* + 1 >= out.len) return false;
            out[pos.*] = '\\';
            pos.* += 1;
        }
        if (component.len >= out.len - pos.*) return false;
        @memcpy(out[pos.* .. pos.* + component.len], component);
        pos.* += component.len;
    }
    return true;
}

fn r4PathToSftpPath(path: []const u8, out: []u8) ?[]const u8 {
    if (path.len < 2 or path[1] != ':' or !isDriveLetter(path[0]) or out.len < 4) return null;
    var pos: usize = 0;
    out[pos] = '/';
    pos += 1;
    out[pos] = upper(path[0]);
    pos += 1;
    out[pos] = '/';
    pos += 1;
    var i: usize = 2;
    while (i < path.len and isPathSeparator(path[i])) : (i += 1) {}
    var last_sep = true;
    while (i < path.len) : (i += 1) {
        const ch = if (isPathSeparator(path[i])) '/' else path[i];
        if (ch == '/') {
            if (last_sep) continue;
            if (pos + 1 >= out.len) return null;
            out[pos] = '/';
            pos += 1;
            last_sep = true;
        } else {
            if (pos + 1 >= out.len) return null;
            out[pos] = ch;
            pos += 1;
            last_sep = false;
        }
    }
    return out[0..pos];
}

fn sftpBaseName(path: []const u8) []const u8 {
    if (path.len == 0) return "";
    var end = path.len;
    while (end > 0 and isPathSeparator(path[end - 1])) : (end -= 1) {}
    if (end == 0) return "";
    var start = end;
    while (start > 0 and !isPathSeparator(path[start - 1]) and path[start - 1] != ':') : (start -= 1) {}
    return path[start..end];
}

fn isDriveLetter(ch: u8) bool {
    const up = upper(ch);
    return up >= 'A' and up <= 'Z';
}

fn isPathSeparator(ch: u8) bool {
    return ch == '/' or ch == '\\';
}

const EncryptedPacketPoll = struct {
    alive: bool = false,
    pending: bool = false,
    service_transient: bool = false,
};

const ChannelReadPump = struct {
    endpoint_handle: u32,
    stats: *ServiceStats,
    config: *const Config,
    s2c_key: []const u8,
    buffers: *SessionBuffers,
    rng: *SessionRng,
    seq_out: *u32,
    channel: *ChannelState,
};

fn pollEncryptedPacket(app: *const App, conn_id: u32) EncryptedPacketPoll {
    var result: r4os.abi.NetServiceTcpResult = .{};
    const rc = tcpPollServiceResultWaitRaw(app, conn_id, &result, channelReadServiceWaitTicks(app));
    if (rc != 0) return .{ .alive = true, .service_transient = true };
    if (tcpServiceTransientResult(&result)) return .{ .alive = true, .service_transient = true };
    if (tcpPollConnectionClosed(&result)) return .{};
    if ((result.flags & r4os.abi.net_service_tcp_flag_handle_valid) == 0) return .{};
    if ((result.flags & r4os.abi.net_service_tcp_flag_conn_valid) == 0) return .{};
    return .{
        .alive = true,
        .pending = result.pending_rx != 0,
    };
}

fn tcpPollServiceResultWaitRaw(app: *const App, conn_id: u32, out: *r4os.abi.NetServiceTcpResult, wait_ticks: u64) i32 {
    return tcpPollServiceWaitLocked(app, conn_id, out, wait_ticks);
}

fn tcpServiceStatusCode(result: *const r4os.abi.NetServiceTcpResult) u32 {
    if (result.service_status != 0) return result.service_status;
    return (result.flags & r4os.abi.net_service_status_mask) >> r4os.abi.net_service_status_shift;
}

fn tcpServiceTransientResult(result: *const r4os.abi.NetServiceTcpResult) bool {
    // 0.56.34b: Terminaler Lifecycle ist NIE transient. Kernel-read() gibt
    // eine FIN-geschlossene Verbindung beim EOF-Read sofort frei (tcp.zig:
    // state==closed && rx leer -> used=false); der Folge-Poll liefert dann
    // dead-handle OHNE valid-Flags und fiel genau damit in die Contention-
    // Heuristik darunter. Folge: Handshake-Read drehte nach Client-Abbruch
    // (Termius Fingerprint-Reject) den vollen 30s-Timeout und verhungerte
    // ueber den Service-Lock den Accept-/Banner-Pfad - EIN Reject blockte
    // alle neuen Verbindungen (banner-exchange-Timeout). Gleiche Klasse wie
    // der 0.56.7-Write-Fix ("Leichen-Loop"), nur im Read-/Poll-Pfad.
    if (tcpLifecycleTerminal(result.lifecycle_cause)) return false;
    const status = tcpServiceStatusCode(result);
    if (status != r4os.abi.net_service_status_failed and status != r4os.abi.net_service_status_timeout) return false;
    if ((result.flags & r4os.abi.net_service_tcp_flag_handle_valid) != 0) return false;
    if ((result.flags & r4os.abi.net_service_tcp_flag_conn_valid) != 0) return false;
    return true;
}

fn tcpPollConnectionClosed(result: *const r4os.abi.NetServiceTcpResult) bool {
    if (tcpLifecycleTerminal(result.lifecycle_cause)) return true;
    const status = tcpServiceStatusCode(result);
    if (result.result != 0 and status != r4os.abi.net_service_status_would_block and status != r4os.abi.net_service_status_timeout) return true;
    if (status == r4os.abi.net_service_status_would_block or result.lifecycle_cause == r4os.abi.net_service_socket_lifecycle_would_block) return false;
    if ((result.flags & r4os.abi.net_service_tcp_flag_handle_valid) == 0) return true;
    if ((result.flags & r4os.abi.net_service_tcp_flag_conn_valid) == 0) return true;
    return false;
}

fn tcpLifecycleTerminal(cause: u32) bool {
    return switch (cause) {
        r4os.abi.net_service_socket_lifecycle_closed,
        r4os.abi.net_service_socket_lifecycle_reset,
        r4os.abi.net_service_socket_lifecycle_peer_gone,
        r4os.abi.net_service_socket_lifecycle_local_abort,
        r4os.abi.net_service_socket_lifecycle_local_close,
        r4os.abi.net_service_socket_lifecycle_bad_handle,
        r4os.abi.net_service_socket_lifecycle_owner_mismatch,
        r4os.abi.net_service_socket_lifecycle_dropped,
        => true,
        else => false,
    };
}

fn waitForEncryptedPacketPending(app: *const App, conn_id: u32, timeout_ticks: u64) bool {
    const start = app.sys.ticks();
    while (app.sys.ticks() - start < timeout_ticks) {
        const state = pollEncryptedPacket(app, conn_id);
        if (!state.alive) return false;
        if (state.pending) return true;
        app.sys.sleepTicks(1);
    }
    return false;
}

fn remoteProgramDone(app: *const App, instance_id: u32) bool {
    return remoteProgramExitCode(app, instance_id) != null;
}

const ProgramInventoryLookup = union(enum) {
    found: r4os.abi.ProgramInstanceInfo,
    missing,
    unavailable,
};

const inventory_restart_limit: u32 = 16;
const inventory_would_block_retry_limit: u32 = 64;
const direct_diag_task_limit: u32 = 192;

fn remoteProgramExitCode(app: *const App, instance_id: u32) ?i32 {
    if (instance_id == 0) return 0;
    switch (inventoryProgramById(app, instance_id)) {
        .found => |info| {
            if (info.state == @intFromEnum(r4os.abi.ProgramInstanceState.done)) return info.exit_code;
            return null;
        },
        .unavailable => return null,
        .missing => {},
    }
    const reaped_exit = app.sys.programReapInstance(instance_id);
    if (reaped_exit != -1 and reaped_exit != -2) return reaped_exit;
    return null;
}

fn inventoryProgramById(app: *const App, instance_id: u32) ProgramInventoryLookup {
    var attempt: u32 = 0;
    restart: while (attempt < inventory_restart_limit) : (attempt += 1) {
        var cursor: r4os.abi.ProgramInventoryCursor = .{};
        var summary: r4os.abi.ProgramInventorySummary = .{};
        if (!beginProgramInventory(app, &cursor, &summary)) return .unavailable;
        while (true) {
            var entries: [@as(usize, r4os.abi.program_inventory_page_max)]r4os.abi.ProgramInstanceSnapshot = undefined;
            var page: r4os.abi.ProgramInventoryPageInfo = .{};
            if (!readProgramInventoryPage(app, &cursor, entries[0..], &page)) return .unavailable;
            if (page.status == r4os.abi.program_inventory_status_restart) continue :restart;
            if (page.returned > entries.len or page.snapshot_generation != cursor.snapshot_generation) return .unavailable;
            for (entries[0..@intCast(page.returned)]) |entry| {
                if (entry.info.id == instance_id) return .{ .found = entry.info };
            }
            if (page.status == r4os.abi.program_inventory_status_complete) return .missing;
            if (page.status != r4os.abi.program_inventory_status_more or page.returned == 0) return .unavailable;
        }
    }
    return .unavailable;
}

fn beginProgramInventory(
    app: *const App,
    cursor: *r4os.abi.ProgramInventoryCursor,
    summary: *r4os.abi.ProgramInventorySummary,
) bool {
    var retry: u32 = 0;
    while (retry <= inventory_would_block_retry_limit) : (retry += 1) {
        cursor.* = .{};
        summary.* = .{};
        const status = app.sys.programInventoryBegin(cursor, summary);
        if (status == r4os.abi.program_handle_ok) return true;
        if (status != r4os.abi.program_handle_error_would_block or retry == inventory_would_block_retry_limit)
            return false;
        app.sys.sleepTicks(1);
    }
    return false;
}

fn readProgramInventoryPage(
    app: *const App,
    cursor: *r4os.abi.ProgramInventoryCursor,
    entries: []r4os.abi.ProgramInstanceSnapshot,
    page: *r4os.abi.ProgramInventoryPageInfo,
) bool {
    var retry: u32 = 0;
    while (retry <= inventory_would_block_retry_limit) : (retry += 1) {
        const cursor_before = cursor.*;
        page.* = .{};
        const status = app.sys.programInventoryPrograms(cursor, entries, page);
        if (status == r4os.abi.program_handle_ok) return true;
        cursor.* = cursor_before;
        page.* = .{};
        if (status != r4os.abi.program_handle_error_would_block or retry == inventory_would_block_retry_limit)
            return false;
        app.sys.sleepTicks(1);
    }
    return false;
}

fn readTaskInventoryPage(
    app: *const App,
    cursor: *r4os.abi.ProgramInventoryCursor,
    entries: []r4os.abi.ProgramTaskSnapshot,
    page: *r4os.abi.ProgramInventoryPageInfo,
) bool {
    var retry: u32 = 0;
    while (retry <= inventory_would_block_retry_limit) : (retry += 1) {
        const cursor_before = cursor.*;
        page.* = .{};
        const status = app.sys.programInventoryTasks(cursor, entries, page);
        if (status == r4os.abi.program_handle_ok) return true;
        cursor.* = cursor_before;
        page.* = .{};
        if (status != r4os.abi.program_handle_error_would_block or retry == inventory_would_block_retry_limit)
            return false;
        app.sys.sleepTicks(1);
    }
    return false;
}

fn reapProgramInstance(app: *const App, instance_id: u32) void {
    if (instance_id == 0) return;
    _ = app.sys.programReapInstance(instance_id);
}

fn sshExitStatus(exit_code: i32) u32 {
    if (exit_code < 0) return 255;
    return @intCast(exit_code);
}

fn channelTargetMatches(payload: []const u8, channel_id: u32) bool {
    if (payload.len < 5) return false;
    return readBeU32(payload[1..]) == channel_id;
}

fn sendChannelOpenConfirmation(app: *const App, conn_id: u32, key: []const u8, channel: *const ChannelState, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    var payload: [32]u8 = .{0} ** 32;
    var w = Writer.init(payload[0..]);
    if (!w.byte(ssh_msg_channel_open_confirmation)) return false;
    if (!w.beU32(channel.client_channel)) return false;
    if (!w.beU32(channel.server_channel)) return false;
    if (!w.beU32(ssh_channel_window)) return false;
    if (!w.beU32(ssh_channel_packet_max)) return false;
    return sendEncryptedPacket(app, conn_id, key, w.slice(), buffers, rng, seq_out);
}

fn sendChannelOpenFailure(app: *const App, conn_id: u32, key: []const u8, recipient: u32, message: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    var payload: [160]u8 = .{0} ** 160;
    var w = Writer.init(payload[0..]);
    if (!w.byte(ssh_msg_channel_open_failure)) return false;
    if (!w.beU32(recipient)) return false;
    if (!w.beU32(ssh_open_administratively_prohibited)) return false;
    if (!w.string(message)) return false;
    if (!w.string("")) return false;
    return sendEncryptedPacket(app, conn_id, key, w.slice(), buffers, rng, seq_out);
}

fn sendChannelRequestReply(app: *const App, conn_id: u32, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, recipient: u32, success: bool) bool {
    var payload: [8]u8 = .{0} ** 8;
    var w = Writer.init(payload[0..]);
    if (!w.byte(if (success) ssh_msg_channel_success else ssh_msg_channel_failure)) return false;
    if (!w.beU32(recipient)) return false;
    return sendEncryptedPacket(app, conn_id, key, w.slice(), buffers, rng, seq_out);
}

fn ackChannelInputWindow(app: *const App, conn_id: u32, stats: *ServiceStats, key: []const u8, channel: *ChannelState, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, bytes: usize) bool {
    if (bytes == 0) return true;
    channel.channel_window_consumed += bytes;
    if (channel.channel_window_consumed < ssh_channel_window_adjust_threshold) return true;
    const adjust = channel.channel_window_consumed;
    if (!sendChannelWindowAdjust(app, conn_id, key, buffers, rng, seq_out, channel.client_channel, adjust)) {
        setLastProtocolError(stats, "window-adjust-send");
        return false;
    }
    channel.channel_window_consumed = 0;
    return true;
}

fn sendChannelWindowAdjust(app: *const App, conn_id: u32, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, recipient: u32, bytes: usize) bool {
    if (bytes == 0) return true;
    var payload: [12]u8 = .{0} ** 12;
    var w = Writer.init(payload[0..]);
    if (!w.byte(ssh_msg_channel_window_adjust)) return false;
    if (!w.beU32(recipient)) return false;
    if (!w.beU32(usizeToDiagU32(bytes))) return false;
    return sendEncryptedPacket(app, conn_id, key, w.slice(), buffers, rng, seq_out);
}

fn sendChannelData(app: *const App, conn_id: u32, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, recipient: u32, data: []const u8) bool {
    if (data.len == 0) return true;
    var payload: [ssh_channel_output_chunk_max + 16]u8 = .{0} ** (ssh_channel_output_chunk_max + 16);
    var w = Writer.init(payload[0..]);
    if (!w.byte(ssh_msg_channel_data)) return false;
    if (!w.beU32(recipient)) return false;
    if (!w.string(data)) return false;
    return sendEncryptedPacket(app, conn_id, key, w.slice(), buffers, rng, seq_out);
}

fn sendChannelExitAndClose(app: *const App, conn_id: u32, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, channel: *ChannelState, exit_code: u32) void {
    if (channel.close_sent) return;
    var status_payload: [32]u8 = .{0} ** 32;
    var status_w = Writer.init(status_payload[0..]);
    if (status_w.byte(ssh_msg_channel_request) and
        status_w.beU32(channel.client_channel) and
        status_w.string("exit-status") and
        status_w.byte(0) and
        status_w.beU32(exit_code))
    {
        _ = sendEncryptedPacket(app, conn_id, key, status_w.slice(), buffers, rng, seq_out);
        _ = flushTcpControlWrite(app, conn_id, null);
    }
    var eof_payload: [8]u8 = .{0} ** 8;
    var eof_w = Writer.init(eof_payload[0..]);
    if (eof_w.byte(ssh_msg_channel_eof) and eof_w.beU32(channel.client_channel)) {
        _ = sendEncryptedPacket(app, conn_id, key, eof_w.slice(), buffers, rng, seq_out);
        _ = flushTcpControlWrite(app, conn_id, null);
    }
    var close_attempts: u8 = 0;
    while (!channel.close_sent and close_attempts < 3) : (close_attempts += 1) {
        if (sendChannelClose(app, conn_id, key, buffers, rng, seq_out, channel)) break;
        app.sys.sleepTicks(1);
    }
    _ = flushTcpControlWrite(app, conn_id, null);
}

fn sendChannelClose(app: *const App, conn_id: u32, key: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, channel: *ChannelState) bool {
    var payload: [8]u8 = .{0} ** 8;
    var w = Writer.init(payload[0..]);
    if (!w.byte(ssh_msg_channel_close)) return false;
    if (!w.beU32(channel.client_channel)) return false;
    const ok = sendEncryptedPacket(app, conn_id, key, w.slice(), buffers, rng, seq_out);
    if (ok) channel.close_sent = true;
    return ok;
}

fn clampU32(value: u32, min_value: u32, max_value: u32) u32 {
    if (value < min_value) return min_value;
    if (value > max_value) return max_value;
    return value;
}

fn appendPlainPreload(buffers: *SessionBuffers, data: []const u8) bool {
    if (data.len == 0) return true;
    const active = if (buffers.preloaded_plain_len >= buffers.preloaded_plain_pos)
        buffers.preloaded_plain_len - buffers.preloaded_plain_pos
    else
        0;
    if (active != 0 and buffers.preloaded_plain_pos != 0) {
        std.mem.copyForwards(u8, buffers.preloaded_plain[0..active], buffers.preloaded_plain[buffers.preloaded_plain_pos..buffers.preloaded_plain_len]);
        buffers.preloaded_plain_pos = 0;
        buffers.preloaded_plain_len = active;
    } else if (active == 0) {
        buffers.preloaded_plain_pos = 0;
        buffers.preloaded_plain_len = 0;
    }
    if (buffers.preloaded_plain_len + data.len > buffers.preloaded_plain.len) return false;
    @memcpy(buffers.preloaded_plain[buffers.preloaded_plain_len .. buffers.preloaded_plain_len + data.len], data);
    buffers.preloaded_plain_len += data.len;
    return true;
}

fn drainPlainPreload(buffers: *SessionBuffers, out: []u8) usize {
    if (out.len == 0 or buffers.preloaded_plain_pos >= buffers.preloaded_plain_len) {
        buffers.preloaded_plain_pos = 0;
        buffers.preloaded_plain_len = 0;
        return 0;
    }
    const available = buffers.preloaded_plain_len - buffers.preloaded_plain_pos;
    const take = @min(out.len, available);
    @memcpy(out[0..take], buffers.preloaded_plain[buffers.preloaded_plain_pos .. buffers.preloaded_plain_pos + take]);
    buffers.preloaded_plain_pos += take;
    if (buffers.preloaded_plain_pos >= buffers.preloaded_plain_len) {
        buffers.preloaded_plain_pos = 0;
        buffers.preloaded_plain_len = 0;
    }
    return take;
}

fn readClientIdent(app: *const App, conn_id: u32, out: []u8, buffers: *SessionBuffers, timeout_ticks: u64, stats: ?*ServiceStats) ?[]const u8 {
    var pos: usize = 0;
    const start = app.sys.ticks();
    while (app.sys.ticks() - start < timeout_ticks and pos + 1 < out.len) {
        var read_buf: [ssh_ident_read_chunk_max]u8 = .{0} ** ssh_ident_read_chunk_max;
        const got = tcpReadWaitServiceConsumeSafeLocked(app, conn_id, read_buf[0..], app.sys.ticksFromMilliseconds(50), tcpFastServiceWaitTicks(app));
        if (got < 0) {
            if (tcpReadTransientRecoverable(app, conn_id, tcpFastServiceWaitTicks(app), stats)) {
                setPacketReadDiag(stats, "ident-retry", 1, 0);
                app.sys.sleepTicks(1);
                continue;
            }
            setPacketReadFail(stats, "ident", 1, 0);
            recordTcpPollOnReadFail(app, conn_id, stats, tcpFastServiceWaitTicks(app));
            return null;
        }
        if (got == 0) {
            var poll: r4os.abi.NetServiceTcpResult = .{};
            const poll_rc = tcpPollServiceResultWaitRaw(app, conn_id, &poll, tcpFastServiceWaitTicks(app));
            if (poll_rc == 0) {
                noteTcpPollStats(stats, &poll);
                if (tcpPollConnectionClosed(&poll)) {
                    setPacketReadFail(stats, "ident-closed", 1, 0);
                    return null;
                }
            } else {
                noteTcpTransient(stats, null, poll_rc, .read);
            }
            setPacketReadDiag(stats, "ident-wait", 1, 0);
            app.sys.taskYield();
            continue;
        }
        const got_len: usize = @intCast(got);
        var i: usize = 0;
        while (i < got_len) : (i += 1) {
            const ch = read_buf[i];
            if (ch == '\n') {
                if (pos != 0 and out[pos - 1] == '\r') pos -= 1;
                out[pos] = 0;
                if (!appendPlainPreload(buffers, read_buf[i + 1 .. got_len])) {
                    setPacketReadFail(stats, "ident-preload", got_len, i + 1);
                    return null;
                }
                return out[0..pos];
            }
            if (ch == 0) return null;
            if (pos + 1 >= out.len) {
                setPacketReadFail(stats, "ident-long", out.len, pos);
                return null;
            }
            out[pos] = ch;
            pos += 1;
        }
    }
    return null;
}

fn sendPlainPacket(app: *const App, conn_id: u32, payload: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32, stats: ?*ServiceStats) bool {
    const total = buildPlainPacket(buffers.plain_packet[0..], payload, rng, 8, true) orelse return false;
    const wrote = tcpWritePacedServiceRobust(app, conn_id, buffers.plain_packet[0..total], app.sys.ticksFromMilliseconds(tcp_write_wait_ms), tcpServiceWaitTicks(app), stats);
    if (wrote != @as(i32, @intCast(total))) return false;
    app.sys.taskYield();
    seq_out.* +%= 1;
    return true;
}

fn readPlainPacket(app: *const App, conn_id: u32, out: []u8, buffers: *SessionBuffers, timeout_ticks: u64, seq_in: *u32, stats: ?*ServiceStats) ?[]const u8 {
    var len_buf: [4]u8 = .{0} ** 4;
    if (!readExactPlain(app, conn_id, buffers, len_buf[0..], timeout_ticks, stats, "plain-len")) return null;
    const packet_len = readBeU32(len_buf[0..]);
    setPacketReadLens(stats, packet_len, 0);
    if (packet_len < 5 or packet_len > ssh_max_packet_len) return null;
    const packet_len_usize: usize = @intCast(packet_len);
    if (!readExactPlain(app, conn_id, buffers, buffers.packet_body[0..packet_len_usize], timeout_ticks, stats, "plain-body")) return null;
    const padding_len: usize = buffers.packet_body[0];
    if (padding_len < 4 or padding_len + 1 > packet_len_usize) return null;
    const payload_len = packet_len_usize - padding_len - 1;
    if (payload_len > out.len) return null;
    @memcpy(out[0..payload_len], buffers.packet_body[1 .. 1 + payload_len]);
    setPacketReadLens(stats, packet_len, payload_len);
    setPacketReadDiag(stats, "plain-payload", payload_len, payload_len);
    seq_in.* +%= 1;
    return out[0..payload_len];
}

fn sendPlainDisconnect(app: *const App, conn_id: u32, reason: u32, message: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    var payload: [160]u8 = .{0} ** 160;
    const disconnect = buildDisconnect(payload[0..], reason, message) orelse return false;
    return sendPlainPacket(app, conn_id, disconnect, buffers, rng, seq_out, null);
}

fn sendEncryptedDisconnect(app: *const App, conn_id: u32, key: []const u8, reason: u32, message: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    var payload: [160]u8 = .{0} ** 160;
    const disconnect = buildDisconnect(payload[0..], reason, message) orelse return false;
    return sendEncryptedPacket(app, conn_id, key, disconnect, buffers, rng, seq_out);
}

fn sendEncryptedPacket(app: *const App, conn_id: u32, key: []const u8, payload: []const u8, buffers: *SessionBuffers, rng: *SessionRng, seq_out: *u32) bool {
    const plain_len = buildPlainPacket(buffers.plain_packet[0..], payload, rng, 8, false) orelse return false;
    const encrypted_len = encryptChachaPacket(app, buffers.encrypted_packet[0..], buffers.plain_packet[0..plain_len], key, seq_out.*) orelse return false;
    const wrote = tcpWritePacedServiceRobust(app, conn_id, buffers.encrypted_packet[0..encrypted_len], app.sys.ticksFromMilliseconds(tcp_write_wait_ms), tcpServiceWaitTicks(app), null);
    if (wrote != @as(i32, @intCast(encrypted_len))) return false;
    app.sys.taskYield();
    seq_out.* +%= 1;
    return true;
}

fn flushTcpControlWrite(app: *const App, conn_id: u32, stats: ?*ServiceStats) bool {
    const wait_ticks = app.sys.ticksFromMilliseconds(tcp_control_ack_wait_ms);
    const retransmit_ticks = app.sys.ticksFromMilliseconds(tcp_control_retransmit_wait_ms);
    const start = app.sys.ticks();
    var last_retransmit = start;
    var target_ack: u32 = 0;
    while (wait_ticks == 0 or app.sys.ticks() - start < wait_ticks) {
        var poll: r4os.abi.NetServiceTcpResult = .{};
        const rc = tcpPollServiceResultWaitRaw(app, conn_id, &poll, tcpServiceWaitTicks(app));
        if (rc != 0) {
            noteTcpTransient(stats, null, rc, .write);
        } else if (tcpServiceTransientResult(&poll)) {
            noteTcpTransient(stats, &poll, poll.result, .write);
        } else {
            noteTcpPollStats(stats, &poll);
            if (tcpPollConnectionClosed(&poll)) return false;
            if (target_ack == 0) target_ack = poll.tx_seq;
            if (target_ack == 0 or tcpSeqReached(poll.tx_ack, target_ack)) return true;
        }

        const now = app.sys.ticks();
        if (retransmit_ticks != 0 and now - last_retransmit >= retransmit_ticks) {
            var retry: r4os.abi.NetServiceTcpResult = .{};
            const retry_rc = tcpRetransmitServiceResultWaitLocked(app, conn_id, &retry, tcpServiceWaitTicks(app));
            if (retry_rc != 0) {
                noteTcpTransient(stats, null, retry_rc, .write);
            } else {
                noteTcpPollStats(stats, &retry);
                if (tcpPollConnectionClosed(&retry)) return false;
            }
            last_retransmit = now;
        }
        app.sys.sleepTicks(1);
    }
    return true;
}

fn maybeRetransmitTcpControl(app: *const App, conn_id: u32, stats: ?*ServiceStats, last_retransmit: *u64, retransmit_ticks: u64) void {
    if (retransmit_ticks == 0) return;
    const now = app.sys.ticks();
    if (now - last_retransmit.* < retransmit_ticks) return;
    var retry: r4os.abi.NetServiceTcpResult = .{};
    const retry_rc = tcpRetransmitServiceResultWaitLocked(app, conn_id, &retry, tcpServiceWaitTicks(app));
    if (retry_rc != 0) {
        noteTcpTransient(stats, null, retry_rc, .write);
    } else {
        noteTcpPollStats(stats, &retry);
    }
    last_retransmit.* = now;
}

fn tcpSeqReached(current: u32, target: u32) bool {
    const diff: i32 = @bitCast(current -% target);
    return diff >= 0;
}

fn readEncryptedPacket(app: *const App, conn_id: u32, key: []const u8, out: []u8, buffers: *SessionBuffers, timeout_ticks: u64, seq_in: *u32, stats: ?*ServiceStats) ?[]const u8 {
    return readEncryptedPacketBounded(app, conn_id, key, out, buffers, timeout_ticks, app.sys.ticksFromMilliseconds(channel_packet_total_timeout_ms), tcpServiceWaitTicks(app), seq_in, stats);
}

fn readEncryptedPacketBounded(app: *const App, conn_id: u32, key: []const u8, out: []u8, buffers: *SessionBuffers, timeout_ticks: u64, total_timeout_ticks: u64, service_wait_ticks: u64, seq_in: *u32, stats: ?*ServiceStats) ?[]const u8 {
    return readEncryptedPacketBoundedInternal(app, conn_id, key, out, buffers, timeout_ticks, total_timeout_ticks, service_wait_ticks, seq_in, stats, null);
}

fn readEncryptedPacketBoundedPumped(app: *const App, conn_id: u32, key: []const u8, out: []u8, buffers: *SessionBuffers, timeout_ticks: u64, total_timeout_ticks: u64, service_wait_ticks: u64, seq_in: *u32, stats: ?*ServiceStats, pump: *ChannelReadPump) ?[]const u8 {
    return readEncryptedPacketBoundedInternal(app, conn_id, key, out, buffers, timeout_ticks, total_timeout_ticks, service_wait_ticks, seq_in, stats, pump);
}

fn readEncryptedPacketBoundedInternal(app: *const App, conn_id: u32, key: []const u8, out: []u8, buffers: *SessionBuffers, timeout_ticks: u64, total_timeout_ticks: u64, service_wait_ticks: u64, seq_in: *u32, stats: ?*ServiceStats, pump: ?*ChannelReadPump) ?[]const u8 {
    var enc_len: [4]u8 = .{0} ** 4;
    if (!readExactTracked(app, conn_id, enc_len[0..], timeout_ticks, total_timeout_ticks, service_wait_ticks, stats, "len", pump)) return null;
    var len_plain: [4]u8 = undefined;
    acquireSshCryptoLock(app);
    chachaXor(len_plain[0..], enc_len[0..], key[32..64], seq_in.*, 0);
    releaseSshCryptoLock();
    const packet_len = readBeU32(len_plain[0..]);
    setPacketReadLens(stats, packet_len, 0);
    if (packet_len < 5 or packet_len > ssh_max_packet_len) {
        setPacketReadDiag(stats, "len-invalid", 0, 0);
        setPacketReadFail(stats, "len-invalid", 0, 0);
        return null;
    }
    const packet_len_usize: usize = @intCast(packet_len);

    const need = packet_len_usize + 16;
    if (!readExactTracked(app, conn_id, buffers.encrypted_body[0..need], timeout_ticks, total_timeout_ticks, service_wait_ticks, stats, "body", pump)) return null;
    const tag: [16]u8 = buffers.encrypted_body[packet_len_usize .. packet_len_usize + 16][0..16].*;
    var calc_tag: [16]u8 = undefined;
    acquireSshCryptoLock(app);
    poly1305PacketTag(&calc_tag, key[0..32], seq_in.*, enc_len[0..], buffers.encrypted_body[0..packet_len_usize]);
    const tag_ok = std.crypto.timing_safe.eql([16]u8, calc_tag, tag);
    if (tag_ok) {
        chachaXor(buffers.packet_body[0..packet_len_usize], buffers.encrypted_body[0..packet_len_usize], key[0..32], seq_in.*, 1);
    }
    releaseSshCryptoLock();
    if (!tag_ok) {
        setPacketReadDiag(stats, "mac", need, need);
        setPacketReadFail(stats, "mac", need, need);
        return null;
    }

    const padding_len: usize = buffers.packet_body[0];
    if (padding_len < 4 or padding_len + 1 > packet_len_usize) {
        setPacketReadDiag(stats, "padding", need, need);
        setPacketReadFail(stats, "padding", need, need);
        return null;
    }
    const payload_len = packet_len_usize - padding_len - 1;
    setPacketReadLens(stats, packet_len, payload_len);
    if (payload_len > out.len) {
        setPacketReadDiag(stats, "payload-cap", payload_len, out.len);
        setPacketReadFail(stats, "payload-cap", payload_len, out.len);
        return null;
    }
    @memcpy(out[0..payload_len], buffers.packet_body[1 .. 1 + payload_len]);
    setPacketReadDiag(stats, "payload", payload_len, payload_len);
    seq_in.* +%= 1;
    return out[0..payload_len];
}

fn readExact(app: *const App, conn_id: u32, out: []u8, timeout_ticks: u64, stats: ?*ServiceStats, stage: []const u8) bool {
    return readExactTracked(app, conn_id, out, timeout_ticks, timeout_ticks, tcpFastServiceWaitTicks(app), stats, stage, null);
}

fn readExactTracked(app: *const App, conn_id: u32, out: []u8, timeout_ticks: u64, total_timeout_ticks: u64, service_wait_ticks: u64, stats: ?*ServiceStats, stage: []const u8, pump: ?*ChannelReadPump) bool {
    return readExactTrackedFromOffset(app, conn_id, out, 0, timeout_ticks, total_timeout_ticks, service_wait_ticks, stats, stage, pump);
}

fn readExactPlain(app: *const App, conn_id: u32, buffers: *SessionBuffers, out: []u8, timeout_ticks: u64, stats: ?*ServiceStats, stage: []const u8) bool {
    const preloaded = drainPlainPreload(buffers, out);
    if (preloaded == out.len) {
        setPacketReadDiag(stats, stage, out.len, out.len);
        return true;
    }
    return readExactTrackedFromOffset(app, conn_id, out, preloaded, timeout_ticks, timeout_ticks, tcpFastServiceWaitTicks(app), stats, stage, null);
}

fn readExactTrackedFromOffset(app: *const App, conn_id: u32, out: []u8, initial_offset: usize, timeout_ticks: u64, total_timeout_ticks: u64, service_wait_ticks: u64, stats: ?*ServiceStats, stage: []const u8, pump: ?*ChannelReadPump) bool {
    var offset: usize = 0;
    if (initial_offset > out.len) return false;
    offset = initial_offset;
    const start = app.sys.ticks();
    var last_progress = start;
    var last_retransmit = start;
    const retransmit_ticks = app.sys.ticksFromMilliseconds(tcp_control_retransmit_wait_ms);
    // 0.56.34b: Fehler-Budget gegen den Dead-Conn-Lock-Konvoi. Eine GESUNDE
    // Verbindung liefert bei Stau got==0 (keine Daten), nie dauerhaft got<0.
    // Dauerhafte got<0-Fehler = tote/entsorgte Verbindung ODER TCPSVC-Kanal
    // im Konvoi (rc!=0-Lock-Timeouts, dann gibt es NIE ein sauberes
    // Lifecycle-Urteil). Ohne Budget drehte der KEX-Read nach Client-Abbruch
    // (Termius Fingerprint-Reject) 30s mit ~2,5s-blockierenden Ops und
    // verstopfte den Service-Kanal: ZWEI solcher Worker starvten den
    // Accept-/Banner-Pfad komplett (banner-exchange-Timeout fuer alle).
    var error_attempts: u32 = 0;
    var first_error_tick: u64 = 0;
    const error_budget_ticks = app.sys.ticksFromMilliseconds(2000);
    setPacketReadDiag(stats, stage, out.len, offset);
    while (offset < out.len) {
        const now = app.sys.ticks();
        if (now - last_progress >= timeout_ticks) break;
        if (now - start >= total_timeout_ticks) break;
        if (!pumpChannelDuringRead(app, conn_id, pump)) return false;
        const got = tcpReadWaitServiceConsumeSafeLocked(app, conn_id, out[offset..], app.sys.ticksFromMilliseconds(50), service_wait_ticks);
        if (got < 0) {
            error_attempts += 1;
            if (first_error_tick == 0) first_error_tick = app.sys.ticks();
            if (error_attempts >= 3 and app.sys.ticks() - first_error_tick >= error_budget_ticks) {
                setPacketReadFail(stats, "tcp-read-dead", out.len, offset);
                recordTcpPollOnReadFail(app, conn_id, stats, service_wait_ticks);
                return false;
            }
            if (tcpReadTransientRecoverable(app, conn_id, service_wait_ticks, stats)) {
                setPacketReadDiag(stats, "tcp-read-retry", out.len, offset);
                if (!pumpChannelDuringRead(app, conn_id, pump)) return false;
                maybeRetransmitTcpControl(app, conn_id, stats, &last_retransmit, retransmit_ticks);
                app.sys.sleepTicks(1);
                continue;
            }
            setPacketReadDiag(stats, "tcp-read", out.len, offset);
            setPacketReadFail(stats, "tcp-read", out.len, offset);
            recordTcpPollOnReadFail(app, conn_id, stats, service_wait_ticks);
            return false;
        }
        if (got == 0) {
            error_attempts = 0;
            first_error_tick = 0;
            // 0.56.35-Fix: got==0 heisst "keine Daten" - das kann eine
            // vom Client GESCHLOSSENE Verbindung sein (KEX-Abbruch /
            // Fingerprint-Reject). Ohne Peer-Check drehte der Worker die
            // vollen Handshake-Timeout-Sekunden und belegte seinen Slot;
            // ein paar Rejects in Folge fuellten den 8er-Pool, neue
            // Verbindungen bekamen keinen Banner mehr (banner-exchange-
            // Timeout). Bei terminalem Lifecycle sofort raus.
            var probe: r4os.abi.NetServiceTcpResult = .{};
            const probe_rc = tcpPollServiceResultWaitRaw(app, conn_id, &probe, service_wait_ticks);
            if (probe_rc == 0 and probe.pending_rx == 0 and tcpLifecycleTerminal(probe.lifecycle_cause)) {
                setPacketReadFail(stats, "peer-disconnect", out.len, offset);
                noteTcpPollStats(stats, &probe);
                return false;
            }
            if (!pumpChannelDuringRead(app, conn_id, pump)) return false;
            maybeRetransmitTcpControl(app, conn_id, stats, &last_retransmit, retransmit_ticks);
            app.sys.taskYield();
            continue;
        }
        offset += @intCast(got);
        error_attempts = 0;
        first_error_tick = 0;
        last_progress = app.sys.ticks();
        setPacketReadDiag(stats, stage, out.len, offset);
        if (!pumpChannelDuringRead(app, conn_id, pump)) return false;
        app.sys.taskYield();
    }
    if (offset != out.len) {
        setPacketReadFail(stats, stage, out.len, offset);
        recordTcpPollOnReadFail(app, conn_id, stats, service_wait_ticks);
        return false;
    }
    return true;
}

fn pumpChannelDuringRead(app: *const App, conn_id: u32, pump: ?*ChannelReadPump) bool {
    const context = pump orelse return true;
    _ = pumpServiceEndpointDuringSession(app, context.endpoint_handle, context.stats, context.config);
    if (!pumpConsoleOutput(app, conn_id, context.stats, context.s2c_key, context.buffers, context.rng, context.seq_out, context.channel) and !pollEncryptedPacket(app, conn_id).alive) {
        context.stats.channel_output_failures +%= 1;
        setLastProtocolError(context.stats, "read-pump-client-disconnect");
        return false;
    }
    return true;
}

fn tcpWritePacedServiceRobust(app: *const App, conn_id: u32, data: []const u8, wait_ticks: u64, service_wait_ticks: u64, stats: ?*ServiceStats) i32 {
    var offset: usize = 0;
    var tx_remaining: usize = 0;
    // 0.56.5: Write-Retry-Korruption geschlossen. Ein Chunk-Write, dessen
    // Service-Antwort das Wait-Fenster verpasst, kann in TCPSVC trotzdem
    // angewendet worden sein (Antwort verfaellt, Bytes sind im Stream).
    // Der alte blinde Retry schickte den Chunk dann DOPPELT -> Chiffre-
    // Desync -> Client "Bad packet length ... Connection corrupted".
    // Wahrheit ist tx_seq der Verbindung (kumulative Sende-Sequenz, vom
    // Kernel in jedem Poll geliefert). Da Verifikations-Poll und Write
    // durch dieselbe TCPSVC-FIFO laufen, sieht ein erfolgreicher Poll
    // jeden frueher eingereihten Write garantiert: Delta zu expected_seq
    // sagt exakt, wie viele Bytes schon draussen sind.
    var expected_seq: ?u32 = null;
    const start = app.sys.ticks();
    while (offset < data.len) {
        if (tx_remaining == 0) {
            var seq: u32 = 0;
            const window = tcpWaitForTxWindowServiceRobust(app, conn_id, wait_ticks, service_wait_ticks, stats, &seq);
            if (window < 0) return -1;
            if (window == 0) return -1;
            tx_remaining = @intCast(window);
            if (expected_seq == null) expected_seq = seq;
        }

        const chunk_len = @min(@min(data.len - offset, r4os.abi.net_service_tcp_write_max), tx_remaining);
        const written = tcpWriteChunkServiceWaitLocked(app, conn_id, data[offset .. offset + chunk_len], service_wait_ticks);
        if (written <= 0) {
            if (expected_seq) |expected| {
                var poll: r4os.abi.NetServiceTcpResult = .{};
                const rc = tcpPollServiceResultWaitRaw(app, conn_id, &poll, service_wait_ticks);
                if (rc == 0 and !tcpServiceTransientResult(&poll)) {
                    noteTcpPollStats(stats, &poll);
                    // 0.56.7: TOTE Verbindung => SOFORT aufgeben. Vorher
                    // lief der Retry-Loop das volle wait_ticks-Budget
                    // (15 s) gegen einen verschwundenen Client und
                    // flutete dabei TCPSVC mit Service-Calls (Gate-
                    // Befund: txwait terminal=403, bad_handle=1374 -
                    // die Blackout-Kaskade, weil neue Verbindungen
                    // hinter dem Leichen-Loop verhungerten).
                    if (poll.result != 0 or
                        (poll.flags & r4os.abi.net_service_tcp_flag_conn_valid) == 0 or
                        tcpPollConnectionClosed(&poll))
                    {
                        return -1;
                    }
                    const applied: u32 = poll.tx_seq -% expected;
                    if (applied != 0) {
                        // Seq ueber den Chunk hinaus = Buchhaltung kaputt
                        // (fremder Writer/FIN); lieber Abbruch als Korruption.
                        if (applied > chunk_len) return -1;
                        offset += @intCast(applied);
                        tx_remaining -|= @intCast(applied);
                        expected_seq = poll.tx_seq;
                        if (stats) |s| s.tcp_write_seq_skips +%= 1;
                        continue;
                    }
                    // applied == 0: Write sicher nicht angewendet -> Retry ok.
                }
                // Poll selbst fehlgeschlagen: nicht blind retrien, unten
                // schlafen und im naechsten Umlauf erneut verifizieren.
            }
            noteTcpWriteFailurePoll(app, conn_id, stats, service_wait_ticks);
            if (wait_ticks == 0 or app.sys.ticks() - start >= wait_ticks) return -1;
            app.sys.sleepTicks(1);
            continue;
        }
        const written_len: usize = @intCast(written);
        offset += written_len;
        tx_remaining -|= written_len;
        if (expected_seq) |e| expected_seq = e +% @as(u32, @intCast(written));
    }
    return @intCast(data.len);
}

fn tcpWaitForTxWindowServiceRobust(app: *const App, conn_id: u32, wait_ticks: u64, service_wait_ticks: u64, stats: ?*ServiceStats, seq_out: *u32) i32 {
    const start = app.sys.ticks();
    while (true) {
        var poll: r4os.abi.NetServiceTcpResult = .{};
        const rc = tcpPollServiceResultWaitRaw(app, conn_id, &poll, tcpFastServiceWaitTicks(app));
        if (rc != 0) {
            noteTcpTransient(stats, null, rc, .write);
        } else if (tcpServiceTransientResult(&poll)) {
            noteTcpTransient(stats, &poll, poll.result, .write);
        } else {
            noteTcpPollStats(stats, &poll);
            if (poll.result != 0) return -1;
            if ((poll.flags & r4os.abi.net_service_tcp_flag_handle_valid) == 0) return -1;
            if ((poll.flags & r4os.abi.net_service_tcp_flag_conn_valid) == 0) return -1;
            if (poll.tx_window != 0) {
                seq_out.* = poll.tx_seq;
                return @intCast(poll.tx_window);
            }
        }

        if (wait_ticks == 0 or app.sys.ticks() - start >= wait_ticks) return 0;
        app.sys.sleepTicks(1);
        _ = service_wait_ticks;
    }
}

fn tcpReadTransientRecoverable(app: *const App, conn_id: u32, service_wait_ticks: u64, stats: ?*ServiceStats) bool {
    _ = service_wait_ticks;
    var poll: r4os.abi.NetServiceTcpResult = .{};
    // 0.56.34b: Diagnose-Poll mit FAST-Wait - als reine Zustandsprobe darf
    // er nicht das volle Service-Wait-Budget blockieren (trieb die
    // Zykluszeit toter KEX-Worker auf ~2,5s und verstopfte den Kanal).
    const rc = tcpPollServiceResultWaitRaw(app, conn_id, &poll, tcpFastServiceWaitTicks(app));
    if (rc != 0) {
        noteTcpTransient(stats, null, rc, .read);
        return true;
    }
    if (tcpServiceTransientResult(&poll)) {
        noteTcpTransient(stats, &poll, poll.result, .read);
        return true;
    }
    noteTcpPollStats(stats, &poll);
    // 0.56.35-Fix: terminaler Peer-Zustand (Client-RST/FIN nach KEX-Abbruch
    // bzw. Fingerprint-Reject) ist NICHT wiederholbar - sonst dreht der
    // Handshake-Read den vollen 30s-Timeout und blockiert seinen Slot; ein
    // paar Rejects fuellten den 8er-Pool und neue Verbindungen bekamen
    // keinen Banner mehr (Termius: "Verbindung zu bevor die Konsole kommt").
    if (tcpLifecycleTerminal(poll.lifecycle_cause)) return false;
    if (poll.result != 0) return false;
    if ((poll.flags & r4os.abi.net_service_tcp_flag_handle_valid) == 0) return false;
    if ((poll.flags & r4os.abi.net_service_tcp_flag_conn_valid) == 0) return false;
    if (stats) |s| {
        s.tcp_read_transients +%= 1;
    }
    return true;
}

const TcpTransientKind = enum {
    read,
    write,
};

fn noteTcpTransient(stats: ?*ServiceStats, poll: ?*const r4os.abi.NetServiceTcpResult, fallback_result: i32, kind: TcpTransientKind) void {
    if (stats) |s| {
        s.tcp_service_transients +%= 1;
        switch (kind) {
            .read => s.tcp_read_transients +%= 1,
            .write => s.tcp_write_transients +%= 1,
        }
        s.last_tcp_result = fallback_result;
        if (poll) |p| {
            noteTcpPollStats(stats, p);
        }
    }
}

fn noteTcpPollStats(stats: ?*ServiceStats, poll: *const r4os.abi.NetServiceTcpResult) void {
    if (stats) |s| {
        s.last_tcp_pending_rx = poll.pending_rx;
        s.last_tcp_rx_window = poll.rx_window;
        s.last_tcp_tx_window = poll.tx_window;
        s.last_tcp_retransmits = poll.retransmits;
        s.last_tcp_rx_drops = poll.rx_drops;
        s.last_tcp_flags = poll.flags;
        s.last_tcp_service_status = tcpServiceStatusCode(poll);
        s.last_tcp_result = poll.result;
    }
}

fn noteTcpWriteFailurePoll(app: *const App, conn_id: u32, stats: ?*ServiceStats, service_wait_ticks: u64) void {
    var poll: r4os.abi.NetServiceTcpResult = .{};
    const rc = tcpPollServiceResultWaitRaw(app, conn_id, &poll, service_wait_ticks);
    if (rc != 0) {
        noteTcpTransient(stats, null, rc, .write);
        return;
    }
    noteTcpPollStats(stats, &poll);
}

fn recordTcpPollOnReadFail(app: *const App, conn_id: u32, stats: ?*ServiceStats, service_wait_ticks: u64) void {
    var poll: r4os.abi.NetServiceTcpResult = .{};
    const rc = tcpPollServiceResultWaitRaw(app, conn_id, &poll, service_wait_ticks);
    if (rc != 0) {
        noteTcpTransient(stats, null, rc, .read);
        return;
    }
    noteTcpPollStats(stats, &poll);
}

fn setPacketReadLens(stats: ?*ServiceStats, packet_len: u32, payload_len: usize) void {
    if (stats) |s| {
        s.last_packet_len = packet_len;
        s.last_payload_len = usizeToDiagU32(payload_len);
    }
}

fn setPacketReadDiag(stats: ?*ServiceStats, stage: []const u8, want: usize, got: usize) void {
    if (stats) |s| {
        s.last_read_want = usizeToDiagU32(want);
        s.last_read_got = usizeToDiagU32(got);
        copyFixedZ(s.last_read_stage[0..], stage);
    }
}

fn setPacketReadFail(stats: ?*ServiceStats, stage: []const u8, want: usize, got: usize) void {
    if (stats) |s| {
        s.last_fail_packet_len = s.last_packet_len;
        s.last_fail_payload_len = s.last_payload_len;
        s.last_fail_read_want = usizeToDiagU32(want);
        s.last_fail_read_got = usizeToDiagU32(got);
        copyFixedZ(s.last_fail_read_stage[0..], stage);
    }
}

fn usizeToDiagU32(value: usize) u32 {
    if (value > std.math.maxInt(u32)) return std.math.maxInt(u32);
    return @intCast(value);
}

fn buildPlainPacket(out: []u8, payload: []const u8, rng: *SessionRng, block_size: usize, include_length_field: bool) ?usize {
    if (payload.len > ssh_max_payload_len or out.len < payload.len + 5 + 32) return null;
    const aligned_len = payload.len + 1 + if (include_length_field) @as(usize, 4) else 0;
    var padding_len = block_size - (aligned_len % block_size);
    if (padding_len < 4) padding_len += block_size;
    const packet_len = payload.len + padding_len + 1;
    if (packet_len > ssh_max_packet_len or out.len < packet_len + 4) return null;
    writeBeU32(out[0..], @intCast(packet_len));
    out[4] = @intCast(padding_len);
    if (payload.len != 0) @memcpy(out[5 .. 5 + payload.len], payload);
    rng.fill(out[5 + payload.len .. 5 + payload.len + padding_len]);
    return packet_len + 4;
}

fn buildServerKexInit(rng: *SessionRng, out: []u8) ?[]const u8 {
    var w = Writer.init(out);
    if (!w.byte(ssh_msg_kexinit)) return null;
    var cookie: [16]u8 = undefined;
    rng.fill(cookie[0..]);
    if (!w.bytes(cookie[0..])) return null;
    if (!w.string(alg_kex_curve25519_libssh)) return null;
    if (!w.string(alg_host_ed25519)) return null;
    if (!w.string(alg_cipher_chacha)) return null;
    if (!w.string(alg_cipher_chacha)) return null;
    if (!w.string(alg_mac_hmac_sha256)) return null;
    if (!w.string(alg_mac_hmac_sha256)) return null;
    if (!w.string(alg_compression_none)) return null;
    if (!w.string(alg_compression_none)) return null;
    if (!w.string("")) return null;
    if (!w.string("")) return null;
    if (!w.byte(0)) return null;
    if (!w.beU32(0)) return null;
    return w.slice();
}

fn parseKexInit(payload: []const u8) ?KexSelection {
    if (payload.len < 17 or payload[0] != ssh_msg_kexinit) return null;
    var r = Reader.init(payload[17..]);
    const kex_list = r.readString() orelse return null;
    const host_key_list = r.readString() orelse return null;
    const cipher_c2s_list = r.readString() orelse return null;
    const cipher_s2c_list = r.readString() orelse return null;
    const mac_c2s_list = r.readString() orelse return null;
    const mac_s2c_list = r.readString() orelse return null;
    const compression_c2s_list = r.readString() orelse return null;
    const compression_s2c_list = r.readString() orelse return null;
    _ = r.readString() orelse return null;
    _ = r.readString() orelse return null;
    const follows = r.readByte() orelse return null;
    _ = r.readU32() orelse return null;
    _ = mac_c2s_list;
    _ = mac_s2c_list;

    const supported_kex = [_][]const u8{alg_kex_curve25519_libssh};
    const kex = chooseName(kex_list, supported_kex[0..]) orelse return null;
    const host_key = chooseName(host_key_list, (&[_][]const u8{alg_host_ed25519})[0..]) orelse return null;
    const cipher_c2s = chooseName(cipher_c2s_list, (&[_][]const u8{alg_cipher_chacha})[0..]) orelse return null;
    const cipher_s2c = chooseName(cipher_s2c_list, (&[_][]const u8{alg_cipher_chacha})[0..]) orelse return null;
    const compression_c2s = chooseName(compression_c2s_list, (&[_][]const u8{alg_compression_none})[0..]) orelse return null;
    const compression_s2c = chooseName(compression_s2c_list, (&[_][]const u8{alg_compression_none})[0..]) orelse return null;
    return .{
        .kex = kex,
        .host_key = host_key,
        .cipher_c2s = cipher_c2s,
        .cipher_s2c = cipher_s2c,
        .compression_c2s = compression_c2s,
        .compression_s2c = compression_s2c,
        .first_kex_packet_follows = follows != 0,
        .first_kex_name = firstName(kex_list),
    };
}

fn chooseName(list: []const u8, supported: []const []const u8) ?[]const u8 {
    var start: usize = 0;
    while (start <= list.len) {
        var end = start;
        while (end < list.len and list[end] != ',') : (end += 1) {}
        const item = list[start..end];
        for (supported) |candidate| {
            if (bytesEq(item, candidate)) return candidate;
        }
        if (end == list.len) break;
        start = end + 1;
    }
    return null;
}

fn firstName(list: []const u8) []const u8 {
    var end: usize = 0;
    while (end < list.len and list[end] != ',') : (end += 1) {}
    return list[0..end];
}

fn buildHostKeyBlob(host_key: *const HostKey, out: []u8) ?[]const u8 {
    return buildHostKeyBlobFromPublic(host_key.public_key[0..], out);
}

fn buildHostKeyBlobFromPublic(public_key: []const u8, out: []u8) ?[]const u8 {
    if (public_key.len != 32) return null;
    var w = Writer.init(out);
    if (!w.string(alg_host_ed25519)) return null;
    if (!w.string(public_key)) return null;
    return w.slice();
}

fn buildKexReply(out: []u8, host_blob: []const u8, server_pub: []const u8, signature: []const u8) ?[]const u8 {
    var sig_blob_buf: [96]u8 = .{0} ** 96;
    var sig_w = Writer.init(sig_blob_buf[0..]);
    if (!sig_w.string(alg_host_ed25519)) return null;
    if (!sig_w.string(signature)) return null;
    const sig_blob = sig_w.slice();

    var w = Writer.init(out);
    if (!w.byte(ssh_msg_kex_ecdh_reply)) return null;
    if (!w.string(host_blob)) return null;
    if (!w.string(server_pub)) return null;
    if (!w.string(sig_blob)) return null;
    return w.slice();
}

fn buildServiceAccept(out: []u8, service: []const u8) ?[]const u8 {
    var w = Writer.init(out);
    if (!w.byte(ssh_msg_service_accept)) return null;
    if (!w.string(service)) return null;
    return w.slice();
}

fn buildDisconnect(out: []u8, reason: u32, message: []const u8) ?[]const u8 {
    var w = Writer.init(out);
    if (!w.byte(ssh_msg_disconnect)) return null;
    if (!w.beU32(reason)) return null;
    if (!w.string(message)) return null;
    if (!w.string("")) return null;
    return w.slice();
}

fn computeExchangeHash(out: *[32]u8, client_ident: []const u8, server_ident: []const u8, client_kex: []const u8, server_kex: []const u8, host_blob: []const u8, client_pub: []const u8, server_pub: []const u8, shared: []const u8) void {
    var h = Sha256.init(.{});
    hashString(&h, client_ident);
    hashString(&h, server_ident);
    hashString(&h, client_kex);
    hashString(&h, server_kex);
    hashString(&h, host_blob);
    hashString(&h, client_pub);
    hashString(&h, server_pub);
    hashMpint(&h, shared);
    h.final(out);
}

fn deriveTransportKeys(keys: *TransportKeys, shared: []const u8, exchange_hash: []const u8) void {
    deriveKey(keys.c2s[0..], shared, exchange_hash, 'C');
    deriveKey(keys.s2c[0..], shared, exchange_hash, 'D');
}

fn deriveKey(out: []u8, shared: []const u8, exchange_hash: []const u8, letter: u8) void {
    var produced: usize = 0;
    while (produced < out.len) {
        var h = Sha256.init(.{});
        hashMpint(&h, shared);
        h.update(exchange_hash);
        if (produced == 0) {
            h.update((&[_]u8{letter})[0..]);
            h.update(exchange_hash);
        } else {
            h.update(out[0..produced]);
        }
        var block: [32]u8 = undefined;
        h.final(&block);
        const n = @min(block.len, out.len - produced);
        @memcpy(out[produced .. produced + n], block[0..n]);
        produced += n;
    }
}

fn encryptChachaPacket(app: *const App, out: []u8, plain_packet: []const u8, key: []const u8, seq: u32) ?usize {
    if (key.len != 64 or plain_packet.len < 5 or out.len < plain_packet.len + 16) return null;
    const body_len = plain_packet.len - 4;
    acquireSshCryptoLock(app);
    chachaXor(out[0..4], plain_packet[0..4], key[32..64], seq, 0);
    chachaXor(out[4 .. 4 + body_len], plain_packet[4..], key[0..32], seq, 1);
    var tag: [16]u8 = undefined;
    poly1305PacketTag(&tag, key[0..32], seq, out[0..4], out[4 .. 4 + body_len]);
    releaseSshCryptoLock();
    @memcpy(out[4 + body_len .. 4 + body_len + 16], tag[0..]);
    return 4 + body_len + 16;
}

fn poly1305PacketTag(out: *[16]u8, key: []const u8, seq: u32, encrypted_len: []const u8, encrypted_body: []const u8) void {
    var poly_key: [32]u8 = .{0} ** 32;
    chachaStream(poly_key[0..], key, seq, 0);
    var mac = Poly1305.init(&poly_key);
    mac.update(encrypted_len);
    mac.update(encrypted_body);
    mac.final(out);
}

fn chachaXor(out: []u8, input: []const u8, key: []const u8, seq: u32, counter: u64) void {
    var key_array: [32]u8 = undefined;
    var nonce: [8]u8 = .{0} ** 8;
    @memcpy(key_array[0..], key[0..32]);
    writeBeU32(nonce[4..], seq);
    ssh_chacha.xor(out, input, counter, key_array, nonce);
}

fn chachaStream(out: []u8, key: []const u8, seq: u32, counter: u64) void {
    var key_array: [32]u8 = undefined;
    var nonce: [8]u8 = .{0} ** 8;
    @memcpy(key_array[0..], key[0..32]);
    writeBeU32(nonce[4..], seq);
    ssh_chacha.stream(out, counter, key_array, nonce);
}

const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    fn init(buf: []u8) Writer {
        return .{ .buf = buf };
    }

    fn byte(self: *Writer, value: u8) bool {
        if (self.pos >= self.buf.len) return false;
        self.buf[self.pos] = value;
        self.pos += 1;
        return true;
    }

    fn bytes(self: *Writer, value: []const u8) bool {
        if (self.pos + value.len > self.buf.len) return false;
        if (value.len != 0) @memcpy(self.buf[self.pos .. self.pos + value.len], value);
        self.pos += value.len;
        return true;
    }

    fn beU32(self: *Writer, value: u32) bool {
        if (self.pos + 4 > self.buf.len) return false;
        writeBeU32(self.buf[self.pos..], value);
        self.pos += 4;
        return true;
    }

    fn beU64(self: *Writer, value: u64) bool {
        if (self.pos + 8 > self.buf.len) return false;
        writeBeU64(self.buf[self.pos..], value);
        self.pos += 8;
        return true;
    }

    fn string(self: *Writer, value: []const u8) bool {
        if (value.len > 0xffff_ffff) return false;
        if (!self.beU32(@intCast(value.len))) return false;
        return self.bytes(value);
    }

    fn slice(self: *const Writer) []const u8 {
        return self.buf[0..self.pos];
    }
};

const Reader = struct {
    data: []const u8,
    pos: usize = 0,

    fn init(data: []const u8) Reader {
        return .{ .data = data };
    }

    fn readByte(self: *Reader) ?u8 {
        if (self.pos >= self.data.len) return null;
        const value = self.data[self.pos];
        self.pos += 1;
        return value;
    }

    fn readU32(self: *Reader) ?u32 {
        if (self.pos + 4 > self.data.len) return null;
        const value = readBeU32(self.data[self.pos..]);
        self.pos += 4;
        return value;
    }

    fn readU64(self: *Reader) ?u64 {
        if (self.pos + 8 > self.data.len) return null;
        const value = readBeU64(self.data[self.pos..]);
        self.pos += 8;
        return value;
    }

    fn readString(self: *Reader) ?[]const u8 {
        const len = self.readU32() orelse return null;
        if (len > self.data.len - self.pos) return null;
        const start = self.pos;
        self.pos += @intCast(len);
        return self.data[start..self.pos];
    }
};

fn hashString(h: *Sha256, value: []const u8) void {
    var len_buf: [4]u8 = undefined;
    writeBeU32(len_buf[0..], @intCast(value.len));
    h.update(len_buf[0..]);
    h.update(value);
}

fn hashMpint(h: *Sha256, value: []const u8) void {
    var first: usize = 0;
    while (first < value.len and value[first] == 0) : (first += 1) {}
    const len = value.len - first;
    const needs_zero = len != 0 and (value[first] & 0x80) != 0;
    var len_buf: [4]u8 = undefined;
    writeBeU32(len_buf[0..], @intCast(len + if (needs_zero) @as(usize, 1) else 0));
    h.update(len_buf[0..]);
    if (needs_zero) h.update((&[_]u8{0})[0..]);
    if (len != 0) h.update(value[first..]);
}

fn hashU64(h: *Sha256, value: u64) void {
    var buf: [8]u8 = undefined;
    buf[0] = @intCast((value >> 56) & 0xff);
    buf[1] = @intCast((value >> 48) & 0xff);
    buf[2] = @intCast((value >> 40) & 0xff);
    buf[3] = @intCast((value >> 32) & 0xff);
    buf[4] = @intCast((value >> 24) & 0xff);
    buf[5] = @intCast((value >> 16) & 0xff);
    buf[6] = @intCast((value >> 8) & 0xff);
    buf[7] = @intCast(value & 0xff);
    h.update(buf[0..]);
}

fn hashU32(h: *Sha256, value: u32) void {
    var buf: [4]u8 = undefined;
    writeBeU32(buf[0..], value);
    h.update(buf[0..]);
}

fn writeBeU32(out: []u8, value: u32) void {
    out[0] = @intCast((value >> 24) & 0xff);
    out[1] = @intCast((value >> 16) & 0xff);
    out[2] = @intCast((value >> 8) & 0xff);
    out[3] = @intCast(value & 0xff);
}

fn writeLeU32(out: []u8, value: u32) void {
    out[0] = @intCast(value & 0xff);
    out[1] = @intCast((value >> 8) & 0xff);
    out[2] = @intCast((value >> 16) & 0xff);
    out[3] = @intCast((value >> 24) & 0xff);
}

fn writeBeU64(out: []u8, value: u64) void {
    out[0] = @intCast((value >> 56) & 0xff);
    out[1] = @intCast((value >> 48) & 0xff);
    out[2] = @intCast((value >> 40) & 0xff);
    out[3] = @intCast((value >> 32) & 0xff);
    out[4] = @intCast((value >> 24) & 0xff);
    out[5] = @intCast((value >> 16) & 0xff);
    out[6] = @intCast((value >> 8) & 0xff);
    out[7] = @intCast(value & 0xff);
}

fn readBeU32(data: []const u8) u32 {
    return (@as(u32, data[0]) << 24) |
        (@as(u32, data[1]) << 16) |
        (@as(u32, data[2]) << 8) |
        @as(u32, data[3]);
}

fn readBeU64(data: []const u8) u64 {
    return (@as(u64, data[0]) << 56) |
        (@as(u64, data[1]) << 48) |
        (@as(u64, data[2]) << 40) |
        (@as(u64, data[3]) << 32) |
        (@as(u64, data[4]) << 24) |
        (@as(u64, data[5]) << 16) |
        (@as(u64, data[6]) << 8) |
        @as(u64, data[7]);
}

fn runPingClient(app: *const App) i32 {
    app.sys.println("SSHD ping");
    var info: r4os.abi.ServiceInfo = .{};
    const handle = waitServiceOpen(app, &info, 100) orelse {
        app.sys.println("SSHD ping failed: service not open");
        return 1;
    };
    defer _ = app.sys.serviceClose(handle);

    var header: r4os.abi.ServiceMessageHeader = .{};
    var response: [32]u8 = undefined;
    const got = app.sys.serviceCall(handle, op_ping, "PING", &header, response[0..], 100);
    if (got != 9 or header.status != r4os.abi.service_api_result_ok or !bytesEq(response[0..9], "SSHD PONG")) {
        app.sys.println("SSHD ping failed");
        return 1;
    }
    app.sys.println("SSHD ping: OK");
    return 0;
}

fn runStatusClient(app: *const App) i32 {
    app.sys.println("SSHD status");
    var info: r4os.abi.ServiceInfo = .{};
    const handle = waitServiceOpen(app, &info, 100) orelse {
        app.sys.println("SSHD status failed: service not open");
        return 1;
    };
    defer _ = app.sys.serviceClose(handle);

    var header: r4os.abi.ServiceMessageHeader = .{};
    var response: [r4os.abi.service_api_max_payload]u8 = undefined;
    const got = app.sys.serviceCall(handle, op_status, "STATUS", &header, response[0..], 100);
    if (got <= 0 or header.status != r4os.abi.service_api_result_ok) {
        app.sys.println("SSHD status failed");
        return 1;
    }
    app.sys.write(response[0..@intCast(got)]);
    app.sys.println("");
    return 0;
}

fn runSelfTest(app: *const App) i32 {
    app.sys.println("SSHD selftest");
    if (!app.sys.hasFn("service_call")) return fail(app, "service-api");
    const repairs = ensureRegistryDefaults(app);
    var config = loadConfig(app);
    if (config.listen_port != default_listen_port) return fail(app, "listen-port");
    if (config.max_sessions != default_max_sessions) return fail(app, "max-sessions");
    if (!bytesEq(spanZ(config.user_name[0..]), default_user_name)) return fail(app, "user");
    if (!bytesEq(spanZ(config.password[0..]), default_password)) return fail(app, "password");
    app.sys.write("SSHD selftest: OK repairs=");
    app.sys.printU64(@intCast(repairs));
    app.sys.println("");
    return 0;
}

fn waitServiceOpen(app: *const App, info: *r4os.abi.ServiceInfo, max_ticks: u32) ?u32 {
    var tick: u32 = 0;
    while (tick < max_ticks) : (tick += 1) {
        const rc = app.sys.serviceOpen(service_name, info);
        if (rc == r4os.abi.service_api_result_ok and info.handle != 0) return info.handle;
        app.sys.sleepTicks(1);
    }
    const rc = app.sys.serviceOpen(service_name, info);
    if (rc == r4os.abi.service_api_result_ok and info.handle != 0) return info.handle;
    return null;
}

fn ensureRegistryDefaults(app: *const App) u32 {
    if (!app.sys.hasFn("registry_get_value") or !app.sys.hasFn("registry_set_value")) return 0;
    var changed: u32 = 0;
    changed += ensureBool(app, "Enabled", default_enabled);
    changed += ensureString(app, "ClientTarget", default_client_target);
    changed += ensureString(app, "UserName", default_user_name);
    changed += ensureString(app, "Password", default_password);
    changed += ensureU32(app, "ListenPort", @intCast(default_listen_port));
    changed += ensureU32(app, "MaxSessions", default_max_sessions);
    changed += ensureBool(app, "LogPasswords", default_log_passwords);
    changed += ensureString(app, "ShellPath", default_shell_path);
    changed += ensureString(app, "ShellArgs", default_shell_args);
    changed += ensureString(app, "SftpRoot", default_sftp_root);
    changed += ensureString(app, "HostKeyType", default_host_key_type);
    if (changed != 0) {
        app.sys.write("SSHD Registry defaults repaired=");
        app.sys.printU64(@intCast(changed));
        app.sys.println("");
    }
    return changed;
}

fn loadOrCreateHostKey(app: *const App, stats: *ServiceStats) ?HostKey {
    if (!app.sys.hasFn("registry_get_value") or !app.sys.hasFn("registry_set_value")) {
        setLastProtocolError(stats, "registry-missing");
        return null;
    }

    var seed: [32]u8 = .{0} ** 32;
    var public_key: [32]u8 = .{0} ** 32;
    const seed_state = readRegistryBinaryExact(app, registry_host_key_seed, seed[0..]);
    const public_state = readRegistryBinaryExact(app, registry_host_key_public, public_key[0..]);

    if (seed_state == .missing and public_state == .missing) {
        seed = generateHostKeySeed(app);
        const kp = Ed25519.KeyPair.generateDeterministic(seed) catch {
            stats.crypto_errors +%= 1;
            setLastProtocolError(stats, "hostkey-generate");
            return null;
        };
        public_key = kp.public_key.toBytes();
        if (app.sys.registrySetBinary(registry_key, registry_host_key_seed, seed[0..]) != r4os.abi.registry_api_result_ok or
            app.sys.registrySetBinary(registry_key, registry_host_key_public, public_key[0..]) != r4os.abi.registry_api_result_ok)
        {
            stats.crypto_errors +%= 1;
            setLastProtocolError(stats, "hostkey-store");
            app.sys.println("SSHD host key store failed");
            return null;
        }
        stats.host_key_generated +%= 1;
        app.sys.println("SSHD host key generated: ed25519");
        return .{ .seed = seed, .public_key = public_key, .key_pair = kp };
    }

    if (seed_state != .ok or public_state != .ok) {
        stats.crypto_errors +%= 1;
        setLastProtocolError(stats, "hostkey-invalid");
        app.sys.println("SSHD host key invalid in Registry");
        return null;
    }

    const kp = Ed25519.KeyPair.generateDeterministic(seed) catch {
        stats.crypto_errors +%= 1;
        setLastProtocolError(stats, "hostkey-seed");
        return null;
    };
    const expected = kp.public_key.toBytes();
    if (!bytesEq(expected[0..], public_key[0..])) {
        stats.crypto_errors +%= 1;
        setLastProtocolError(stats, "hostkey-mismatch");
        app.sys.println("SSHD host key mismatch in Registry");
        return null;
    }

    stats.host_key_loaded +%= 1;
    app.sys.println("SSHD host key loaded: ed25519");
    return .{ .seed = seed, .public_key = public_key, .key_pair = kp };
}

const RegistryBinaryState = enum {
    ok,
    missing,
    invalid,
};

fn readRegistryBinaryExact(app: *const App, name: [*:0]const u8, out: []u8) RegistryBinaryState {
    var info: r4os.abi.RegistryValueInfo = .{};
    var data: [96]u8 = .{0} ** 96;
    const rc = app.sys.registryGetValue(registry_key, name, &info, data[0..]);
    if (rc < 0) return .missing;
    if (info.value_type != r4os.abi.registry_value_type_binary) return .invalid;
    if (info.data_len != out.len or rc != @as(i32, @intCast(out.len))) return .invalid;
    @memcpy(out, data[0..out.len]);
    return .ok;
}

fn generateHostKeySeed(app: *const App) [32]u8 {
    var h = Sha256.init(.{});
    h.update("R4OS SSHD 0.52.8 ed25519 host key");
    hashU64(&h, app.sys.ticks());
    const time_state = app.sys.timeState();
    hashU64(&h, time_state.monotonic_ticks);
    hashU32(&h, time_state.seconds_since_midnight);
    hashU32(&h, @intCast(time_state.year));
    hashU32(&h, time_state.month);
    hashU32(&h, time_state.day);
    hashU32(&h, time_state.hour);
    hashU32(&h, time_state.minute);
    hashU32(&h, time_state.second);
    var net_config: r4os.abi.NetConfigSnapshot = .{};
    if (app.net.netConfigGet(&net_config) == 0) {
        h.update(&net_config.mac);
        h.update(&net_config.local_ip);
        h.update(&net_config.gateway_ip);
    }
    var out: [32]u8 = undefined;
    h.final(&out);
    if (allZero(out[0..])) out[0] = 1;
    return out;
}

fn ensureString(app: *const App, name: [*:0]const u8, value: []const u8) u32 {
    if (registryValueExists(app, name)) return 0;
    return if (app.sys.registrySetString(registry_key, name, value) == r4os.abi.registry_api_result_ok) 1 else 0;
}

fn ensureU32(app: *const App, name: [*:0]const u8, value: u32) u32 {
    if (registryValueExists(app, name)) return 0;
    return if (app.sys.registrySetU32(registry_key, name, value) == r4os.abi.registry_api_result_ok) 1 else 0;
}

fn ensureBool(app: *const App, name: [*:0]const u8, value: bool) u32 {
    if (registryValueExists(app, name)) return 0;
    return if (app.sys.registrySetBool(registry_key, name, value) == r4os.abi.registry_api_result_ok) 1 else 0;
}

fn registryValueExists(app: *const App, name: [*:0]const u8) bool {
    var info: r4os.abi.RegistryValueInfo = .{};
    var data: [256]u8 = .{0} ** 256;
    const rc = app.sys.registryGetValue(registry_key, name, &info, data[0..]);
    return rc >= 0 or rc == r4os.abi.registry_api_result_buffer_too_small;
}

fn loadConfig(app: *const App) Config {
    var config = Config{};
    copyFixedZ(config.user_name[0..], default_user_name);
    copyFixedZ(config.password[0..], default_password);
    copyFixedZ(config.shell_path[0..], default_shell_path);
    copyFixedZ(config.shell_args[0..], default_shell_args);
    copyFixedZ(config.sftp_root[0..], default_sftp_root);
    copyFixedZ(config.host_key_type[0..], default_host_key_type);

    if (!app.sys.hasFn("registry_get_value")) return config;
    config.enabled = readRegistryBool(app, "Enabled") orelse config.enabled;
    if (readRegistryU32(app, "ListenPort")) |port_raw| {
        if (port_raw > 0 and port_raw <= 65535) config.listen_port = @intCast(port_raw);
    }
    config.max_sessions = readRegistryU32(app, "MaxSessions") orelse config.max_sessions;
    if (config.max_sessions == 0) config.max_sessions = 1;
    config.log_passwords = readRegistryBool(app, "LogPasswords") orelse config.log_passwords;
    _ = readRegistryString(app, "UserName", config.user_name[0..]);
    _ = readRegistryString(app, "Password", config.password[0..]);
    _ = readRegistryString(app, "ShellPath", config.shell_path[0..]);
    _ = readRegistryString(app, "ShellArgs", config.shell_args[0..]);
    _ = readRegistryString(app, "SftpRoot", config.sftp_root[0..]);
    _ = readRegistryString(app, "HostKeyType", config.host_key_type[0..]);
    return config;
}

fn readRegistryString(app: *const App, name: [*:0]const u8, out: []u8) bool {
    var info: r4os.abi.RegistryValueInfo = .{};
    var data: [160]u8 = .{0} ** 160;
    const rc = app.sys.registryGetValue(registry_key, name, &info, data[0..]);
    if (rc < 0) return false;
    if (info.value_type != r4os.abi.registry_value_type_string) return false;
    const got: usize = @intCast(rc);
    const available = @min(@min(got, @as(usize, @intCast(info.data_len))), data.len);
    copyFixedZ(out, data[0..available]);
    return true;
}

fn readRegistryU32(app: *const App, name: [*:0]const u8) ?u32 {
    var info: r4os.abi.RegistryValueInfo = .{};
    var data: [4]u8 = .{0} ** 4;
    const rc = app.sys.registryGetValue(registry_key, name, &info, data[0..]);
    if (rc < 0) return null;
    if (info.value_type != r4os.abi.registry_value_type_u32 or info.data_len != 4) return null;
    return @as(u32, data[0]) |
        (@as(u32, data[1]) << 8) |
        (@as(u32, data[2]) << 16) |
        (@as(u32, data[3]) << 24);
}

fn readRegistryBool(app: *const App, name: [*:0]const u8) ?bool {
    var info: r4os.abi.RegistryValueInfo = .{};
    var data: [1]u8 = .{0};
    const rc = app.sys.registryGetValue(registry_key, name, &info, data[0..]);
    if (rc < 0) return null;
    if (info.value_type != r4os.abi.registry_value_type_bool or info.data_len != 1) return null;
    return data[0] != 0;
}

fn fail(app: *const App, label: []const u8) i32 {
    app.sys.write("SSHD selftest FAILED: ");
    app.sys.println(label);
    return 1;
}

fn hasArg(args: [*:0]const u8, wanted: []const u8) bool {
    var offset: usize = 0;
    while (offset < 256 and args[offset] != 0) {
        while (offset < 256 and (args[offset] == ' ' or args[offset] == '\t')) : (offset += 1) {}
        const start = offset;
        while (offset < 256 and args[offset] != 0 and args[offset] != ' ' and args[offset] != '\t') : (offset += 1) {}
        if (equalsIgnoreCase(args[start..offset], wanted)) return true;
    }
    return false;
}

fn copyFixedZ(dest: []u8, src: []const u8) void {
    if (dest.len == 0) return;
    @memset(dest, 0);
    const len = @min(dest.len - 1, src.len);
    if (len != 0) @memcpy(dest[0..len], src[0..len]);
}

fn appendChecked(dest: []u8, pos: *usize, src: []const u8) bool {
    if (pos.* + src.len >= dest.len) return false;
    if (src.len != 0) @memcpy(dest[pos.* .. pos.* + src.len], src);
    pos.* += src.len;
    return true;
}

fn spanZ(value: []const u8) []const u8 {
    var len: usize = 0;
    while (len < value.len and value[len] != 0) : (len += 1) {}
    return value[0..len];
}

fn trimSpaces(value: []const u8) []const u8 {
    var start: usize = 0;
    var end: usize = value.len;
    while (start < end and (value[start] == ' ' or value[start] == '\t' or value[start] == '\r' or value[start] == '\n')) : (start += 1) {}
    while (end > start and (value[end - 1] == ' ' or value[end - 1] == '\t' or value[end - 1] == '\r' or value[end - 1] == '\n')) : (end -= 1) {}
    return value[start..end];
}

fn isSpace(ch: u8) bool {
    return ch == ' ' or ch == '\t' or ch == '\r' or ch == '\n';
}

fn bytesEq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

fn allZero(value: []const u8) bool {
    var acc: u8 = 0;
    for (value) |b| acc |= b;
    return acc == 0;
}

fn setLastProtocolError(stats: *ServiceStats, value: []const u8) void {
    copyFixedZ(stats.last_protocol_error[0..], value);
}

fn noteSessionKind(stats: *ServiceStats, kind: []const u8, command: []const u8) void {
    copyFixedZ(stats.last_session_kind[0..], kind);
    copyFixedZ(stats.last_exec_command[0..], command);
}

fn noteCloseReason(stats: *ServiceStats, reason: []const u8) void {
    copyFixedZ(stats.last_close_reason[0..], reason);
}

fn noteChannelExit(stats: *ServiceStats, exit_code: i32) void {
    stats.last_channel_exit = exit_code;
}

fn logAuthAttempt(app: *const App, config: *const Config, attempt: AuthAttempt) void {
    var message: [r4os.abi.log_service_text_bytes]u8 = .{0} ** r4os.abi.log_service_text_bytes;
    var pos: usize = 0;
    appendText(message[0..], &pos, "auth attempt user=");
    appendText(message[0..], &pos, attempt.user);
    appendText(message[0..], &pos, " method=");
    appendText(message[0..], &pos, attempt.method);
    if (config.log_passwords and attempt.password.len != 0) {
        appendText(message[0..], &pos, " password=");
        appendText(message[0..], &pos, attempt.password);
    }
    logServiceEvent(app, r4os.abi.log_severity_debug, message[0..pos]);
}

fn logAuthFailure(app: *const App, config: *const Config, attempt: AuthAttempt) void {
    var message: [r4os.abi.log_service_text_bytes]u8 = .{0} ** r4os.abi.log_service_text_bytes;
    var pos: usize = 0;
    appendText(message[0..], &pos, "auth FAILED user=");
    appendText(message[0..], &pos, attempt.user);
    appendText(message[0..], &pos, " method=");
    appendText(message[0..], &pos, attempt.method);
    if (config.log_passwords and attempt.password.len != 0) {
        appendText(message[0..], &pos, " password=");
        appendText(message[0..], &pos, attempt.password);
    }
    logServiceEvent(app, r4os.abi.log_severity_warn, message[0..pos]);
}

fn logAuthSuccess(app: *const App, attempt: AuthAttempt) void {
    var message: [r4os.abi.log_service_text_bytes]u8 = .{0} ** r4os.abi.log_service_text_bytes;
    var pos: usize = 0;
    appendText(message[0..], &pos, "auth OK user=");
    appendText(message[0..], &pos, attempt.user);
    logServiceEvent(app, r4os.abi.log_severity_info, message[0..pos]);
}

fn logShellStarted(app: *const App, instance_id: u32) void {
    var message: [r4os.abi.log_service_text_bytes]u8 = .{0} ** r4os.abi.log_service_text_bytes;
    var pos: usize = 0;
    appendText(message[0..], &pos, "shell started instance=");
    appendU64(message[0..], &pos, instance_id);
    logServiceEvent(app, r4os.abi.log_severity_info, message[0..pos]);
}

fn logExecStarted(app: *const App, instance_id: u32, command: []const u8) void {
    var message: [r4os.abi.log_service_text_bytes]u8 = .{0} ** r4os.abi.log_service_text_bytes;
    var pos: usize = 0;
    appendText(message[0..], &pos, "exec started instance=");
    appendU64(message[0..], &pos, instance_id);
    appendText(message[0..], &pos, " command=");
    appendText(message[0..], &pos, command);
    logServiceEvent(app, r4os.abi.log_severity_info, message[0..pos]);
}

fn logScpStarted(app: *const App, mode: ScpMode, command: []const u8) void {
    var message: [r4os.abi.log_service_text_bytes]u8 = .{0} ** r4os.abi.log_service_text_bytes;
    var pos: usize = 0;
    appendText(message[0..], &pos, "scp ");
    appendText(message[0..], &pos, if (mode == .source) "source" else "sink");
    appendText(message[0..], &pos, " command=");
    appendText(message[0..], &pos, command);
    logServiceEvent(app, r4os.abi.log_severity_info, message[0..pos]);
}

fn logServiceEvent(app: *const App, severity: u8, message: []const u8) void {
    _ = app.sys.logServiceWriteRecord(r4os.abi.log_service_source_service, r4os.abi.log_record_type_event, severity, log_origin, message);
}

fn equalsIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (upper(a[i]) != upper(b[i])) return false;
    }
    return true;
}

fn upper(ch: u8) u8 {
    if (ch >= 'a' and ch <= 'z') return ch - ('a' - 'A');
    return ch;
}

fn appendText(out: []u8, pos: *usize, text: []const u8) void {
    var i: usize = 0;
    while (i < text.len and pos.* < out.len) : (i += 1) {
        out[pos.*] = text[i];
        pos.* += 1;
    }
}

fn appendI32(out: []u8, pos: *usize, value: i32) void {
    if (value < 0) {
        appendText(out, pos, "-");
        appendU64(out, pos, @intCast(-@as(i64, value)));
    } else {
        appendU64(out, pos, @intCast(value));
    }
}

fn appendU64(out: []u8, pos: *usize, value: u64) void {
    var tmp: [20]u8 = .{0} ** 20;
    var n = value;
    var len: usize = 0;
    if (n == 0) {
        appendText(out, pos, "0");
        return;
    }
    while (n != 0 and len < tmp.len) : (len += 1) {
        tmp[len] = @intCast('0' + (n % 10));
        n /= 10;
    }
    while (len != 0) {
        len -= 1;
        if (pos.* >= out.len) return;
        out[pos.*] = tmp[len];
        pos.* += 1;
    }
}
