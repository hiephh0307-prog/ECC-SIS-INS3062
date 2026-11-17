"use strict";

(function () {
  const LANG_STORAGE_KEY = "ecc_sis_lang";

  const DICT = {
    en: {
      page_title: "ECC-SIS | Secure Information System (P-256 End-to-End Encryption)",
      brand_subtitle: "Secure Information System",
      mode_backend: "Mode: Python FastAPI + SQLite",
      mode_standalone: "Mode: Browser Hybrid Engine (GitHub Pages)",

      nav_sis: "E2EE Messaging & Files",
      nav_lab: "ECC Cryptography Lab",
      nav_bench: "Speed Race: ECC vs RSA",
      nav_audit: "Audit Log & Architecture",

      active_identity_label: "ACTIVE IDENTITY",
      not_logged_in: "Not signed in",
      key_not_loaded: "No key loaded",
      quick_switch_label: "Quick Demo Persona Switch",
      btn_demo_alice: "👩 Alice (Sender)",
      btn_demo_bob: "👨 Bob (Recipient)",

      spec_engine_lbl: "Core Engine:",
      spec_engine_val: "Pure Python (From Scratch)",
      spec_coord_lbl: "Projective Coords:",
      spec_coord_val: "Jacobian (~5.4x Speedup)",
      spec_curves_lbl: "Curves:",
      spec_sig_lbl: "Signature Std:",

      secure_ctx_warn:
        "⚠️ Open via <code>https://</code>, <code>http://localhost:8000</code>, or <code>http://127.0.0.1:8000</code> to enable WebCrypto P-256.",

      persona_open_lbl: "ACTIVE ACCOUNT:",
      ecdsa_badge_on: "ECDSA Signature Auth: Enabled",
      role_sender_p256: "Sender (P-256)",
      role_recipient_p256: "Recipient (P-256)",
      other_account: "Custom Account",
      passkey_login_sub: "Passkey Sign-In",

      badge_zero_trust: "⚡ ZERO-TRUST ARCHITECTURE",
      badge_zk_server: "Zero-Knowledge Server",
      pipeline_title: "End-to-End Data Protection Pipeline (P-256 E2EE)",
      pipeline_desc:
        "Private keys never leave your browser. The server stores only ciphertext. Digital signatures block every tampering attempt.",
      btn_run_5s: "Run 5-Second Live Simulation",
      btn_running_5s: "Running Alice ➔ Server ➔ Bob simulation...",

      step1_num: "STEP 1",
      step1_role: "ALICE'S BROWSER",
      step1_name: "Alice (Sender)",
      step1_c1: "🔑 Ephemeral ECDH Key (P-256)",
      step1_c2: "🔒 AES-256-GCM Encryption",
      step1_c3: "✍️ ECDSA Signature (RFC 6979)",
      step1_foot: "🔒 Encrypted locally on client",
      packet1_lbl: "Sealed Ciphertext",

      step2_num: "STEP 2",
      step2_role: "RELAY SERVER",
      step2_name: "FastAPI / Relay Store",
      step2_c1: "🔒 Stores only Hex strings in DB",
      step2_c2: "🚫 0 bytes of plaintext (Zero-Knowledge)",
      step2_c3: "🛡️ Holds zero decryption keys",
      step2_foot: "🛡️ Unreadable even if DB leaks",
      packet2_lbl: "Forwards envelope",

      step3_num: "STEP 3",
      step3_role: "BOB'S BROWSER",
      step3_name: "Bob (Recipient)",
      step3_c1: "✅ Verifies Alice's ECDSA signature",
      step3_c2: "🔑 Derives shared secret (ECDH)",
      step3_c3: "💬 Decrypts & renders original data",
      step3_foot: "🎉 Only Bob can unlock",

      sim_proof_title: "🔍 LIVE PROOF: WHAT THE SERVER SEES VS WHAT BOB SEES",
      btn_close: "✕ Close",
      sim_server_col_title: "Server sees meaningless ciphertext only:",
      sim_server_col_note: "Server is completely blind to plaintext (Zero-Knowledge).",
      sim_bob_col_title: "Bob decrypts plaintext with his private key:",
      sim_bob_col_note: "ECDSA Signature: VALID ✅ | AES-GCM Auth Tag: VALID ✅",
      sim_sample_msg: "Top-Secret Wire Approval Code: X9A-772-ECC [5s Live Simulation]",
      sim_zero_bytes: "0 BYTES STORED (Zero-Knowledge Relay Server)",
      sim_bob_verified_lines:
        '"{text}"\n\nIntegrity Verification:\n✓ Alice\'s ECDSA Signature: AUTHENTIC & VALID ✅\n✓ AES-256-GCM Auth Tag: 100% MATCH ✅',

      compose_title: "🔒 Compose Encrypted Message or Confidential File",
      lbl_recipient: "Recipient",
      lbl_file: "Attach file (Optional, max 5 MB)",
      lbl_presets: "Quick presets:",
      btn_preset1: "💰 $20k Wire Approval",
      btn_preset2: "📄 NDA Security Contract",
      preset1_text: "Approve wire transfer of $20,000 USD (500,000,000 VND) to partner #8821.",
      preset2_text: "Confidential Information Security & Financial Integrity Agreement v2026.",
      lbl_plaintext: "Confidential message / File note",
      ph_plaintext: "Type confidential message or attachment note here...",
      btn_send_enc: "Encrypt & Sign (Send Now)",

      passkey_card_title: "👤 Register New Account (Passkey)",
      badge_passwordless: "Passwordless Auth",
      passkey_desc:
        "Your browser generates a P-256 keypair stored locally. No password is ever transmitted over the network.",
      lbl_username: "Username",
      ph_username: "e.g. auditor_01",
      lbl_display_name: "Display Name",
      ph_display_name: "e.g. Alex Auditor",
      btn_register_login: "Generate P-256 Key & Register",
      btn_challenge_login: "Sign In with Saved Key",

      inspector_title: "☁️ Raw Ciphertext in Server Database (Zero-Knowledge Inspector)",
      inspector_desc:
        "Exact JSON records stored inside the SQLite <code>messages</code> table. 100% hex ciphertext — zero plaintext!",
      badge_server_blind: "Server Cannot Read Plaintext",

      inbox_title: "📥 Encrypted Mailbox & Sent Envelopes",
      inbox_desc:
        "Envelopes are verified and decrypted directly inside your browser using your private key.",
      btn_refresh_inbox: "↻ Refresh Mailbox",
      btn_toggle_inspector: "👁️ Inspect Server DB",
      loading_inbox: "Loading encrypted mailbox...",
      empty_inbox: "Mailbox of @{user} has no encrypted envelopes yet.",

      badge_from: "📥 From @{user}",
      badge_to: "📤 To @{user}",
      badge_sig_ok: "✓ Authentic Signature",
      badge_sig_err: "❌ Forged Signature",
      btn_tamper: "⚡ Simulate Hacker 1-Bit Tamper",
      btn_tamper_title: "Flip 1 byte in DB ciphertext to test tamper detection",
      unlocked_file: "📄 Unlocked File: {name} ({size} bytes)",
      file_note: 'Note: "{note}"',
      btn_download_file: "⬇ Download Decrypted File",
      sender_copy_note: "🔒 Encrypted copy sealed exclusively for the recipient's private key (Forward Secrecy).",
      tamper_alert_title: "🚨 TAMPERING / FORGERY DETECTED! (Packet #{id})",
      tamper_zero_trust_note:
        "🛡️ <strong>Zero-Trust Principle:</strong> ECDSA signature or AES-GCM authentication tag mismatch. Decryption blocked automatically!",
      lbl_eph_key: "Ephemeral PubKey:",
      lbl_db_cipher: "DB Ciphertext:",

      err_ecdsa_verify:
        "ECDSA signature verification FAILED! Packet was altered in transit/storage or sender was forged.",
      err_gcm_tag:
        "AES-256-GCM Authentication Tag FAILED! Ciphertext or AAD metadata was unauthorizedly modified.",
      err_user_exists_diff_key:
        "User '{user}' already exists on server with a different public key. Please choose a new username.",
      msg_logged_in_as: "Authenticated as {name} (@{user}) via ECDSA Challenge-Response.",
      err_enter_username: "Please enter a username.",
      msg_registered_ok:
        "Generated P-256 keypair, registered '{user}', and authenticated via ECDSA Challenge-Response!",
      err_enter_username_login: "Enter a username to sign in with its browser-stored private key.",
      err_no_local_key: "No local P-256 private key found in this browser for '{user}'.",
      msg_challenge_ok: "Authenticated '{user}' via one-time ECDSA Challenge-Response!",
      err_login_first: "Please sign in before sending an encrypted envelope.",
      err_pick_recipient: "Please select a valid recipient.",
      err_file_too_large: "Attachment exceeds the 5 MB demo limit.",
      err_empty_payload: "Please enter a message or attach a file.",
      msg_sent_ok: "Encrypted ({bytes} bytes) & ECDSA-signed envelope delivered to @{user}.",

      lab_header_title: "ECC Algorithm & Cryptographic Research Lab",
      lab_header_desc:
        "Powered by our from-scratch <code>ecc_core</code> engine (Finite-field Affine, Jacobian projective speedup, ECDH, RFC 6979 ECDSA, ECIES)",
      toy_curve_title: "Finite-Field Elliptic Curve Plot (<code>toy_p97</code>)",
      toy_curve_desc:
        "Equation: <code>y² ≡ x³ + 3x + 2 (mod 97)</code>, prime order <code>n = 103</code>, generator <code>G = (2, 4)</code>",
      leg_all: "Curve points",
      leg_p: "Point P",
      leg_q: "Point Q",
      leg_neg: "Intersection -(P+Q)",
      leg_sum: "Sum P+Q",
      leg_kp: "Scalar k·P",
      leg_secant: "— Line P&Q",
      leg_refl: "--- Reflection axis",

      point_ops_title: "Point Addition & Bit-by-Bit Scalar Multiplication (Double-and-Add)",
      lbl_point_p: "Point P (x, y)",
      lbl_point_q: "Point Q (x, y)",
      lbl_scalar_k: "Scalar k",
      btn_compute_ops: "Compute P + Q, 2P & k·P",
      infinity_pt: "Infinity (𝒪)",
      ops_sum_1: "1. Point Addition:",
      ops_sum_inter: "3rd collinear point is -(P+Q) =",
      ops_sum_refl: "reflected across x-axis",
      ops_sum_2: "2. Point Doubling:",
      ops_sum_3: "3. Scalar Mul:",
      ops_bin: "binary",
      th_step: "Step",
      th_bit: "Bit",
      th_double: "After Double (2R)",
      th_add: "Add P?",
      th_result: "Accumulator",
      val_yes: "Yes",
      val_no: "No",

      ecdh_card_title: "ECDH Key Exchange + HKDF",
      lbl_curve: "Elliptic Curve",
      btn_run_ecdh: "Run ECDH Handshake",
      click_to_run: "Click button above to execute...",

      ecdsa_card_title: "ECDSA Signing & Sony PS3 Nonce Attack",
      lbl_ecdsa_msg: "Message to sign",
      val_ecdsa_msg: "Approve wire transfer #9021",
      lbl_nonce_reuse: "Simulate reused Nonce k (Sony PS3 Private Key Recovery)",
      btn_run_ecdsa: "Sign, Verify & Run Attack Demo",

      ecies_card_title: "ECIES Seal & Tamper Test",
      lbl_ecies_msg: "Secret plaintext",
      val_ecies_msg: "Classified National Report 2026",
      lbl_ecies_tamper: "Corrupt 1 ciphertext byte (Simulate MITM attacker)",
      btn_run_ecies: "Run ECIES Pipeline",

      bench_header_title: "Speed Race: ECC vs RSA Performance Benchmark",
      bench_header_desc:
        "Live measurement at equivalent NIST SP 800-57 security levels + Projective Jacobian vs Affine speedup",
      btn_quick_bench: "▶ Quick Benchmark (~1s)",
      btn_full_bench: "▶ Full Benchmark (+RSA-3072)",
      coord_card_title: "Coordinate Optimization: Jacobian vs Affine (<code>secp256r1</code>)",
      coord_card_wait: "Click a benchmark button above to measure Affine vs Jacobian speedup.",
      size_chart_title: "Public Key & Signature Size Comparison (Bytes)",
      bench_table_title: "Live Execution Time Results (Milliseconds — ms)",
      bench_table_wait: 'Click "Quick Benchmark" or "Full Benchmark" above to run live measurements.',
      bench_running: "Running live cryptographic benchmark ({mode})...",
      mode_quick: "Quick",
      mode_full: "Full + RSA-3072",
      coord_curve: "Curve:",
      coord_iters: "iterations",
      coord_affine: "Affine Scalar Multiplication:",
      coord_jacobian: "Projective Jacobian Multiplication:",
      coord_badge: "Jacobian Speedup: {x}x faster",
      coord_note: "(eliminates per-bit modular inversion mod_inv)",

      th_algo: "Algorithm",
      th_sec_bits: "Security Level",
      th_pubkey: "Public Key (Comp / Raw)",
      th_sig_size: "Signature Size",
      th_keygen: "KeyGen (ms)",
      th_sign: "Sign (ms)",
      th_verify: "Verify (ms)",
      th_ecdh_enc: "ECDH / Enc-Dec (ms)",

      nist_table_title: "NIST SP 800-57 Security Equivalence & Bandwidth Savings",
      th_nist_lvl: "NIST Security Level",
      th_ecc_bits: "ECC Key (bits)",
      th_rsa_bits: "RSA Key (bits)",
      th_ecc_bytes: "ECC PubKey (Bytes)",
      th_rsa_bytes: "RSA PubKey (Bytes)",
      th_ratio: "Size Reduction (RSA / ECC)",
      badge_smaller: "{x}x smaller",

      audit_header_title: "SHA-256 Hash-Chained Audit Log & Security Architecture",
      audit_header_desc:
        "Every security event is cryptographically chained like a mini-blockchain: <code>H_i = SHA256(H_{i-1} || timestamp || actor || action || details)</code>",
      btn_verify_audit: "✓ Verify Hash-Chain Integrity",
      audit_valid_msg:
        "Hash chain is 100% INTACT across all {n} records. Head Hash: {hash}",
      audit_broken_msg: "Hash chain BROKEN at ID #{id}: {reason}",

      arch_main_title: "4-Layer Defense-in-Depth Architecture",
      arch1_t: "1. Passwordless Passkey Auth",
      arch1_p:
        "Each user holds a local P-256 keypair and signs a one-time 120s server challenge (zero password exposure, replay-proof).",
      arch2_t: "2. Ephemeral Forward Secrecy",
      arch2_p:
        "Every message/file generates a fresh ephemeral keypair <code>(k, kG)</code>, derives an HKDF-SHA256 key, and seals with AES-256-GCM.",
      arch3_t: "3. Non-Repudiation Signatures",
      arch3_p:
        "Sender signs the entire envelope with RFC 6979 ECDSA. Both relay server and recipient verify authenticity before opening.",
      arch4_t: "4. Zero-Knowledge Storage",
      arch4_p:
        "Database stores only hex ciphertexts, public keys, and signatures. Even a compromised DB reveals 0 bytes of plaintext.",

      audit_table_title: "System Security Event Ledger",
      th_id: "ID",
      th_time: "Timestamp (UTC)",
      th_actor: "Actor",
      th_action: "Event Action",
      th_details: "Cryptographic Details",
      th_hash: "Entry SHA-256 Hash",
    },

    vi: {
      page_title: "ECC-SIS | Hệ Thống Thông Tin Bảo Mật (Mã Hóa Đầu Cuối P-256 E2EE)",
      brand_subtitle: "Hệ Thống Thông Tin Bảo Mật",
      mode_backend: "Chế độ: Python FastAPI + SQLite",
      mode_standalone: "Chế độ: Lõi Hybrid Trình Duyệt (GitHub Pages)",

      nav_sis: "Nhắn Tin & Gửi File (E2EE)",
      nav_lab: "Thí Nghiệm Toán Học ECC",
      nav_bench: "Đua Tốc Độ: ECC vs RSA",
      nav_audit: "Sổ Nhật Ký & Kiến Trúc",

      active_identity_label: "ĐỊNH DANH ĐANG HOẠT ĐỘNG",
      not_logged_in: "Chưa đăng nhập",
      key_not_loaded: "Chưa tải khóa",
      quick_switch_label: "Chuyển Nhanh Nhân Vật Demo",
      btn_demo_alice: "👩 Alice (Người gửi)",
      btn_demo_bob: "👨 Bob (Người nhận)",

      spec_engine_lbl: "Động cơ lõi:",
      spec_engine_val: "Pure Python (Tự Code)",
      spec_coord_lbl: "Tọa độ xạ ảnh:",
      spec_coord_val: "Jacobian (~5.4x tốc độ)",
      spec_curves_lbl: "Đường cong:",
      spec_sig_lbl: "Chuẩn ký số:",

      secure_ctx_warn:
        "⚠️ Trình duyệt cần mở qua <code>https://</code>, <code>http://localhost:8000</code> hoặc <code>http://127.0.0.1:8000</code> để kích hoạt WebCrypto P-256.",

      persona_open_lbl: "TÀI KHOẢN ĐANG MỞ:",
      ecdsa_badge_on: "Xác Thực Chữ Ký ECDSA: Đang Bật",
      role_sender_p256: "Người gửi (P-256)",
      role_recipient_p256: "Người nhận (P-256)",
      other_account: "Tài Khoản Khác",
      passkey_login_sub: "Đăng nhập Passkey",

      badge_zero_trust: "⚡ KIẾN TRÚC AN TOÀN ZERO-TRUST",
      badge_zk_server: "Máy Chủ Zero-Knowledge",
      pipeline_title: "Quy Trình Bảo Mật Dữ Liệu Đầu-Cuối (P-256 E2EE)",
      pipeline_desc:
        "Khóa bí mật lưu tại trình duyệt. Máy chủ chỉ lưu bản mã. Chữ ký số chặn đứng mọi can thiệp.",
      btn_run_5s: "Bấm Chạy Mô Phỏng 5 Giây",
      btn_running_5s: "Đang chạy mô phỏng Alice ➔ Máy Chủ ➔ Bob...",

      step1_num: "BƯỚC 1",
      step1_role: "TRÌNH DUYỆT ALICE",
      step1_name: "Alice (Người gửi)",
      step1_c1: "🔑 Khóa tạm Ephemeral ECDH (P-256)",
      step1_c2: "🔒 Mã hóa AES-256-GCM",
      step1_c3: "✍️ Ký số xác thực ECDSA (RFC 6979)",
      step1_foot: "🔒 Mã hóa hoàn tất tại máy khách",
      packet1_lbl: "Bản mã bảo vệ",

      step2_num: "BƯỚC 2",
      step2_role: "MÁY CHỦ TRUNG GIAN",
      step2_name: "Máy Chủ FastAPI",
      step2_c1: "🔒 Chỉ lưu chuỗi mã Hex trong SQLite",
      step2_c2: "🚫 0 byte bản rõ (Zero-Knowledge)",
      step2_c3: "🛡️ Không có chìa khóa giải mã",
      step2_foot: "🛡️ Dù lộ CSDL cũng không đọc được",
      packet2_lbl: "Chuyển tiếp gói tin",

      step3_num: "BƯỚC 3",
      step3_role: "TRÌNH DUYỆT BOB",
      step3_name: "Bob (Người nhận)",
      step3_c1: "✅ Xác minh chữ ký Alice (Chống giả mạo)",
      step3_c2: "🔑 Tính khóa chung bí mật (ECDH)",
      step3_c3: "💬 Giải mã và hiển thị dữ liệu gốc",
      step3_foot: "🎉 Chỉ Bob mới mở được",

      sim_proof_title: "🔍 BẰNG CHỨNG ĐỐI CHIẾU: MÁY CHỦ THẤY GÌ VS BOB THẤY GÌ",
      btn_close: "✕ Đóng",
      sim_server_col_title: "Máy chủ chỉ thấy bản mã vô nghĩa:",
      sim_server_col_note: "Máy chủ hoàn toàn mù trước nội dung (Zero-Knowledge).",
      sim_bob_col_title: "Bob giải mã chữ rõ bằng khóa riêng:",
      sim_bob_col_note: "Chữ ký ECDSA: HỢP LỆ ✅ | Thẻ toàn vẹn AES-GCM: HỢP LỆ ✅",
      sim_sample_msg: "Mã Phê Duyệt Tuyệt Mật: X9A-772-ECC [Mô phỏng 5 giây]",
      sim_zero_bytes: "0 BYTES LƯU TRỮ (Máy Chủ Mù Nội Dung / Zero-Knowledge)",
      sim_bob_verified_lines:
        '"{text}"\n\nKiểm tra toàn vẹn:\n✓ Chữ ký số ECDSA của Alice: CHUẨN XÁC HỢP LỆ ✅\n✓ Thẻ xác thực AES-256-GCM Tag: TRÙNG KHỚP 100% ✅',

      compose_title: "🔒 Soạn Tin Nhắn Hoặc Gửi Tài Liệu Mật",
      lbl_recipient: "Người nhận",
      lbl_file: "Đính kèm tệp tin (Tùy chọn, tối đa 5 MB)",
      lbl_presets: "Nạp tin mẫu:",
      btn_preset1: "💰 Lệnh chuyển 500tr",
      btn_preset2: "📄 Hợp đồng bảo mật",
      preset1_text: "Phê duyệt lệnh chuyển khoản 500,000,000 VNĐ cho đối tác #8821.",
      preset2_text: "Hợp đồng dịch vụ bảo mật thông tin & bảo đảm toàn vẹn tài chính.",
      lbl_plaintext: "Nội dung tin nhắn mật / Ghi chú tài liệu",
      ph_plaintext: "Nhập nội dung bí mật hoặc ghi chú cho tài liệu tại đây...",
      btn_send_enc: "Mã Hóa & Ký Số (Gửi Ngay)",

      passkey_card_title: "👤 Đăng Ký Tài Khoản Mới (Passkey)",
      badge_passwordless: "Không Dùng Mật Khẩu",
      passkey_desc:
        "Trình duyệt tự tạo cặp khóa P-256 cất trong máy bạn. Mật khẩu không bao giờ được gửi qua mạng.",
      lbl_username: "Tên tài khoản (Username)",
      ph_username: "ví dụ: kiem_toan_01",
      lbl_display_name: "Tên hiển thị",
      ph_display_name: "ví dụ: Kiểm Toán Viên 01",
      btn_register_login: "Tạo Khóa P-256 & Đăng Ký",
      btn_challenge_login: "Đăng Nhập Khóa Có Sẵn",

      inspector_title: "☁️ Soi Bản Mã Thô Trong Cơ Sở Dữ Liệu Máy Chủ (Zero-Knowledge)",
      inspector_desc:
        "Nguyên văn dữ liệu JSON lưu trong bảng <code>messages</code> của SQLite. Toàn bộ là mã hex, 0 byte chữ rõ!",
      badge_server_blind: "Máy Chủ Hoàn Toàn Không Thể Đọc Trộm",

      inbox_title: "📥 Hộp Thư Mã Hóa & Tin Nhắn Đã Gửi",
      inbox_desc:
        "Tin nhắn được giải mã và kiểm tra chữ ký số trực tiếp trên trình duyệt bằng khóa bí mật riêng.",
      btn_refresh_inbox: "↻ Tải Lại Hộp Thư",
      btn_toggle_inspector: "👁️ Soi CSDL Máy Chủ",
      loading_inbox: "Đang tải dữ liệu hộp thư...",
      empty_inbox: "Hộp thư của @{user} chưa có gói tin mã hóa nào.",

      badge_from: "📥 Từ @{user}",
      badge_to: "📤 Tới @{user}",
      badge_sig_ok: "✓ Chữ ký chính chủ",
      badge_sig_err: "❌ Chữ ký giả mạo",
      btn_tamper: "⚡ Hacker sửa 1 bit dữ liệu",
      btn_tamper_title: "Đảo 1 byte trong CSDL để chứng minh khả năng phát hiện can thiệp",
      unlocked_file: "📄 Tệp đã mở khóa: {name} ({size} bytes)",
      file_note: 'Ghi chú: "{note}"',
      btn_download_file: "⬇ Tải tệp giải mã",
      sender_copy_note: "🔒 Bản sao đã mã hóa dành riêng cho khóa bí mật người nhận (Forward Secrecy).",
      tamper_alert_title: "🚨 PHÁT HIỆN CAN THIỆP GIAN LẬN! (Gói #{id})",
      tamper_zero_trust_note:
        "🛡️ <strong>Nguyên lý Zero-Trust:</strong> Chữ ký số hoặc thẻ xác thực GCM bị sai lệch. Trình duyệt tự động chặn mở dữ liệu!",
      lbl_eph_key: "Khóa tạm:",
      lbl_db_cipher: "Bản mã CSDL:",

      err_ecdsa_verify:
        "Xác thực chữ ký ECDSA THẤT BẠI! Gói tin đã bị sửa đổi trên đường truyền hoặc người gửi giả mạo.",
      err_gcm_tag:
        "Xác thực thẻ Auth Tag AES-256-GCM THẤT BẠI! Dữ liệu hoặc thông tin phụ trợ AAD đã bị sửa đổi trái phép.",
      err_user_exists_diff_key:
        "Người dùng '{user}' đã tồn tại trên máy chủ với khóa khác. Vui lòng đăng ký tên mới.",
      msg_logged_in_as: "Đã đăng nhập với tư cách {name} (@{user}) qua Thử thách - Phản hồi ECDSA.",
      err_enter_username: "Vui lòng nhập tên người dùng.",
      msg_registered_ok:
        "Đã sinh cặp khóa P-256, đăng ký '{user}' và xác thực thành công bằng ECDSA!",
      err_enter_username_login: "Nhập tên người dùng để đăng nhập bằng khóa đã lưu trong trình duyệt.",
      err_no_local_key: "Không tìm thấy khóa bí mật P-256 nội bộ trong trình duyệt cho '{user}'.",
      msg_challenge_ok: "Đã xác thực '{user}' thành công qua thử thách phản hồi ECDSA!",
      err_login_first: "Vui lòng đăng nhập trước khi gửi tin.",
      err_pick_recipient: "Vui lòng chọn người nhận hợp lệ trong danh sách.",
      err_file_too_large: "Tập tin vượt quá giới hạn demo 5 MB.",
      err_empty_payload: "Vui lòng nhập nội dung tin nhắn hoặc đính kèm tập tin.",
      msg_sent_ok: "Đã mã hóa ({bytes} bytes) & ký số ECDSA thành công tới @{user}.",

      lab_header_title: "Phòng Thí Nghiệm & Nghiên Cứu Thuật Toán ECC",
      lab_header_desc:
        "Chạy trực tiếp bằng lõi <code>ecc_core</code> tự lập trình của nhóm (Toán Affine, Tối ưu Jacobian, ECDH, ECDSA RFC 6979, ECIES)",
      toy_curve_title: "Đồ Thị Đường Cong Elliptic Hữu Hạn (<code>toy_p97</code>)",
      toy_curve_desc:
        "Phương trình: <code>y² ≡ x³ + 3x + 2 (mod 97)</code>, bậc nguyên tố <code>n = 103</code>, điểm sinh <code>G = (2, 4)</code>",
      leg_all: "Các điểm trên đường cong",
      leg_p: "Điểm P",
      leg_q: "Điểm Q",
      leg_neg: "Điểm giao -(P+Q)",
      leg_sum: "Tổng P+Q",
      leg_kp: "Tích k·P",
      leg_secant: "— Đường nối P&Q",
      leg_refl: "--- Trục đối xứng",

      point_ops_title: "Phép Cộng Điểm & Từng Bước Nhân Vô Hướng (Double-and-Add)",
      lbl_point_p: "Điểm P (x, y)",
      lbl_point_q: "Điểm Q (x, y)",
      lbl_scalar_k: "Hệ số k",
      btn_compute_ops: "Tính P + Q, 2P & k·P",
      infinity_pt: "Vô cùng (𝒪)",
      ops_sum_1: "1. Phép Cộng Điểm:",
      ops_sum_inter: "Điểm cắt thứ 3 là -(P+Q) =",
      ops_sum_refl: "sau đó lấy đối xứng trục",
      ops_sum_2: "2. Phép Nhân Đôi:",
      ops_sum_3: "3. Nhân Vô Hướng:",
      ops_bin: "nhị phân",
      th_step: "Bước",
      th_bit: "Bit",
      th_double: "Nhân Đôi (2R)",
      th_add: "Cộng P?",
      th_result: "Kết Quả",
      val_yes: "Có",
      val_no: "Không",

      ecdh_card_title: "Bắt Tay Trao Đổi Khóa ECDH + HKDF",
      lbl_curve: "Đường cong",
      btn_run_ecdh: "Chạy Bắt Tay ECDH",
      click_to_run: "Bấm nút để chạy thử...",

      ecdsa_card_title: "Ký ECDSA & Tấn Công Trùng Nonce (PS3)",
      lbl_ecdsa_msg: "Nội dung cần ký",
      val_ecdsa_msg: "Phê duyệt lệnh chuyển tiền #9021",
      lbl_nonce_reuse: "Biểu diễn khôi phục Khóa Bí Mật khi bị trùng Nonce k",
      btn_run_ecdsa: "Ký Số, Soi Dấu & Tấn Công Demo",

      ecies_card_title: "Mã Hóa & Cạy Hộp ECIES",
      lbl_ecies_msg: "Văn bản mật",
      val_ecies_msg: "Tài liệu bí mật quốc gia 2026",
      lbl_ecies_tamper: "Cố tình sửa 1 byte bản mã (Mô phỏng Hacker cạy hộp)",
      btn_run_ecies: "Chạy Thử Quy Trình ECIES",

      bench_header_title: "Đua Tốc Độ: So Sánh Hiệu Năng ECC vs RSA",
      bench_header_desc:
        "Đo đạc trực tiếp ở các mức an toàn tương đương theo chuẩn NIST SP 800-57 + Tối ưu hóa tọa độ Jacobian",
      btn_quick_bench: "▶ Chạy Đua Nhanh (~1 giây)",
      btn_full_bench: "▶ Chạy Đầy Đủ (+RSA-3072)",
      coord_card_title: "Tối Ưu Tọa Độ: Jacobian vs Affine (Đường cong <code>secp256r1</code>)",
      coord_card_wait: "Bấm nút chạy đua tốc độ ở trên để đo mức tăng tốc giữa Affine và Jacobian.",
      size_chart_title: "So Sánh Kích Thước Khóa & Chữ Ký Số (Byte)",
      bench_table_title: "Bảng Kết Quả Đo Thời Gian Thực Tế (Mili-giây — ms)",
      bench_table_wait: 'Bấm "Chạy Đua Nhanh" hoặc "Chạy Đầy Đủ" ở trên để đo trực tiếp.',
      bench_running: "Đang chạy đo kiểm hiệu năng ({mode})...",
      mode_quick: "Nhanh",
      mode_full: "Toàn diện + RSA-3072",
      coord_curve: "Đường cong:",
      coord_iters: "lần lặp",
      coord_affine: "Nhân vô hướng Tọa độ Afin:",
      coord_jacobian: "Nhân vô hướng Tọa độ Xạ ảnh Jacobian:",
      coord_badge: "Tốc độ Jacobian: Nhanh hơn {x} lần",
      coord_note: "(loại bỏ phép nghịch đảo modulo trong từng bit)",

      th_algo: "Thuật Toán",
      th_sec_bits: "Mức An Toàn",
      th_pubkey: "Khóa Công Khai (Nén / Gốc)",
      th_sig_size: "Kích Thước Chữ Ký",
      th_keygen: "Tạo Khóa (ms)",
      th_sign: "Ký Số (ms)",
      th_verify: "Xác Minh (ms)",
      th_ecdh_enc: "ECDH / Mã-Giải mã (ms)",

      nist_table_title: "Bảng Quy Đổi Mức An Toàn NIST SP 800-57 & Mức Tiết Kiệm Băng Thông",
      th_nist_lvl: "Cấp Độ Bảo Mật NIST",
      th_ecc_bits: "Khóa ECC (bit)",
      th_rsa_bits: "Khóa RSA (bit)",
      th_ecc_bytes: "Khóa Công Khai ECC (byte)",
      th_rsa_bytes: "Khóa Công Khai RSA (byte)",
      th_ratio: "Tỉ Lệ Rút Gọn (RSA / ECC)",
      badge_smaller: "Nhỏ gọn hơn {x} lần",

      audit_header_title: "Sổ Nhật Ký Kiểm Toán Chuỗi Băm SHA-256 & Mô Hình Kiến Trúc",
      audit_header_desc:
        "Mỗi sự kiện bảo mật được băm nối tiếp bằng SHA-256 như sổ cái chuỗi khối mini: <code>H_i = SHA256(H_{i-1} || timestamp || actor || action || details)</code>",
      btn_verify_audit: "✓ Kiểm Tra Tính Toàn Vẹn Chuỗi Băm",
      audit_valid_msg:
        "Chuỗi băm toàn vẹn HỢP LỆ trên toàn bộ {n} bản ghi. Mã băm đỉnh (Head Hash): {hash}",
      audit_broken_msg: "Chuỗi băm BỊ ĐỨT GÃY tại ID #{id}: {reason}",

      arch_main_title: "Tổng Quan 4 Tầng Bảo Mật Của Hệ Thống",
      arch1_t: "1. Đăng Nhập Không Mật Khẩu",
      arch1_p:
        "Mỗi người dùng sở hữu cặp khóa P-256 riêng và ký số lên câu đố ngẫu nhiên 120s của Server (không gửi mật khẩu, chống phát lại).",
      arch2_t: "2. Khóa Tạm Thời (Forward Secrecy)",
      arch2_p:
        "Mỗi tin nhắn/tệp tin đều sinh khóa phiên tạm <code>(k, kG)</code> riêng, rèn khóa qua HKDF-SHA256 và khóa két AES-256-GCM.",
      arch3_t: "3. Chữ Ký Chống Chối Bỏ",
      arch3_p:
        "Người gửi đóng dấu chữ ký ECDSA RFC 6979 lên toàn bộ gói tin. Máy chủ và người nhận đều kiểm tra trước khi mở.",
      arch4_t: "4. Máy Chủ Mù (Zero-Knowledge)",
      arch4_p:
        "CSDL chỉ lưu bản mã hex, khóa công khai và chữ ký. Kể cả quản trị viên hay hacker lấy được CSDL cũng thấy 0 byte bản rõ.",

      audit_table_title: "Sổ Nhật Ký Ghi Nhận Sự Kiện Hệ Thống",
      th_id: "Mã ID",
      th_time: "Thời Gian (UTC)",
      th_actor: "Tác Nhân",
      th_action: "Hành Động",
      th_details: "Chi Tiết Giao Dịch",
      th_hash: "Mã Băm Bản Ghi (Hash)",
    },
  };

  function resolveInitialLang() {
    try {
      const params = new URLSearchParams(window.location.search);
      const q = (params.get("lang") || "").toLowerCase();
      if (q === "en" || q === "vi") {
        localStorage.setItem(LANG_STORAGE_KEY, q);
        return q;
      }
      const saved = localStorage.getItem(LANG_STORAGE_KEY);
      if (saved === "en" || saved === "vi") return saved;
    } catch (_) {}
    return "en"; // English default per user preference
  }

  let currentLang = resolveInitialLang();
  const listeners = [];

  function t(key, vars = {}) {
    const pack = DICT[currentLang] || DICT.en;
    let str = pack[key] ?? DICT.en[key] ?? key;
    for (const [k, v] of Object.entries(vars)) {
      str = str.replaceAll(`{${k}}`, String(v));
    }
    return str;
  }

  function applyStaticTranslations() {
    document.documentElement.lang = currentLang;
    document.title = t("page_title");

    document.querySelectorAll("[data-i18n]").forEach((el) => {
      const k = el.getAttribute("data-i18n");
      el.textContent = t(k);
    });
    document.querySelectorAll("[data-i18n-html]").forEach((el) => {
      const k = el.getAttribute("data-i18n-html");
      el.innerHTML = t(k);
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
      el.setAttribute("placeholder", t(el.getAttribute("data-i18n-placeholder")));
    });
    document.querySelectorAll("[data-i18n-value-default]").forEach((el) => {
      const k = el.getAttribute("data-i18n-value-default");
      const otherLang = currentLang === "en" ? "vi" : "en";
      if (!el.value || el.value === DICT[otherLang][k]) {
        el.value = t(k);
      }
    });

    document.querySelectorAll(".lang-btn[data-lang]").forEach((btn) => {
      const active = btn.getAttribute("data-lang") === currentLang;
      btn.classList.toggle("active", active);
      btn.setAttribute("aria-pressed", active ? "true" : "false");
    });
  }

  function setLang(lang) {
    if (lang !== "en" && lang !== "vi") return;
    if (lang === currentLang) return;
    currentLang = lang;
    try {
      localStorage.setItem(LANG_STORAGE_KEY, lang);
    } catch (_) {}

    const runUpdate = () => {
      applyStaticTranslations();
      listeners.forEach((fn) => {
        try {
          fn(currentLang);
        } catch (_) {}
      });
    };

    if (document.startViewTransition) {
      document.startViewTransition(runUpdate);
    } else {
      runUpdate();
    }
  }

  window.ECC_I18N = {
    getLang: () => currentLang,
    setLang,
    t,
    applyStaticTranslations,
    onChange: (fn) => listeners.push(fn),
  };
})();
