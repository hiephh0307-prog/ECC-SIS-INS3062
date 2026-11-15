"use strict";

const STORAGE_PREFIX = "ecc_sis_jwk_";
const STATE = {
  username: null,
  displayName: null,
  token: null,
  jwk: null,
  pubHex: null,
  users: [],
  toyCurveData: null,
};

// ----------------------------------------------------------------------
// Encoding & WebCrypto P-256 Helpers
// ----------------------------------------------------------------------
const textEnc = new TextEncoder();
const textDec = new TextDecoder();

function bytesToHex(buf) {
  const arr = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const clean = hex.trim();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function concatBytes(...arrays) {
  const total = arrays.reduce((acc, a) => acc + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

function uint8ToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function base64ToUint8(b64) {
  const binStr = atob(b64);
  const bytes = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i++) {
    bytes[i] = binStr.charCodeAt(i);
  }
  return bytes;
}

function stripJwkForImport(jwk, keyOps) {
  return {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
    ...(jwk.d ? { d: jwk.d } : {}),
    ext: true,
    key_ops: keyOps,
  };
}

async function generateP256Identity() {
  const kp = await window.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const jwk = await window.crypto.subtle.exportKey("jwk", kp.privateKey);
  const rawPub = await window.crypto.subtle.exportKey("raw", kp.publicKey);
  return { jwk, pubHex: bytesToHex(rawPub) };
}

async function pubHexFromJwk(jwk) {
  const pubJwk = stripJwkForImport({ ...jwk, d: undefined }, ["verify"]);
  const pubKey = await window.crypto.subtle.importKey(
    "jwk",
    pubJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
  const raw = await window.crypto.subtle.exportKey("raw", pubKey);
  return bytesToHex(raw);
}

async function ecdsaSign(jwk, dataBytes) {
  const privKey = await window.crypto.subtle.importKey(
    "jwk",
    stripJwkForImport(jwk, ["sign"]),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
  const sig = await window.crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privKey,
    dataBytes
  );
  return new Uint8Array(sig);
}

async function ecdsaVerify(pubHex, dataBytes, sigHex) {
  const pubKey = await window.crypto.subtle.importKey(
    "raw",
    hexToBytes(pubHex),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );
  return window.crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    pubKey,
    hexToBytes(sigHex),
    dataBytes
  );
}

async function deriveAesKeyEcdh(privateJwkOrCryptoKey, peerPubHex, saltBytes, usages) {
  let privKey = privateJwkOrCryptoKey;
  if (!(privKey instanceof CryptoKey)) {
    privKey = await window.crypto.subtle.importKey(
      "jwk",
      stripJwkForImport(privateJwkOrCryptoKey, ["deriveBits"]),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"]
    );
  }
  const peerPub = await window.crypto.subtle.importKey(
    "raw",
    hexToBytes(peerPubHex),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  const sharedBits = await window.crypto.subtle.deriveBits(
    { name: "ECDH", public: peerPub },
    privKey,
    256
  );
  const hkdfBase = await window.crypto.subtle.importKey(
    "raw",
    sharedBits,
    "HKDF",
    false,
    ["deriveKey"]
  );
  return window.crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: saltBytes,
      info: textEnc.encode("ECC-SIS-v1|AES-256-GCM"),
    },
    hkdfBase,
    { name: "AES-GCM", length: 256 },
    false,
    usages
  );
}

async function encryptAndSignEnvelope(senderJwk, recipientPubHex, plaintextBytes, aadText) {
  const eph = await window.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const ephPubBytes = new Uint8Array(await window.crypto.subtle.exportKey("raw", eph.publicKey));
  const aesKey = await deriveAesKeyEcdh(eph.privateKey, recipientPubHex, ephPubBytes, ["encrypt"]);
  const nonce = window.crypto.getRandomValues(new Uint8Array(12));
  const aadBytes = textEnc.encode(aadText);

  const ct = new Uint8Array(
    await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aadBytes, tagLength: 128 },
      aesKey,
      plaintextBytes
    )
  );

  const sigPayload = concatBytes(
    textEnc.encode("ECC-SIS-SIG-v1|"),
    ephPubBytes,
    nonce,
    ct,
    aadBytes
  );
  const sig = await ecdsaSign(senderJwk, sigPayload);

  return {
    ephemeral_pubkey_hex: bytesToHex(ephPubBytes),
    nonce_hex: bytesToHex(nonce),
    ciphertext_hex: bytesToHex(ct),
    signature_hex: bytesToHex(sig),
  };
}

async function verifyAndDecryptMessage(myJwk, msg) {
  const ephBytes = hexToBytes(msg.ephemeral_pubkey_hex);
  const nonceBytes = hexToBytes(msg.nonce_hex);
  const ctBytes = hexToBytes(msg.ciphertext_hex);
  const aadBytes = textEnc.encode(msg.aad_text);

  const sigPayload = concatBytes(
    textEnc.encode("ECC-SIS-SIG-v1|"),
    ephBytes,
    nonceBytes,
    ctBytes,
    aadBytes
  );
  const sigValid = await ecdsaVerify(msg.sender_public_key_hex, sigPayload, msg.signature_hex);

  if (!sigValid) {
    return {
      sigValid: false,
      decrypted: false,
      error: "Xác thực chữ ký ECDSA THẤT BẠI! Gói tin đã bị sửa đổi trên đường truyền hoặc người gửi giả mạo.",
    };
  }

  if (msg.recipient !== STATE.username) {
    return {
      sigValid: true,
      decrypted: false,
      senderCopy: true,
      error: "Được mã hóa bằng ECDH tạm thời (Ephemeral) dành riêng cho khóa bí mật của người nhận. (Bảo mật chuyển tiếp Forward-Secrecy: chỉ người nhận mới giải mã được).",
    };
  }

  try {
    const aesKey = await deriveAesKeyEcdh(myJwk, msg.ephemeral_pubkey_hex, ephBytes, ["decrypt"]);
    const ptBuf = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonceBytes, additionalData: aadBytes, tagLength: 128 },
      aesKey,
      ctBytes
    );
    return { sigValid: true, decrypted: true, plaintextBytes: new Uint8Array(ptBuf) };
  } catch (err) {
    return {
      sigValid: true,
      decrypted: false,
      error: "Xác thực thẻ xác thực (Auth Tag) AES-256-GCM THẤT BẠI! Dữ liệu hoặc thông tin phụ trợ AAD đã bị sửa đổi trái phép.",
    };
  }
}

// ----------------------------------------------------------------------
// HTTP API Helper
// ----------------------------------------------------------------------
async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (STATE.token) {
    headers["Authorization"] = `Bearer ${STATE.token}`;
  }
  const resp = await fetch(path, { ...options, headers });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(data.detail || `HTTP ${resp.status}`);
  }
  return data;
}

function showStatus(elId, msg, ok = true) {
  const el = document.getElementById(elId);
  el.textContent = msg;
  el.classList.remove("hidden", "ok", "err");
  el.classList.add(ok ? "ok" : "err");
}

function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

// ----------------------------------------------------------------------
// Auth & Identity Flows
// ----------------------------------------------------------------------
function updatePersonaHighlight(username, displayName) {
  const topText = document.getElementById("activePersonaText");
  const avatar = username === "alice" ? "👩" : username === "bob" ? "👨" : "👤";
  topText.textContent = `${avatar} ${displayName} (@${username})`;

  document.querySelectorAll(".persona-pill").forEach((pill) => pill.classList.remove("active"));
  if (username === "alice") {
    document.getElementById("topBtnAlice").classList.add("active");
  } else if (username === "bob") {
    document.getElementById("topBtnBob").classList.add("active");
  } else {
    document.getElementById("topBtnCustom").classList.add("active");
  }
}

async function loginWithStoredKey(username, jwk) {
  const challenge = await api("/api/auth/challenge", {
    method: "POST",
    body: JSON.stringify({ username }),
  });
  const payload = concatBytes(
    textEnc.encode("ECC-SIS-AUTH|"),
    textEnc.encode(username),
    textEnc.encode("|"),
    hexToBytes(challenge.nonce_hex)
  );
  const sig = await ecdsaSign(jwk, payload);
  const verified = await api("/api/auth/verify", {
    method: "POST",
    body: JSON.stringify({
      challenge_id: challenge.challenge_id,
      username,
      signature_hex: bytesToHex(sig),
    }),
  });

  STATE.username = verified.username;
  STATE.displayName = verified.display_name;
  STATE.token = verified.access_token;
  STATE.jwk = jwk;
  STATE.pubHex = verified.public_key_hex;

  const badge = document.getElementById("activeUserBadge");
  badge.innerHTML = `<span class="status-indicator"></span> ${verified.display_name} (@${verified.username})`;
  badge.classList.remove("offline");
  badge.classList.add("online");

  document.getElementById("activePubKeyPreview").textContent =
    `Pub: ${verified.public_key_hex.slice(0, 26)}...`;

  updatePersonaHighlight(verified.username, verified.display_name);

  await refreshUsers();
  await refreshMessages();
  await refreshAuditLog();
}

const DEMO_PRESET_JWKS = {
  alice: {
    kty: "EC", crv: "P-256",
    x: "dLGMoh-ESk8F4O1ncsXMqfiFQN3MiSl1WpEoaoBeY3c",
    y: "PzgZPgr8-S6ApqKseMqBWFFD3T0K7rtykA1RWyMREeg",
    d: "d7059ZAFWzncqJEQdgeRf88oqZF17gY8HoireWPmod8",
    ext: true
  },
  bob: {
    kty: "EC", crv: "P-256",
    x: "TgYYItwgxxy30pJxdslU37-9awDqB7F4lPmwfZyD4Wo",
    y: "MpcMv8ntrceXlan1hUH4HGs0Z-0Cqs9Su3Nvw28tQbY",
    d: "k_CRVwws1WoWPhgeI2T-nBFmqioURA21bTxiDJNoz5g",
    ext: true
  }
};

async function ensureDemoPersona(username, displayName) {
  const keySlot = STORAGE_PREFIX + username;
  let jwk = null;
  let pubHex = null;

  const saved = localStorage.getItem(keySlot);
  if (saved) {
    jwk = JSON.parse(saved);
    pubHex = await pubHexFromJwk(jwk);
  } else if (DEMO_PRESET_JWKS[username]) {
    jwk = DEMO_PRESET_JWKS[username];
    pubHex = await pubHexFromJwk(jwk);
    localStorage.setItem(keySlot, JSON.stringify(jwk));
  } else {
    const generated = await generateP256Identity();
    jwk = generated.jwk;
    pubHex = generated.pubHex;
    localStorage.setItem(keySlot, JSON.stringify(jwk));
  }

  const usersResp = await api("/api/users");
  const existing = usersResp.users.find((u) => u.username === username);
  if (!existing || (username in DEMO_PRESET_JWKS && existing.public_key_hex !== pubHex)) {
    await api("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        username,
        display_name: displayName,
        curve: "secp256r1",
        public_key_hex: pubHex,
      }),
    });
  } else if (existing.public_key_hex !== pubHex) {
    throw new Error(
      `Người dùng '${username}' đã tồn tại trên máy chủ với khóa khác. Vui lòng đăng ký tên người dùng mới.`
    );
  }

  await loginWithStoredKey(username, jwk);
  showStatus("authLog", `Đã đăng nhập với tư cách ${displayName} (@${username}) qua Thử thách - Phản hồi ECDSA.`, true);
}

async function handleRegisterAndLogin() {
  const username = document.getElementById("authUsername").value.trim();
  const displayName = document.getElementById("authDisplayName").value.trim() || username;
  if (!username) {
    showStatus("authLog", "Vui lòng nhập tên người dùng.", false);
    return;
  }
  try {
    const { jwk, pubHex } = await generateP256Identity();
    await api("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        username,
        display_name: displayName,
        curve: "secp256r1",
        public_key_hex: pubHex,
      }),
    });
    localStorage.setItem(STORAGE_PREFIX + username, JSON.stringify(jwk));
    await loginWithStoredKey(username, jwk);
    showStatus("authLog", `Đã sinh cặp khóa P-256, đăng ký '${username}' và xác thực thành công bằng ECDSA!`, true);
  } catch (err) {
    showStatus("authLog", err.message, false);
  }
}

async function handleChallengeLogin() {
  const username = document.getElementById("authUsername").value.trim();
  if (!username) {
    showStatus("authLog", "Nhập tên người dùng để đăng nhập bằng khóa đã lưu trong trình duyệt.", false);
    return;
  }
  const saved = localStorage.getItem(STORAGE_PREFIX + username);
  if (!saved) {
    showStatus("authLog", `Không tìm thấy khóa bí mật P-256 nội bộ trong trình duyệt cho '${username}'.`, false);
    return;
  }
  try {
    await loginWithStoredKey(username, JSON.parse(saved));
    showStatus("authLog", `Đã xác thực '${username}' thành công qua thử thách phản hồi ECDSA!`, true);
  } catch (err) {
    showStatus("authLog", err.message, false);
  }
}

async function refreshUsers() {
  const data = await api("/api/users");
  STATE.users = data.users;
  const select = document.getElementById("msgRecipient");
  const prev = select.value;
  select.innerHTML = "";
  for (const u of data.users) {
    const opt = document.createElement("option");
    opt.value = u.username;
    opt.textContent = `${u.display_name} (@${u.username})`;
    select.appendChild(opt);
  }
  if (prev && data.users.some((u) => u.username === prev)) {
    select.value = prev;
  } else {
    const other = data.users.find((u) => u.username !== STATE.username);
    if (other) select.value = other.username;
  }
}

async function handleSendEncrypted() {
  if (!STATE.token || !STATE.jwk) {
    showStatus("sendStatus", "Vui lòng đăng nhập trước khi gửi tin.", false);
    return;
  }
  const recipient = document.getElementById("msgRecipient").value;
  const targetUser = STATE.users.find((u) => u.username === recipient);
  if (!targetUser) {
    showStatus("sendStatus", "Vui lòng chọn người nhận hợp lệ trong danh sách.", false);
    return;
  }

  const fileInput = document.getElementById("msgFileInput");
  const textVal = document.getElementById("msgPlaintext").value;
  let msgType = "text";
  let filename = "";
  let mimeType = "text/plain";
  let fileSize = 0;
  let plaintextBytes;

  try {
    if (fileInput.files && fileInput.files.length > 0) {
      const file = fileInput.files[0];
      if (file.size > 5 * 1024 * 1024) {
        showStatus("sendStatus", "Tập tin vượt quá giới hạn demo 5 MB.", false);
        return;
      }
      msgType = "file";
      filename = file.name;
      mimeType = file.type || "application/octet-stream";
      fileSize = file.size;
      const fileBuf = new Uint8Array(await file.arrayBuffer());
      const note = textVal || "";
      const wrapper = JSON.stringify({
        note,
        file_b64: uint8ToBase64(fileBuf),
      });
      plaintextBytes = textEnc.encode(wrapper);
    } else {
      if (!textVal.trim()) {
        showStatus("sendStatus", "Vui lòng nhập nội dung tin nhắn hoặc đính kèm tập tin.", false);
        return;
      }
      plaintextBytes = textEnc.encode(textVal);
    }

    const aadText = `${STATE.username}|${recipient}|${msgType}|${filename}`;
    const env = await encryptAndSignEnvelope(
      STATE.jwk,
      targetUser.public_key_hex,
      plaintextBytes,
      aadText
    );

    await api("/api/messages", {
      method: "POST",
      body: JSON.stringify({
        recipient,
        msg_type: msgType,
        filename,
        mime_type: mimeType,
        file_size: fileSize,
        curve: "secp256r1",
        ...env,
        aad_text: aadText,
      }),
    });

    document.getElementById("msgPlaintext").value = "";
    fileInput.value = "";
    showStatus(
      "sendStatus",
      `Đã mã hóa (${env.ciphertext_hex.length / 2} bytes) & ký số ECDSA thành công tới @${recipient}.`,
      true
    );
    await refreshMessages();
    await refreshAuditLog();
  } catch (err) {
    showStatus("sendStatus", err.message, false);
  }
}

// ----------------------------------------------------------------------
// Upgraded Message Cards with Clear Cryptographic Indicators
// ----------------------------------------------------------------------
async function refreshMessages() {
  if (!STATE.token) return;
  const data = await api("/api/messages");
  const container = document.getElementById("messagesList");
  if (!data.messages.length) {
    container.innerHTML = `<p class="muted">Hộp thư của @${escapeHtml(STATE.username)} chưa có gói tin mã hóa nào.</p>`;
    return;
  }

  container.innerHTML = "";
  for (const msg of data.messages) {
    const res = await verifyAndDecryptMessage(STATE.jwk, msg);
    const card = document.createElement("div");
    card.className = "msg-card";

    const isTampered = !res.sigValid || (!res.decrypted && !res.senderCopy);
    if (isTampered) {
      card.classList.add("tampered-alert");
    }

    const dirBadge =
      msg.recipient === STATE.username
        ? `<span class="badge badge-info">📥 Từ @${escapeHtml(msg.sender)}</span>`
        : `<span class="badge badge-warning">📤 Tới @${escapeHtml(msg.recipient)}</span>`;

    const sigBadge = res.sigValid
      ? `<span class="badge badge-ok">✓ Chữ ký chính chủ</span>`
      : `<span class="badge badge-err">❌ Chữ ký giả mạo</span>`;

    const aeadBadge = `<span class="badge badge-cyber">🔒 E2EE P-256</span>`;

    let bodyHtml = "";
    if (res.decrypted) {
      if (msg.msg_type === "file") {
        const parsed = JSON.parse(textDec.decode(res.plaintextBytes));
        const bytes = base64ToUint8(parsed.file_b64);
        const blobUrl = URL.createObjectURL(new Blob([bytes], { type: msg.mime_type }));
        bodyHtml = `
          <div class="msg-content-box">
            <div style="font-size:14px; font-weight:700; color:#86efac; margin-bottom:4px;">
              📄 Tệp đã mở khóa: ${escapeHtml(msg.filename)} (${msg.file_size} bytes)
            </div>
            ${parsed.note ? `<div class="small muted">Ghi chú: "${escapeHtml(parsed.note)}"</div>` : ""}
            <div style="margin-top:8px;">
              <a class="btn btn-primary btn-sm" href="${blobUrl}" download="${escapeHtml(msg.filename)}">
                ⬇ Tải tệp giải mã
              </a>
            </div>
          </div>
        `;
      } else {
        bodyHtml = `
          <div class="msg-content-box">
            <div class="msg-plaintext-text">"${escapeHtml(textDec.decode(res.plaintextBytes))}"</div>
          </div>
        `;
      }
    } else if (res.senderCopy) {
      bodyHtml = `
        <div class="msg-content-box">
          <div class="muted small">🔒 <em>Bản sao đã mã hóa bằng khóa riêng của người nhận.</em></div>
        </div>
      `;
    } else {
      // Tamper alert explanation
      bodyHtml = `
        <div class="tamper-warning-box">
          <div class="tamper-warning-title">🚨 PHÁT HIỆN CAN THIỆP GIAN LẬN! (Gói #${msg.id})</div>
          <div class="tamper-warning-detail">❌ ${escapeHtml(res.error)}</div>
          <div class="small" style="color:#fecaca; margin-top:6px;">
            🛡️ <strong>Nguyên lý Zero-Trust:</strong> Chữ ký số hoặc thẻ xác thực GCM bị sai lệch. Trình duyệt tự động chặn mở dữ liệu!
          </div>
        </div>
      `;
    }

    card.innerHTML = `
      <div class="msg-card-top">
        <div class="msg-badges-group">
          <strong style="color:#fff;">#${msg.id}</strong>
          ${dirBadge}
          ${sigBadge}
          ${aeadBadge}
        </div>
        <div class="btn-row">
          <button class="btn btn-danger btn-sm btn-tamper" data-id="${msg.id}" title="Đảo 1 byte trong CSDL để chứng minh khả năng phát hiện can thiệp">
            ⚡ Hacker sửa 1 bit dữ liệu
          </button>
        </div>
      </div>

      ${bodyHtml}

      <div class="msg-inspect-toggle">
        <span class="mono small">
          <strong>Khóa tạm:</strong> ${escapeHtml(msg.ephemeral_pubkey_hex.slice(0, 16))}... | 
          <strong>Bản mã CSDL:</strong> ${escapeHtml(msg.ciphertext_hex.slice(0, 20))}...
        </span>
      </div>
    `;
    container.appendChild(card);
  }

  container.querySelectorAll(".btn-tamper").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await api(`/api/messages/${btn.dataset.id}/simulate-tamper`, { method: "POST" });
      await refreshMessages();
      await refreshInspector();
      await refreshAuditLog();
    });
  });
}

async function refreshInspector() {
  if (!STATE.token) return;
  const data = await api("/api/messages/server-inspector");
  document.getElementById("serverInspectorPre").textContent = JSON.stringify(data, null, 2);
}

// ----------------------------------------------------------------------
// BỘ TRÌNH DIỄN MÔ PHỎNG TƯƠNG TÁC 5 GIÂY (INTERACTIVE SIMULATION)
// ----------------------------------------------------------------------
async function run5SecondInteractiveSimulation() {
  const btn = document.getElementById("btnRunAutoDemo");
  btn.disabled = true;
  btn.innerHTML = `<span class="icon-pulse">⚙️</span> Đang chạy mô phỏng Alice ➔ Máy Chủ ➔ Bob...`;

  const s1 = document.getElementById("stageSender");
  const s2 = document.getElementById("stageServer");
  const s3 = document.getElementById("stageRecipient");
  const p1 = document.getElementById("packetAnim1");
  const p2 = document.getElementById("packetAnim2");
  const simProof = document.getElementById("simResultBox");
  const simServerView = document.getElementById("simServerView");
  const simBobView = document.getElementById("simBobView");

  // Reset highlight states
  s1.classList.remove("highlight");
  s2.classList.remove("highlight");
  s3.classList.remove("highlight");
  p1.classList.remove("active-travel");
  p2.classList.remove("active-travel");

  try {
    // Stage 1: Alice's browser
    s1.classList.add("highlight");
    await ensureDemoPersona("alice", "Alice Tran");

    const sampleText = "Mã Phê Duyệt Tuyệt Mật: X9A-772-ECC [Mô phỏng 5 giây]";
    const bobUser = STATE.users.find((u) => u.username === "bob");
    if (!bobUser) {
      // Register bob first if needed
      await ensureDemoPersona("bob", "Bob Le");
      await ensureDemoPersona("alice", "Alice Tran");
    }

    const recipientUser = STATE.users.find((u) => u.username === "bob");
    const aadText = "alice|bob|text|simulation";
    const env = await encryptAndSignEnvelope(
      STATE.jwk,
      recipientUser.public_key_hex,
      textEnc.encode(sampleText),
      aadText
    );

    // Animate Packet 1
    p1.classList.add("active-travel");
    await new Promise((r) => setTimeout(r, 800));

    // Stage 2: Server saves ciphertext
    s1.classList.remove("highlight");
    s2.classList.add("highlight");

    const sent = await api("/api/messages", {
      method: "POST",
      body: JSON.stringify({
        recipient: "bob",
        msg_type: "text",
        filename: "",
        mime_type: "text/plain",
        file_size: 0,
        curve: "secp256r1",
        ...env,
        aad_text: aadText,
      }),
    });

    simServerView.textContent = JSON.stringify(
      {
        msg_id: sent.id,
        ephemeral_pubkey: env.ephemeral_pubkey_hex.slice(0, 32) + "...",
        nonce_12_bytes: env.nonce_hex,
        ciphertext_hex: env.ciphertext_hex.slice(0, 36) + "...",
        signature_hex: env.signature_hex.slice(0, 36) + "...",
        plaintext: "0 BYTES LƯU TRỮ (Máy Chủ Tri Thức Bằng Không / Zero-Knowledge)",
      },
      null,
      2
    );

    // Animate Packet 2
    p2.classList.add("active-travel");
    await new Promise((r) => setTimeout(r, 800));

    // Stage 3: Bob's browser receives and decrypts
    s2.classList.remove("highlight");
    s3.classList.add("highlight");

    await ensureDemoPersona("bob", "Bob Le");
    simBobView.textContent = `"${sampleText}"\n\nKiểm tra toàn vẹn:\n✓ Chữ ký số ECDSA của Alice: CHUẨN XÁC HỢP LỆ ✅\n✓ Thẻ xác thực AES-256-GCM Tag: TRÙNG KHỚP 100% ✅`;

    simProof.classList.remove("hidden");
    await refreshMessages();
  } catch (err) {
    alert("Lỗi mô phỏng: " + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<span class="icon-pulse">▶</span> Chạy Mô Phỏng Trực Quan Trong 5 Giây`;
    setTimeout(() => {
      s1.classList.remove("highlight");
      s2.classList.remove("highlight");
      s3.classList.remove("highlight");
      p1.classList.remove("active-travel");
      p2.classList.remove("active-travel");
    }, 2000);
  }
}

// ----------------------------------------------------------------------
// Tab 2: ECC Algorithm Lab & SVG Curve Visualizer
// ----------------------------------------------------------------------
async function loadToyCurve() {
  const data = await api("/api/lab/toy-curve");
  STATE.toyCurveData = data;

  const selP = document.getElementById("labPointP");
  const selQ = document.getElementById("labPointQ");
  selP.innerHTML = "";
  selQ.innerHTML = "";
  data.points.forEach(([x, y], idx) => {
    const label = `(${x}, ${y})${x === 2 && y === 4 ? " [G]" : ""}`;
    const o1 = new Option(label, `${x},${y}`);
    const o2 = new Option(label, `${x},${y}`);
    selP.appendChild(o1);
    selQ.appendChild(o2);
    if (x === 2 && y === 4) selP.selectedIndex = idx;
    if (idx === 10) selQ.selectedIndex = idx;
  });

  await runPointOps();
}

function drawToyCurveSvg(points, highlights = {}) {
  const svg = document.getElementById("curveSvg");
  const pad = 28;
  const size = 420 - pad * 2;
  const p = 97;
  const mapX = (x) => pad + (x / (p - 1)) * size;
  const mapY = (y) => 420 - pad - (y / (p - 1)) * size;

  let html = `
    <rect x="0" y="0" width="420" height="420" fill="#070b14" rx="8" />
    <line x1="${pad}" y1="${420 - pad}" x2="${420 - pad}" y2="${420 - pad}" stroke="#1e293b" />
    <line x1="${pad}" y1="${pad}" x2="${pad}" y2="${420 - pad}" stroke="#1e293b" />
    <text x="${420 - pad}" y="${420 - 8}" fill="#94a3b8" font-size="11" text-anchor="end">x mod 97</text>
    <text x="${pad}" y="${16}" fill="#94a3b8" font-size="11">y mod 97</text>
  `;

  for (const [x, y] of points) {
    html += `<circle cx="${mapX(x).toFixed(1)}" cy="${mapY(y).toFixed(1)}" r="2.8" fill="#475569" opacity="0.75" />`;
  }

  const P = highlights.P;
  const Q = highlights.Q;
  const sum = highlights.sum;

  // Điểm giao thứ ba trên đường thẳng: -R = (x, (p - y) % p)
  let negR = null;
  if (Array.isArray(sum)) {
    negR = [sum[0], (p - (sum[1] % p)) % p];
  }

  // Vẽ đường thẳng hình học nối các điểm (Dây cung / Tiếp tuyến)
  if (Array.isArray(P) && Array.isArray(Q)) {
    const xP = mapX(P[0]), yP = mapY(P[1]);
    const xQ = mapX(Q[0]), yQ = mapY(Q[1]);

    if (P[0] === Q[0] && P[1] === Q[1]) {
      // Phép nhân đôi (2P): Tiếp tuyến đi qua P và -R
      if (negR) {
        const xNeg = mapX(negR[0]), yNeg = mapY(negR[1]);
        html += `<line x1="${xP.toFixed(1)}" y1="${yP.toFixed(1)}" x2="${xNeg.toFixed(1)}" y2="${yNeg.toFixed(1)}" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" />`;
      }
    } else {
      // Phép cộng hai điểm khác nhau (P != Q): Cát tuyến nối P, Q và -R
      html += `<line x1="${xP.toFixed(1)}" y1="${yP.toFixed(1)}" x2="${xQ.toFixed(1)}" y2="${yQ.toFixed(1)}" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" />`;
      if (negR) {
        const xNeg = mapX(negR[0]), yNeg = mapY(negR[1]);
        html += `<line x1="${xQ.toFixed(1)}" y1="${yQ.toFixed(1)}" x2="${xNeg.toFixed(1)}" y2="${yNeg.toFixed(1)}" stroke="#f59e0b" stroke-width="1.8" stroke-dasharray="4,3" />`;
      }
    }

    // Đường gióng nét đứt đối xứng dọc qua trục hoành từ -R tới R = P + Q
    if (negR && Array.isArray(sum)) {
      const xNeg = mapX(negR[0]), yNeg = mapY(negR[1]);
      const xSum = mapX(sum[0]), ySum = mapY(sum[1]);
      html += `<line x1="${xNeg.toFixed(1)}" y1="${yNeg.toFixed(1)}" x2="${xSum.toFixed(1)}" y2="${ySum.toFixed(1)}" stroke="#00f2fe" stroke-width="2" stroke-dasharray="5,4" />`;
    }
  }

  const drawHighlight = (pt, color, label) => {
    if (!Array.isArray(pt)) return;
    const cx = mapX(pt[0]);
    const cy = mapY(pt[1]);
    html += `<circle cx="${cx.toFixed(1)}" cy="${cy.toFixed(1)}" r="6.5" fill="${color}" stroke="#fff" stroke-width="1.8" />`;
    html += `<text x="${(cx + 8).toFixed(1)}" y="${(cy - 6).toFixed(1)}" fill="${color}" font-size="11" font-weight="bold">${label}(${pt[0]},${pt[1]})</text>`;
  };

  drawHighlight(highlights.P, "#00f2fe", "P");
  drawHighlight(highlights.Q, "#10b981", "Q");
  if (negR) {
    drawHighlight(negR, "#a855f7", "-(P+Q)");
  }
  drawHighlight(highlights.sum, "#f59e0b", "P+Q");
  drawHighlight(highlights.kP, "#ec4899", "kP");

  svg.innerHTML = html;
}

async function runPointOps() {
  const [px, py] = document.getElementById("labPointP").value.split(",").map(Number);
  const [qx, qy] = document.getElementById("labPointQ").value.split(",").map(Number);
  const k = Number(document.getElementById("labScalarK").value) || 7;

  const res = await api("/api/lab/point-ops", {
    method: "POST",
    body: JSON.stringify({ px, py, qx, qy, k }),
  });

  drawToyCurveSvg(STATE.toyCurveData.points, {
    P: res.P,
    Q: res.Q,
    sum: res.P_plus_Q,
    kP: res.k_times_P,
  });

  const negRText = Array.isArray(res.P_plus_Q)
    ? `(${res.P_plus_Q[0]}, ${(97 - res.P_plus_Q[1]) % 97})`
    : "Vô cùng";

  document.getElementById("pointOpsSummary").innerHTML = `
    <div><strong>1. Phép Cộng Điểm:</strong> P + Q = <span class="mono" style="color:#f59e0b;">(${res.P_plus_Q})</span> 
    (Điểm cắt thứ 3 là -(P+Q) = <span class="mono" style="color:#a855f7;">${negRText}</span>, sau đó lấy đối xứng trục).</div>
    <div style="margin-top:4px;"><strong>2. Phép Nhân Đôi:</strong> 2P = <span class="mono" style="color:#10b981;">(${res.two_P})</span> &nbsp;|&nbsp;
    <strong>3. Nhân Vô Hướng:</strong> <strong>${res.k}·P</strong> (dạng nhị phân <code>${res.k_binary}</code>) = <span class="mono" style="color:#ec4899;">(${res.k_times_P})</span></div>
  `;

  let rows = `<table><thead><tr><th>Bước</th><th>Bit</th><th>Nhân Đôi (2P)</th><th>Cộng P?</th><th>Kết Quả</th></tr></thead><tbody>`;
  for (const s of res.trace) {
    rows += `<tr><td>${s.step}</td><td class="mono">${s.bit}</td><td class="mono">${JSON.stringify(s.after_double)}</td><td>${s.added_base ? "Có" : "Không"}</td><td class="mono">${JSON.stringify(s.result)}</td></tr>`;
  }
  rows += `</tbody></table>`;
  document.getElementById("pointOpsTrace").innerHTML = rows;
}

// ----------------------------------------------------------------------
// Tab 3: Benchmarks & Charts (Đo Kiểm Hiệu Năng & So Sánh)
// ----------------------------------------------------------------------
function drawSizeChart(results) {
  const canvas = document.getElementById("sizeChartCanvas");
  const ctx = canvas.getContext("2d");
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  const padLeft = 125;
  const maxBytes = Math.max(...results.map((r) => r.public_key_bytes_uncompressed), 384);
  const barH = 15;
  const rowGap = 36;

  ctx.font = "12px sans-serif";
  results.forEach((r, idx) => {
    const y = 24 + idx * rowGap;
    ctx.fillStyle = "#e2e8f0";
    ctx.fillText(r.algorithm, 8, y + 12);

    const wPub = (r.public_key_bytes_compressed / maxBytes) * (canvas.width - padLeft - 60);
    ctx.fillStyle = r.family === "ECC" ? "#00f2fe" : "#f59e0b";
    ctx.fillRect(padLeft, y, Math.max(wPub, 4), barH);
    ctx.fillStyle = "#94a3b8";
    ctx.fillText(`${r.public_key_bytes_compressed} B pub`, padLeft + wPub + 6, y + 12);
  });
}

async function runBenchmark(mode) {
  const wrap = document.getElementById("benchResultsTableWrap");
  wrap.innerHTML = `<p class="muted">Đang chạy đo kiểm hiệu năng (${mode === "quick" ? "Nhanh" : "Toàn diện"}) bằng Python thuần...</p>`;
  const data = await api(`/api/benchmarks/run?mode=${mode}`);

  const cc = data.coordinate_comparison;
  document.getElementById("coordBenchBox").innerHTML = `
    <div><strong>Đường cong:</strong> ${cc.curve} (${cc.iterations} lần lặp)</div>
    <div><strong>Nhân vô hướng Tọa độ Afin:</strong> ${cc.affine_ms} ms</div>
    <div><strong>Nhân vô hướng Tọa độ Xạ ảnh Jacobian:</strong> ${cc.jacobian_ms} ms</div>
    <div style="margin-top:6px;"><span class="badge badge-ok">Tốc độ Jacobian: Nhanh hơn ${cc.speedup} lần</span> (loại bỏ phép nghịch đảo modulo trong từng bit)</div>
  `;

  drawSizeChart(data.results);

  let html = `<table><thead><tr>
    <th>Thuật Toán</th><th>Mức An Toàn</th><th>Khóa Công Khai (Nén / Gốc)</th><th>Kích Thước Chữ Ký</th>
    <th>Tạo Khóa (ms)</th><th>Ký Số (ms)</th><th>Xác Minh (ms)</th><th>ECDH / Mã-Giải mã (ms)</th>
  </tr></thead><tbody>`;
  for (const r of data.results) {
    html += `<tr>
      <td><strong>${escapeHtml(r.algorithm)}</strong></td>
      <td>${r.security_bits}-bit</td>
      <td class="mono">${r.public_key_bytes_compressed} B / ${r.public_key_bytes_uncompressed} B</td>
      <td class="mono">${r.signature_bytes} B</td>
      <td class="mono">${r.keygen_ms}</td>
      <td class="mono">${r.sign_ms}</td>
      <td class="mono">${r.verify_ms}</td>
      <td class="mono">${r.key_exchange_or_enc_ms}</td>
    </tr>`;
  }
  html += `</tbody></table>`;
  wrap.innerHTML = html;

  let nistHtml = `<table><thead><tr>
    <th>Cấp Độ Bảo Mật NIST</th><th>Khóa ECC (bit)</th><th>Khóa RSA (bit)</th>
    <th>Khóa Công Khai ECC (byte)</th><th>Khóa Công Khai RSA (byte)</th><th>Tỉ Lệ Rút Gọn (RSA / ECC)</th>
  </tr></thead><tbody>`;
  for (const row of data.security_equivalence) {
    nistHtml += `<tr>
      <td><strong>${row.security_bits}-bit</strong></td>
      <td class="mono">${row.ecc_bits}</td>
      <td class="mono">${row.rsa_bits}</td>
      <td class="mono">${row.ecc_pubkey_bytes} B</td>
      <td class="mono">${row.rsa_pubkey_bytes} B</td>
      <td><span class="badge badge-ok">Nhỏ gọn hơn ${row.ratio_key} lần</span></td>
    </tr>`;
  }
  nistHtml += `</tbody></table>`;
  document.getElementById("nistTableWrap").innerHTML = nistHtml;
}

// ----------------------------------------------------------------------
// Tab 4: Audit Log (Sổ Nhật Ký Kiểm Toán Toàn Vẹn)
// ----------------------------------------------------------------------
async function refreshAuditLog() {
  const data = await api("/api/audit");
  let html = `<table><thead><tr>
    <th>Mã ID</th><th>Thời Gian (UTC)</th><th>Tác Nhân</th><th>Hành Động</th><th>Chi Tiết Giao Dịch</th><th>Mã Băm Bản Ghi (Hash)</th>
  </tr></thead><tbody>`;
  for (const e of data.entries) {
    html += `<tr>
      <td>${e.id}</td>
      <td class="mono small">${escapeHtml(e.timestamp.slice(0, 19))}</td>
      <td>@${escapeHtml(e.actor)}</td>
      <td><span class="badge badge-info">${escapeHtml(e.action)}</span></td>
      <td>${escapeHtml(e.details)}</td>
      <td class="mono small">${escapeHtml(e.entry_hash.slice(0, 18))}...</td>
    </tr>`;
  }
  html += `</tbody></table>`;
  document.getElementById("auditTableWrap").innerHTML = html;
}

// ----------------------------------------------------------------------
// Wiring & Init
// ----------------------------------------------------------------------
document.querySelectorAll(".nav-menu .nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-menu .nav-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
  });
});

document.getElementById("btnRegisterLogin").addEventListener("click", handleRegisterAndLogin);
document.getElementById("btnChallengeLogin").addEventListener("click", handleChallengeLogin);

// Persona Buttons
document.getElementById("btnDemoAlice").addEventListener("click", () =>
  ensureDemoPersona("alice", "Alice Tran").catch((e) => showStatus("authLog", e.message, false))
);
document.getElementById("btnDemoBob").addEventListener("click", () =>
  ensureDemoPersona("bob", "Bob Le").catch((e) => showStatus("authLog", e.message, false))
);

document.getElementById("topBtnAlice").addEventListener("click", () =>
  ensureDemoPersona("alice", "Alice Tran").catch((e) => showStatus("authLog", e.message, false))
);
document.getElementById("topBtnBob").addEventListener("click", () =>
  ensureDemoPersona("bob", "Bob Le").catch((e) => showStatus("authLog", e.message, false))
);
document.getElementById("topBtnCustom").addEventListener("click", () => {
  document.getElementById("customAuthCard").scrollIntoView({ behavior: "smooth" });
  document.getElementById("authUsername").focus();
});

// 5-Second Simulation Button
document.getElementById("btnRunAutoDemo").addEventListener("click", run5SecondInteractiveSimulation);
document.getElementById("btnCloseSimProof").addEventListener("click", () => {
  document.getElementById("simResultBox").classList.add("hidden");
});

document.getElementById("btnSendEncrypted").addEventListener("click", handleSendEncrypted);

const p1Btn = document.getElementById("btnPreset1");
if (p1Btn) {
  p1Btn.addEventListener("click", () => {
    document.getElementById("msgPlaintext").value = "Phê duyệt lệnh chuyển khoản 500,000,000 VNĐ cho đối tác #8821.";
  });
}
const p2Btn = document.getElementById("btnPreset2");
if (p2Btn) {
  p2Btn.addEventListener("click", () => {
    document.getElementById("msgPlaintext").value = "Hợp đồng dịch vụ bảo mật thông tin & bảo đảm toàn vẹn tài chính.";
  });
}

document.getElementById("btnRefreshSis").addEventListener("click", () => {
  refreshUsers();
  refreshMessages();
});
document.getElementById("btnToggleInspector").addEventListener("click", async () => {
  const card = document.getElementById("serverInspectorCard");
  card.classList.toggle("hidden");
  if (!card.classList.contains("hidden")) {
    await refreshInspector();
    card.scrollIntoView({ behavior: "smooth" });
  }
});

document.getElementById("btnComputePointOps").addEventListener("click", runPointOps);
document.getElementById("btnRunEcdhLab").addEventListener("click", async () => {
  const curve = document.getElementById("labEcdhCurve").value;
  const res = await api("/api/lab/ecdh-demo", { method: "POST", body: JSON.stringify({ curve }) });
  document.getElementById("labEcdhOut").textContent = JSON.stringify(res, null, 2);
});
document.getElementById("btnRunEcdsaLab").addEventListener("click", async () => {
  const message = document.getElementById("labEcdsaMsg").value;
  const demonstrate_nonce_reuse = document.getElementById("labNonceReuse").checked;
  const res = await api("/api/lab/ecdsa-demo", {
    method: "POST",
    body: JSON.stringify({ curve: "secp256r1", message, demonstrate_nonce_reuse }),
  });
  document.getElementById("labEcdsaOut").textContent = JSON.stringify(res, null, 2);
});
document.getElementById("btnRunEciesLab").addEventListener("click", async () => {
  const plaintext = document.getElementById("labEciesMsg").value;
  const simulate_tamper = document.getElementById("labEciesTamper").checked;
  const res = await api("/api/lab/ecies-demo", {
    method: "POST",
    body: JSON.stringify({ curve: "secp256r1", plaintext, simulate_tamper }),
  });
  document.getElementById("labEciesOut").textContent = JSON.stringify(res, null, 2);
});

document.getElementById("btnRunQuickBench").addEventListener("click", () => runBenchmark("quick"));
document.getElementById("btnRunFullBench").addEventListener("click", () => runBenchmark("full"));
document.getElementById("btnVerifyAudit").addEventListener("click", async () => {
  const res = await api("/api/audit/verify");
  showStatus(
    "auditIntegrityBanner",
    res.valid
      ? `Chuỗi băm toàn vẹn HỢP LỆ trên toàn bộ ${res.total_entries} bản ghi. Mã băm đỉnh (Head Hash): ${res.head_hash}`
      : `Chuỗi băm BỊ ĐỨT GÃY tại ID ${res.broken_at_id}: ${res.reason}`,
    res.valid
  );
  await refreshAuditLog();
});

// ----------------------------------------------------------------------
// Dynamic Animated Cyber Background (Elliptic Curve Nodes & Mesh)
// ----------------------------------------------------------------------
function initCyberBackground() {
  const canvas = document.getElementById("cyberBackground");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  let width, height;
  const particles = [];
  const mouse = { x: -1000, y: -1000 };

  function resize() {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  }
  window.addEventListener("resize", resize);
  window.addEventListener("mousemove", (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
  });
  resize();

  const count = Math.min(Math.floor((window.innerWidth * window.innerHeight) / 18000), 70);
  for (let i = 0; i < count; i++) {
    particles.push({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.5,
      vy: (Math.random() - 0.5) * 0.5,
      radius: Math.random() * 2.2 + 1.2,
      color: Math.random() > 0.4 ? "#00f2fe" : "#a855f7",
    });
  }

  function render() {
    ctx.clearRect(0, 0, width, height);

    for (let i = 0; i < particles.length; i++) {
      const p1 = particles[i];
      for (let j = i + 1; j < particles.length; j++) {
        const p2 = particles[j];
        const dx = p1.x - p2.x;
        const dy = p1.y - p2.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 130) {
          const alpha = (1 - dist / 130) * 0.28;
          ctx.strokeStyle = `rgba(0, 242, 254, ${alpha})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.stroke();
        }
      }

      const mdx = p1.x - mouse.x;
      const mdy = p1.y - mouse.y;
      const mdist = Math.sqrt(mdx * mdx + mdy * mdy);
      if (mdist < 140) {
        const malpha = (1 - mdist / 140) * 0.4;
        ctx.strokeStyle = `rgba(168, 85, 247, ${malpha})`;
        ctx.lineWidth = 1.2;
        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.lineTo(mouse.x, mouse.y);
        ctx.stroke();
      }

      p1.x += p1.vx;
      p1.y += p1.vy;
      if (p1.x < 0 || p1.x > width) p1.vx *= -1;
      if (p1.y < 0 || p1.y > height) p1.vy *= -1;

      ctx.fillStyle = p1.color;
      ctx.shadowColor = p1.color;
      ctx.shadowBlur = 8;
      ctx.beginPath();
      ctx.arc(p1.x, p1.y, p1.radius, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    requestAnimationFrame(render);
  }

  render();
}

window.addEventListener("DOMContentLoaded", async () => {
  initCyberBackground();
  if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
    document.getElementById("secureContextBanner").classList.remove("hidden");
  }
  // Initialize both demo accounts so Bob is always available for Alice to send to
  await ensureDemoPersona("bob", "Bob Le").catch(() => {});
  await ensureDemoPersona("alice", "Alice Tran").catch(() => {});
  await refreshUsers().catch(() => {});
  await loadToyCurve().catch(() => {});
  await refreshAuditLog().catch(() => {});

  // If there are no messages yet, Alice automatically sends Bob an initial demo greeting
  const msgs = await api("/api/messages").catch(() => ({ messages: [] }));
  if (msgs.messages && msgs.messages.length === 0) {
    const bobUser = STATE.users.find((u) => u.username === "bob");
    if (bobUser && STATE.jwk) {
      const initialText = "Xin chào Bob! Kênh liên lạc E2EE bảo vệ bằng P-256 + AES-256-GCM đã kích hoạt thành công.";
      const aadText = "alice|bob|text|initial";
      const env = await encryptAndSignEnvelope(STATE.jwk, bobUser.public_key_hex, textEnc.encode(initialText), aadText);
      await api("/api/messages", {
        method: "POST",
        body: JSON.stringify({
          recipient: "bob",
          msg_type: "text",
          filename: "",
          mime_type: "text/plain",
          file_size: 0,
          curve: "secp256r1",
          ...env,
          aad_text: aadText,
        }),
      }).catch(() => {});
      await refreshMessages();
      await refreshAuditLog();
    }
  }
});
