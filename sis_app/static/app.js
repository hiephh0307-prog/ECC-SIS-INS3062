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
  lastPointOpsRes: null,
  lastBenchData: null,
  lastAuditVerifyRes: null,
  usingStandalone: window.location.hostname.endsWith(".github.io") || window.location.protocol === "file:",
};

const t = (key, vars) => (window.ECC_I18N ? window.ECC_I18N.t(key, vars) : key);

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
      error: t("err_ecdsa_verify"),
    };
  }

  if (msg.recipient !== STATE.username) {
    return {
      sigValid: true,
      decrypted: false,
      senderCopy: true,
      error: t("sender_copy_note"),
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
  } catch (_) {
    return {
      sigValid: true,
      decrypted: false,
      error: t("err_gcm_tag"),
    };
  }
}

// ----------------------------------------------------------------------
// Hybrid HTTP API Helper (Python FastAPI first -> Browser Engine fallback)
// ----------------------------------------------------------------------
function updateModeBadge() {
  const el = document.getElementById("runtimeModeBadge");
  if (!el) return;
  el.textContent = STATE.usingStandalone ? t("mode_standalone") : t("mode_backend");
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (STATE.token) {
    headers["Authorization"] = `Bearer ${STATE.token}`;
  }

  if (STATE.usingStandalone && window.ECC_STANDALONE_API) {
    return window.ECC_STANDALONE_API.handle(path, { ...options, headers });
  }

  try {
    const resp = await fetch(path, { ...options, headers });
    const ct = resp.headers.get("content-type") || "";
    if ((resp.status === 404 || resp.status === 405 || !ct.includes("application/json")) && window.ECC_STANDALONE_API) {
      STATE.usingStandalone = true;
      updateModeBadge();
      return window.ECC_STANDALONE_API.handle(path, { ...options, headers });
    }
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      throw new Error(data.detail || `HTTP ${resp.status}`);
    }
    return data;
  } catch (err) {
    if (window.ECC_STANDALONE_API && (err instanceof TypeError || String(err.message).includes("Failed to fetch"))) {
      STATE.usingStandalone = true;
      updateModeBadge();
      return window.ECC_STANDALONE_API.handle(path, { ...options, headers });
    }
    throw err;
  }
}

function showStatus(elId, msg, ok = true) {
  const el = document.getElementById(elId);
  if (!el) return;
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
  badge.innerHTML = `<span class="status-indicator"></span> ${escapeHtml(verified.display_name)} (@${escapeHtml(verified.username)})`;
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
    throw new Error(t("err_user_exists_diff_key", { user: username }));
  }

  await loginWithStoredKey(username, jwk);
  showStatus("authLog", t("msg_logged_in_as", { name: displayName, user: username }), true);
}

async function handleRegisterAndLogin() {
  const username = document.getElementById("authUsername").value.trim();
  const displayName = document.getElementById("authDisplayName").value.trim() || username;
  if (!username) {
    showStatus("authLog", t("err_enter_username"), false);
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
    showStatus("authLog", t("msg_registered_ok", { user: username }), true);
  } catch (err) {
    showStatus("authLog", err.message, false);
  }
}

async function handleChallengeLogin() {
  const username = document.getElementById("authUsername").value.trim();
  if (!username) {
    showStatus("authLog", t("err_enter_username_login"), false);
    return;
  }
  const saved = localStorage.getItem(STORAGE_PREFIX + username);
  if (!saved) {
    showStatus("authLog", t("err_no_local_key", { user: username }), false);
    return;
  }
  try {
    await loginWithStoredKey(username, JSON.parse(saved));
    showStatus("authLog", t("msg_challenge_ok", { user: username }), true);
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
    showStatus("sendStatus", t("err_login_first"), false);
    return;
  }
  const recipient = document.getElementById("msgRecipient").value;
  const targetUser = STATE.users.find((u) => u.username === recipient);
  if (!targetUser) {
    showStatus("sendStatus", t("err_pick_recipient"), false);
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
        showStatus("sendStatus", t("err_file_too_large"), false);
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
        showStatus("sendStatus", t("err_empty_payload"), false);
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
      t("msg_sent_ok", { bytes: env.ciphertext_hex.length / 2, user: recipient }),
      true
    );
    await refreshMessages();
    await refreshAuditLog();
  } catch (err) {
    showStatus("sendStatus", err.message, false);
  }
}

// ----------------------------------------------------------------------
// Message Cards with Cryptographic Indicators
// ----------------------------------------------------------------------
async function refreshMessages() {
  if (!STATE.token) return;
  const data = await api("/api/messages");
  const container = document.getElementById("messagesList");
  if (!data.messages.length) {
    container.innerHTML = `<p class="muted">${escapeHtml(t("empty_inbox", { user: STATE.username }))}</p>`;
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
        ? `<span class="badge badge-info">${escapeHtml(t("badge_from", { user: msg.sender }))}</span>`
        : `<span class="badge badge-warning">${escapeHtml(t("badge_to", { user: msg.recipient }))}</span>`;

    const sigBadge = res.sigValid
      ? `<span class="badge badge-ok">${escapeHtml(t("badge_sig_ok"))}</span>`
      : `<span class="badge badge-err">${escapeHtml(t("badge_sig_err"))}</span>`;

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
              ${escapeHtml(t("unlocked_file", { name: msg.filename, size: msg.file_size }))}
            </div>
            ${parsed.note ? `<div class="small muted">${escapeHtml(t("file_note", { note: parsed.note }))}</div>` : ""}
            <div style="margin-top:8px;">
              <a class="btn btn-primary btn-sm" href="${blobUrl}" download="${escapeHtml(msg.filename)}">
                ${escapeHtml(t("btn_download_file"))}
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
          <div class="muted small"><em>${escapeHtml(t("sender_copy_note"))}</em></div>
        </div>
      `;
    } else {
      bodyHtml = `
        <div class="tamper-warning-box">
          <div class="tamper-warning-title">${escapeHtml(t("tamper_alert_title", { id: msg.id }))}</div>
          <div class="tamper-warning-detail">❌ ${escapeHtml(res.error)}</div>
          <div class="small" style="color:#fecaca; margin-top:6px;">
            ${t("tamper_zero_trust_note")}
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
          <button type="button" class="btn btn-danger btn-sm btn-tamper" data-id="${msg.id}" title="${escapeHtml(t("btn_tamper_title"))}">
            ${escapeHtml(t("btn_tamper"))}
          </button>
        </div>
      </div>

      ${bodyHtml}

      <div class="msg-inspect-toggle">
        <span class="mono small">
          <strong>${escapeHtml(t("lbl_eph_key"))}</strong> ${escapeHtml(msg.ephemeral_pubkey_hex.slice(0, 16))}... |
          <strong>${escapeHtml(t("lbl_db_cipher"))}</strong> ${escapeHtml(msg.ciphertext_hex.slice(0, 20))}...
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
// 5-Second Interactive Simulation
// ----------------------------------------------------------------------
async function run5SecondInteractiveSimulation() {
  const btn = document.getElementById("btnRunAutoDemo");
  btn.disabled = true;
  btn.innerHTML = `<span class="icon-pulse" aria-hidden="true">⚙️</span> <span>${escapeHtml(t("btn_running_5s"))}</span>`;

  const s1 = document.getElementById("stageSender");
  const s2 = document.getElementById("stageServer");
  const s3 = document.getElementById("stageRecipient");
  const p1 = document.getElementById("packetAnim1");
  const p2 = document.getElementById("packetAnim2");
  const simProof = document.getElementById("simResultBox");
  const simServerView = document.getElementById("simServerView");
  const simBobView = document.getElementById("simBobView");

  s1.classList.remove("highlight");
  s2.classList.remove("highlight");
  s3.classList.remove("highlight");
  p1.classList.remove("active-travel");
  p2.classList.remove("active-travel");

  try {
    s1.classList.add("highlight");
    await ensureDemoPersona("alice", "Alice Tran");

    const sampleText = t("sim_sample_msg");
    const bobUser = STATE.users.find((u) => u.username === "bob");
    if (!bobUser) {
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

    p1.classList.add("active-travel");
    await new Promise((r) => setTimeout(r, 800));

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
        plaintext: t("sim_zero_bytes"),
      },
      null,
      2
    );

    p2.classList.add("active-travel");
    await new Promise((r) => setTimeout(r, 800));

    s2.classList.remove("highlight");
    s3.classList.add("highlight");

    await ensureDemoPersona("bob", "Bob Le");
    simBobView.textContent = t("sim_bob_verified_lines", { text: sampleText });

    simProof.classList.remove("hidden");
    await refreshMessages();
  } catch (err) {
    alert(err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<span class="icon-pulse" aria-hidden="true">▶</span> <span data-i18n="btn_run_5s">${escapeHtml(t("btn_run_5s"))}</span>`;
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
    selP.appendChild(new Option(label, `${x},${y}`));
    selQ.appendChild(new Option(label, `${x},${y}`));
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

  let negR = null;
  if (Array.isArray(sum)) {
    negR = [sum[0], (p - (sum[1] % p)) % p];
  }

  if (Array.isArray(P) && Array.isArray(Q)) {
    const xP = mapX(P[0]), yP = mapY(P[1]);
    const xQ = mapX(Q[0]), yQ = mapY(Q[1]);

    if (P[0] === Q[0] && P[1] === Q[1]) {
      if (negR) {
        const xNeg = mapX(negR[0]), yNeg = mapY(negR[1]);
        html += `<line x1="${xP.toFixed(1)}" y1="${yP.toFixed(1)}" x2="${xNeg.toFixed(1)}" y2="${yNeg.toFixed(1)}" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" />`;
      }
    } else {
      html += `<line x1="${xP.toFixed(1)}" y1="${yP.toFixed(1)}" x2="${xQ.toFixed(1)}" y2="${yQ.toFixed(1)}" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" />`;
      if (negR) {
        const xNeg = mapX(negR[0]), yNeg = mapY(negR[1]);
        html += `<line x1="${xQ.toFixed(1)}" y1="${yQ.toFixed(1)}" x2="${xNeg.toFixed(1)}" y2="${yNeg.toFixed(1)}" stroke="#f59e0b" stroke-width="1.8" stroke-dasharray="4,3" />`;
      }
    }

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
  if (negR) drawHighlight(negR, "#a855f7", "-(P+Q)");
  drawHighlight(highlights.sum, "#f59e0b", "P+Q");
  drawHighlight(highlights.kP, "#ec4899", "kP");

  svg.innerHTML = html;
}

function renderPointOpsResult(res) {
  if (!res) return;
  const negRText = Array.isArray(res.P_plus_Q)
    ? `(${res.P_plus_Q[0]}, ${(97 - res.P_plus_Q[1]) % 97})`
    : t("infinity_pt");

  document.getElementById("pointOpsSummary").innerHTML = `
    <div><strong>${escapeHtml(t("ops_sum_1"))}</strong> P + Q = <span class="mono" style="color:#f59e0b;">(${res.P_plus_Q})</span>
    (${escapeHtml(t("ops_sum_inter"))} <span class="mono" style="color:#a855f7;">${negRText}</span>, ${escapeHtml(t("ops_sum_refl"))}).</div>
    <div style="margin-top:4px;"><strong>${escapeHtml(t("ops_sum_2"))}</strong> 2P = <span class="mono" style="color:#10b981;">(${res.two_P})</span> &nbsp;|&nbsp;
    <strong>${escapeHtml(t("ops_sum_3"))}</strong> <strong>${res.k}·P</strong> (${escapeHtml(t("ops_bin"))} <code>${res.k_binary}</code>) = <span class="mono" style="color:#ec4899;">(${res.k_times_P})</span></div>
  `;

  let rows = `<table><thead><tr><th scope="col">${escapeHtml(t("th_step"))}</th><th scope="col">${escapeHtml(t("th_bit"))}</th><th scope="col">${escapeHtml(t("th_double"))}</th><th scope="col">${escapeHtml(t("th_add"))}</th><th scope="col">${escapeHtml(t("th_result"))}</th></tr></thead><tbody>`;
  for (const s of res.trace) {
    rows += `<tr><td>${s.step}</td><td class="mono">${s.bit}</td><td class="mono">${JSON.stringify(s.after_double)}</td><td>${escapeHtml(s.added_base ? t("val_yes") : t("val_no"))}</td><td class="mono">${JSON.stringify(s.result)}</td></tr>`;
  }
  rows += `</tbody></table>`;
  document.getElementById("pointOpsTrace").innerHTML = rows;
}

async function runPointOps() {
  const [px, py] = document.getElementById("labPointP").value.split(",").map(Number);
  const [qx, qy] = document.getElementById("labPointQ").value.split(",").map(Number);
  const k = Number(document.getElementById("labScalarK").value) || 7;

  const res = await api("/api/lab/point-ops", {
    method: "POST",
    body: JSON.stringify({ px, py, qx, qy, k }),
  });
  STATE.lastPointOpsRes = res;

  drawToyCurveSvg(STATE.toyCurveData.points, {
    P: res.P,
    Q: res.Q,
    sum: res.P_plus_Q,
    kP: res.k_times_P,
  });
  renderPointOpsResult(res);
}

// ----------------------------------------------------------------------
// Tab 3: Benchmarks & Charts
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

function renderBenchmarkData(data) {
  if (!data) return;
  const cc = data.coordinate_comparison;
  document.getElementById("coordBenchBox").innerHTML = `
    <div><strong>${escapeHtml(t("coord_curve"))}</strong> ${cc.curve} (${cc.iterations} ${escapeHtml(t("coord_iters"))})</div>
    <div><strong>${escapeHtml(t("coord_affine"))}</strong> ${cc.affine_ms} ms</div>
    <div><strong>${escapeHtml(t("coord_jacobian"))}</strong> ${cc.jacobian_ms} ms</div>
    <div style="margin-top:6px;"><span class="badge badge-ok">${escapeHtml(t("coord_badge", { x: cc.speedup }))}</span> ${escapeHtml(t("coord_note"))}</div>
  `;

  drawSizeChart(data.results);

  let html = `<table><thead><tr>
    <th scope="col">${escapeHtml(t("th_algo"))}</th><th scope="col">${escapeHtml(t("th_sec_bits"))}</th><th scope="col">${escapeHtml(t("th_pubkey"))}</th><th scope="col">${escapeHtml(t("th_sig_size"))}</th>
    <th scope="col">${escapeHtml(t("th_keygen"))}</th><th scope="col">${escapeHtml(t("th_sign"))}</th><th scope="col">${escapeHtml(t("th_verify"))}</th><th scope="col">${escapeHtml(t("th_ecdh_enc"))}</th>
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
  document.getElementById("benchResultsTableWrap").innerHTML = html;

  let nistHtml = `<table><thead><tr>
    <th scope="col">${escapeHtml(t("th_nist_lvl"))}</th><th scope="col">${escapeHtml(t("th_ecc_bits"))}</th><th scope="col">${escapeHtml(t("th_rsa_bits"))}</th>
    <th scope="col">${escapeHtml(t("th_ecc_bytes"))}</th><th scope="col">${escapeHtml(t("th_rsa_bytes"))}</th><th scope="col">${escapeHtml(t("th_ratio"))}</th>
  </tr></thead><tbody>`;
  for (const row of data.security_equivalence) {
    nistHtml += `<tr>
      <td><strong>${row.security_bits}-bit</strong></td>
      <td class="mono">${row.ecc_bits}</td>
      <td class="mono">${row.rsa_bits}</td>
      <td class="mono">${row.ecc_pubkey_bytes} B</td>
      <td class="mono">${row.rsa_pubkey_bytes} B</td>
      <td><span class="badge badge-ok">${escapeHtml(t("badge_smaller", { x: row.ratio_key }))}</span></td>
    </tr>`;
  }
  nistHtml += `</tbody></table>`;
  document.getElementById("nistTableWrap").innerHTML = nistHtml;
}

async function runBenchmark(mode) {
  const wrap = document.getElementById("benchResultsTableWrap");
  const modeLabel = mode === "quick" ? t("mode_quick") : t("mode_full");
  wrap.innerHTML = `<p class="muted">${escapeHtml(t("bench_running", { mode: modeLabel }))}</p>`;
  const data = await api(`/api/benchmarks/run?mode=${mode}`);
  STATE.lastBenchData = data;
  renderBenchmarkData(data);
}

// ----------------------------------------------------------------------
// Tab 4: Audit Log
// ----------------------------------------------------------------------
async function refreshAuditLog() {
  const data = await api("/api/audit");
  let html = `<table><thead><tr>
    <th scope="col">${escapeHtml(t("th_id"))}</th><th scope="col">${escapeHtml(t("th_time"))}</th><th scope="col">${escapeHtml(t("th_actor"))}</th><th scope="col">${escapeHtml(t("th_action"))}</th><th scope="col">${escapeHtml(t("th_details"))}</th><th scope="col">${escapeHtml(t("th_hash"))}</th>
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
// Wiring, View Transitions & Bilingual Live Re-render
// ----------------------------------------------------------------------
function switchTab(tabName, routeFocus = false) {
  const applyTab = () => {
    document.querySelectorAll(".nav-menu .nav-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    const btn = document.querySelector(`.nav-menu .nav-btn[data-tab="${tabName}"]`);
    const panel = document.getElementById(`tab-${tabName}`);
    if (btn) btn.classList.add("active");
    if (panel) panel.classList.add("active");
  };

  const focusHeading = () => {
    if (!routeFocus) return;
    document.getElementById(`heading-${tabName}`)?.focus({ preventScroll: true });
  };

  if (!document.startViewTransition) {
    applyTab();
    focusHeading();
    return;
  }
  const transition = document.startViewTransition(applyTab);
  transition.finished.finally(focusHeading);
}

document.querySelectorAll(".nav-menu .nav-btn").forEach((btn) => {
  btn.addEventListener("click", (e) => switchTab(btn.dataset.tab, e.detail === 0));
});

document.querySelectorAll(".lang-btn[data-lang]").forEach((btn) => {
  btn.addEventListener("click", () => window.ECC_I18N?.setLang(btn.getAttribute("data-lang")));
});

if (window.ECC_I18N) {
  window.ECC_I18N.onChange(async () => {
    updateModeBadge();
    if (STATE.lastPointOpsRes) renderPointOpsResult(STATE.lastPointOpsRes);
    if (STATE.lastBenchData) renderBenchmarkData(STATE.lastBenchData);
    if (STATE.lastAuditVerifyRes) {
      const r = STATE.lastAuditVerifyRes;
      showStatus(
        "auditIntegrityBanner",
        r.valid
          ? t("audit_valid_msg", { n: r.total_entries, hash: r.head_hash })
          : t("audit_broken_msg", { id: r.broken_at_id, reason: r.reason }),
        r.valid
      );
    }
    if (STATE.token) {
      await refreshMessages().catch(() => {});
      await refreshAuditLog().catch(() => {});
    }
  });
}

document.getElementById("btnRegisterLogin").addEventListener("click", handleRegisterAndLogin);
document.getElementById("btnChallengeLogin").addEventListener("click", handleChallengeLogin);

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

document.getElementById("btnRunAutoDemo").addEventListener("click", run5SecondInteractiveSimulation);
document.getElementById("btnCloseSimProof").addEventListener("click", () => {
  document.getElementById("simResultBox").classList.add("hidden");
});

document.getElementById("btnSendEncrypted").addEventListener("click", handleSendEncrypted);

document.getElementById("btnPreset1")?.addEventListener("click", () => {
  document.getElementById("msgPlaintext").value = t("preset1_text");
});
document.getElementById("btnPreset2")?.addEventListener("click", () => {
  document.getElementById("msgPlaintext").value = t("preset2_text");
});

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
  STATE.lastAuditVerifyRes = res;
  showStatus(
    "auditIntegrityBanner",
    res.valid
      ? t("audit_valid_msg", { n: res.total_entries, hash: res.head_hash })
      : t("audit_broken_msg", { id: res.broken_at_id, reason: res.reason }),
    res.valid
  );
  await refreshAuditLog();
});

// ----------------------------------------------------------------------
// Dynamic Animated Cyber Background
// ----------------------------------------------------------------------
function initCyberBackground() {
  const canvas = document.getElementById("cyberBackground");
  if (!canvas) return;
  if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

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
  window.ECC_I18N?.applyStaticTranslations();
  initCyberBackground();
  if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
    document.getElementById("secureContextBanner").classList.remove("hidden");
  }
  await ensureDemoPersona("bob", "Bob Le").catch(() => {});
  await ensureDemoPersona("alice", "Alice Tran").catch(() => {});
  updateModeBadge();
  await refreshUsers().catch(() => {});
  await loadToyCurve().catch(() => {});
  await refreshAuditLog().catch(() => {});

  const msgs = await api("/api/messages").catch(() => ({ messages: [] }));
  if (msgs.messages && msgs.messages.length === 0) {
    const bobUser = STATE.users.find((u) => u.username === "bob");
    if (bobUser && STATE.jwk) {
      const initialText = "Hello Bob! P-256 + AES-256-GCM End-to-End Encrypted channel is live.";
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
