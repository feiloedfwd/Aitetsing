// api/whitelist.js
import crypto from "crypto";

const WHITELIST_KEY = 7;
const XOR_SEED     = 13;
const OUTER_XOR    = 0xA5;
const SECRET       = "x9K2-PL3-Qm7-Zr5-Lp2-Wt8"; // NEVER shipped to client
const TOKEN_TTL    = 30_000; // 30 seconds

// ============================================================
//  LOCAL WHITELIST TABLE (server-side, never sent to client)
// ============================================================
const whitelistTable = {
    "Player1":     true,
    "Builderman":  true,
    "PremiumUser": true,
    "Roblox":      true,
};
// ============================================================

// ---------- Multi-layer encode (5 layers) ----------
function encodePayload(str) {
    let hex = "";
    for (let i = 0; i < str.length; i++) {
        const c   = str.charCodeAt(i);
        const x   = c ^ ((i * XOR_SEED + 7) & 0xFF);   // L1: rotating XOR
        const s   = (x + WHITELIST_KEY) & 0xFF;        // L2: shift
        hex += s.toString(16).padStart(2, "0");
    }
    const reversed = hex.split("").reverse().join(""); // L3: reverse
    const b64      = Buffer.from(reversed).toString("base64"); // L4: base64
    let outer = "";
    for (let i = 0; i < b64.length; i++) {              // L5: XOR pass
        outer += String.fromCharCode(b64.charCodeAt(i) ^ OUTER_XOR);
    }
    return Buffer.from(outer).toString("base64");
}

// ---------- Multi-layer decode ----------
function decodePayload(encoded) {
    const b64x = Buffer.from(encoded, "base64").toString("utf-8");
    let b64 = "";
    for (let i = 0; i < b64x.length; i++) {
        b64 += String.fromCharCode(b64x.charCodeAt(i) ^ OUTER_XOR);
    }
    const reversed = Buffer.from(b64, "base64").toString("utf-8");
    const hex = reversed.split("").reverse().join("");
    let out = "";
    let i = 0;
    for (let j = 0; j < hex.length; j += 2) {
        const code      = parseInt(hex.substr(j, 2), 16);
        const unshifted = (code - WHITELIST_KEY) & 0xFF;
        const unxored   = unshifted ^ ((i * XOR_SEED + 7) & 0xFF);
        out += String.fromCharCode(unxored);
        i++;
    }
    return out;
}

// ---------- HMAC-SHA256 ----------
function hmac(data, key) {
    return crypto.createHmac("sha256", key).update(data).digest("hex");
}

// ---------- Robust nonce check ----------
const seenNonces = new Set();

export default function handler(req, res) {
    if (req.method !== "POST") {
        return res.status(405).json({ user: false });
    }

    try {
        const { data, nonce, hwid } = req.body || {};
        if (!data || !nonce || !hwid) {
            return res.status(200).json({ user: false, reason: "missing_fields" });
        }

        // Reject replayed nonces
        if (seenNonces.has(nonce)) {
            return res.status(200).json({ user: false, reason: "nonce_replay" });
        }
        seenNonces.add(nonce);
        // Light cleanup (Set grows unboundedly — fine for serverless short life)
        if (seenNonces.size > 5000) seenNonces.clear();

        const username = decodePayload(data);

        if (!whitelistTable[username]) {
            return res.status(200).json({ user: false, reason: "not_whitelisted" });
        }

        const reversedUsername = username.split("").reverse().join("");
        const timestamp = Date.now();

        // Payload: username:reversedUsername:timestamp:nonce:hwid
        const payload = `${username}:${reversedUsername}:${timestamp}:${nonce}:${hwid}`;
        const token   = encodePayload(payload);
        const sig     = hmac(payload, SECRET);

        return res.status(200).json({
            user: true,
            token,
            sig,
            ts: timestamp,
        });
    } catch (e) {
        return res.status(200).json({ user: false, reason: "server_error" });
    }
      }
