// Password-based encryption for the wallet's master seed, using the browser's native WebCrypto
// (available in both the background service worker and the popup) — no custom crypto here.
// PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP's 2023 minimum recommendation) derives an
// AES-256-GCM key from the unlock password; the encrypted blob is what's persisted to
// chrome.storage.local. The derived key and plaintext seed only ever live in memory, and only for
// as long as the wallet is unlocked (see background/session.ts).

const PBKDF2_ITERATIONS = 600_000;

export interface EncryptedVault {
  version: 1;
  salt: string; // hex
  iv: string; // hex
  ciphertext: string; // hex
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

async function deriveAesKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptVault(password: string, plaintext: Uint8Array): Promise<EncryptedVault> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveAesKey(password, salt);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource }, key, plaintext as BufferSource)
  );
  return { version: 1, salt: toHex(salt), iv: toHex(iv), ciphertext: toHex(ciphertext) };
}

/** @throws if the password is wrong or the vault is corrupt. */
export async function decryptVault(password: string, vault: EncryptedVault): Promise<Uint8Array> {
  const salt = fromHex(vault.salt);
  const iv = fromHex(vault.iv);
  const key = await deriveAesKey(password, salt);
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv as BufferSource },
      key,
      fromHex(vault.ciphertext) as BufferSource
    );
    return new Uint8Array(plaintext);
  } catch {
    throw new Error("Incorrect password");
  }
}
