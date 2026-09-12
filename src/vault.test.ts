import { describe, expect, it } from "vitest";
import { decryptVault, encryptVault, type EncryptedVault } from "./vault";

describe("encryptVault / decryptVault round-trip", () => {
  it("decrypts with the correct password", async () => {
    const plaintext = crypto.getRandomValues(new Uint8Array(24));
    const vault = await encryptVault("correct horse battery staple", plaintext);
    const decrypted = await decryptVault("correct horse battery staple", vault);
    expect(decrypted).toEqual(plaintext);
  });

  it("rejects the wrong password", async () => {
    const plaintext = crypto.getRandomValues(new Uint8Array(24));
    const vault = await encryptVault("correct password", plaintext);
    await expect(decryptVault("wrong password", vault)).rejects.toThrow("Incorrect password");
  });

  it("produces a different salt/iv/ciphertext each time, even for the same password and plaintext", async () => {
    const plaintext = new Uint8Array(24).fill(7);
    const vaultA = await encryptVault("same password", plaintext);
    const vaultB = await encryptVault("same password", plaintext);
    expect(vaultA.salt).not.toBe(vaultB.salt);
    expect(vaultA.iv).not.toBe(vaultB.iv);
    expect(vaultA.ciphertext).not.toBe(vaultB.ciphertext);
    // But both still decrypt back to the identical plaintext.
    expect(await decryptVault("same password", vaultA)).toEqual(plaintext);
    expect(await decryptVault("same password", vaultB)).toEqual(plaintext);
  });

  it("rejects a tampered ciphertext (AES-GCM auth tag fails)", async () => {
    const plaintext = crypto.getRandomValues(new Uint8Array(24));
    const vault = await encryptVault("a password", plaintext);
    const tampered: EncryptedVault = {
      ...vault,
      ciphertext: vault.ciphertext.slice(0, -2) + (vault.ciphertext.slice(-2) === "00" ? "01" : "00"),
    };
    await expect(decryptVault("a password", tampered)).rejects.toThrow("Incorrect password");
  });

  it("round-trips an empty plaintext", async () => {
    const vault = await encryptVault("password", new Uint8Array(0));
    expect(await decryptVault("password", vault)).toEqual(new Uint8Array(0));
  });
});
