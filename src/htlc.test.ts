import { describe, expect, it } from "vitest";
import { createStealthOutputWitness, generateKeypair, generateOotleAddress, validateStealthTransfer } from "@tari-project/ootle-wasm";
import { accessRuleRequiringPublicKey, htlcConditions } from "./htlc";
import { buildHtlcSpendStatement } from "./wallet";
import { toHex } from "./vault";

async function sha256Hex(data: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource)));
}

// Golden vector generated directly from `tari_ootle_wallet_crypto`'s real Rust types (a throwaway
// `#[test]` using the exact same `htlc_conditions`/`requires_public_key` shape as
// `applications/tari_walletd/src/handlers/accounts.rs`'s own reference test, run against a local
// clone of tari-project/tari-ootle's `development` branch and discarded afterward -- not
// hand-derived, not assumed from docs). Preimage was the literal bytes `"golden-vector-preimage"`;
// its SHA-256 digest is hardcoded below rather than recomputed, so this test never needs to
// reimplement hashing itself.
const CLAIMANT_PK_HEX = "5c7f0fec164142986ada18df7c0950d93827925ece06b0e6a1247b6a3a304c7c";
const REFUNDER_PK_HEX = "c2a0394cab5ff3b6b51335386d8fb473cf03db714258bc17a10165783b3cf46c";
const HASH_LOCK_HEX = "1b6c2e0578ba7761629d1375c33498b763865a9d8f74b700e023e2cbe0cd39d8";
const REFUND_EPOCH = 4242n;
const EXPECTED_CONDITIONS_JSON =
  '[[{"Builtin":{"HashLock":{"hash":"1b6c2e0578ba7761629d1375c33498b763865a9d8f74b700e023e2cbe0cd39d8","alg":"Sha256"}}},{"Builtin":{"BeforeEpoch":4242}},{"AccessRule":{"Restricted":{"Require":{"Require":{"NonFungibleAddress":{"resource_address":"resource_0100000000000000000000000000000000000000000000000000000000000000","id":{"U256":"5c7f0fec164142986ada18df7c0950d93827925ece06b0e6a1247b6a3a304c7c"}}}}}}}],[{"Builtin":{"AfterEpoch":4242}},{"AccessRule":{"Restricted":{"Require":{"Require":{"NonFungibleAddress":{"resource_address":"resource_0100000000000000000000000000000000000000000000000000000000000000","id":{"U256":"c2a0394cab5ff3b6b51335386d8fb473cf03db714258bc17a10165783b3cf46c"}}}}}}}]]';
const EXPECTED_CONDITION_ROOT = "f53bd17bf4b3585314ca397c163446d01625db36075f40ef49de906075fe0a4b";

describe("htlcConditions", () => {
  it("matches the Rust reference implementation's JSON byte-for-byte", () => {
    const conditions = htlcConditions({
      hashLockHex: HASH_LOCK_HEX,
      refundEpoch: REFUND_EPOCH,
      claimantPublicKeyHex: CLAIMANT_PK_HEX,
      refunderPublicKeyHex: REFUNDER_PK_HEX,
    });
    expect(JSON.stringify(conditions)).toBe(EXPECTED_CONDITIONS_JSON);
  });

  // Exercises the exact same wasm entry point OotleAccount.htlcFund() itself calls
  // (createStealthOutputWitness with payTo: { Conditions }) -- the published @tari-project/
  // ootle-wasm already supports this (confirmed live before any vendoring this session); it's
  // only the *spend* side (claim/refund) that ever needed the newer, since-reverted wasm build
  // (see pnpm-workspace.yaml's override comment for why that got reverted).
  it("produces a condition root (via the real wasm build) matching the independently-computed Rust root", () => {
    const conditions = htlcConditions({
      hashLockHex: HASH_LOCK_HEX,
      refundEpoch: REFUND_EPOCH,
      claimantPublicKeyHex: CLAIMANT_PK_HEX,
      refunderPublicKeyHex: REFUNDER_PK_HEX,
    });
    const dest = generateKeypair();
    const witnessJson = createStealthOutputWitness(
      0x26,
      dest.public_key,
      dest.public_key,
      1_000_000n,
      "resource_0101010101010101010101010101010101010101010101010101010101010101",
      null,
      null,
      JSON.stringify({ Conditions: conditions }),
      0n
    );
    const auth = JSON.parse(witnessJson).auth;
    expect(auth.Script).toBe(EXPECTED_CONDITION_ROOT);
  });

  it("rejects a refundEpoch that isn't a safe JS integer", () => {
    expect(() =>
      htlcConditions({
        hashLockHex: HASH_LOCK_HEX,
        refundEpoch: 2n ** 60n,
        claimantPublicKeyHex: CLAIMANT_PK_HEX,
        refunderPublicKeyHex: REFUNDER_PK_HEX,
      })
    ).toThrow(/safe JS integer/);
  });

  it("rejects a non-positive refundEpoch", () => {
    expect(() =>
      htlcConditions({
        hashLockHex: HASH_LOCK_HEX,
        refundEpoch: 0n,
        claimantPublicKeyHex: CLAIMANT_PK_HEX,
        refunderPublicKeyHex: REFUNDER_PK_HEX,
      })
    ).toThrow(/positive epoch/);
  });

  it("rejects a hashLockHex that isn't exactly 64 hex characters", () => {
    expect(() =>
      htlcConditions({
        hashLockHex: "abcd",
        refundEpoch: REFUND_EPOCH,
        claimantPublicKeyHex: CLAIMANT_PK_HEX,
        refunderPublicKeyHex: REFUNDER_PK_HEX,
      })
    ).toThrow(/64 hex characters/);
  });

  it("rejects a hashLockHex containing non-hex characters", () => {
    expect(() =>
      htlcConditions({
        hashLockHex: "z".repeat(64),
        refundEpoch: REFUND_EPOCH,
        claimantPublicKeyHex: CLAIMANT_PK_HEX,
        refunderPublicKeyHex: REFUNDER_PK_HEX,
      })
    ).toThrow(/64 hex characters/);
  });
});

describe("accessRuleRequiringPublicKey", () => {
  it("matches the Rust reference implementation's JSON byte-for-byte", () => {
    expect(JSON.stringify(accessRuleRequiringPublicKey(CLAIMANT_PK_HEX))).toBe(
      '{"Restricted":{"Require":{"Require":{"NonFungibleAddress":{"resource_address":"resource_0100000000000000000000000000000000000000000000000000000000000000","id":{"U256":"5c7f0fec164142986ada18df7c0950d93827925ece06b0e6a1247b6a3a304c7c"}}}}}}'
    );
  });
});

// `buildHtlcSpendStatement` (OotleAccount.htlcClaim/htlcRefund's shared core) is exercised here
// against the real wasm build, the same way `crates/ootle_wasm/core/src/stealth/transfer.rs`'s
// own Rust unit tests verify `build_stealth_transfer_statement`: build a real condition tree, feed
// it a real script-path witness for one of its two leaves, and assert the resulting statement
// passes the engine's own `validateStealthTransfer` -- not just that it has the right shape. The
// mask/value fed in stand in for whatever a real caller would have (on-chain-decrypted for a
// claim, retained from funding time for a refund) -- `buildHtlcSpendStatement` doesn't care where
// they came from, only that they round-trip correctly into the statement it assembles.
//
// `covenant_claims` comes back non-empty here (confirmed live via this test, not assumed): a
// claim is generated per condition-root partition among the *spent* script-path inputs
// unconditionally, regardless of what atomic condition the revealed leaf actually used --
// separate from whether the *engine* ever reads it back at spend time (`covenant_balanced`,
// reached only via a `Covenant::BalancePreserved` leaf or a `TemplateFunction`, neither of which
// any HTLC leaf here is). The new output being a plain key-path output sharing no condition root
// with the spent input means the whole partition's value shows up "revealed" out of it.
describe("buildHtlcSpendStatement (real wasm crypto round trip)", () => {
  const NETWORK = 0x26; // Esmeralda-style network byte, matching htlc.test.ts's existing convention.
  const RESOURCE = "resource_0101010101010101010101010101010101010101010101010101010101010101";

  it("claim leaf: reveals the hashlock preimage and produces a statement the engine's own validator accepts", async () => {
    const claimant = generateKeypair();
    const refunder = generateKeypair();
    const claimantAddress = generateOotleAddress(claimant.public_key, claimant.public_key, NETWORK);

    const preimage = new TextEncoder().encode("htlcClaim test preimage");
    const hashLockHex = await sha256Hex(preimage);
    const conditions = htlcConditions({
      hashLockHex,
      refundEpoch: 999_999n,
      claimantPublicKeyHex: toHex(claimant.public_key),
      refunderPublicKeyHex: toHex(refunder.public_key),
    });

    // Any real scalar/amount works here -- this test targets buildHtlcSpendStatement's own
    // assembly logic, not the separate (already-tested-elsewhere) on-chain decrypt step that
    // would normally produce them for a real claim.
    const mask = toHex(generateKeypair().secret_key);
    const value = 12_345n;

    const statementJson = buildHtlcSpendStatement({
      network: NETWORK,
      conditions,
      leaf: conditions[0]!,
      data: preimage,
      mask,
      value,
      destinationWalletAddress: claimantAddress,
      resourceAddress: RESOURCE,
    });

    expect(() => validateStealthTransfer(statementJson, null)).not.toThrow();
    const statement = JSON.parse(statementJson);
    // A real covenant claim gets generated for this partition regardless of leaf type (see this
    // describe block's own doc comment) -- the whole value is "revealed" out of it, since the new
    // output is a plain key-path output sharing no condition root with the spent input.
    expect(statement.covenant_claims).toHaveLength(1);
    expect(statement.covenant_claims[0].revealed_amount).toBe(String(value));
    expect(statement.balance_proof).toBeTruthy();
    expect(statement.inputs_statement.inputs).toHaveLength(1);
    expect(statement.outputs_statement.outputs).toHaveLength(1);
  });

  it("refund leaf: reveals the timelock/key leaf with no witness data and still validates", async () => {
    const claimant = generateKeypair();
    const refunder = generateKeypair();
    const refunderAddress = generateOotleAddress(refunder.public_key, refunder.public_key, NETWORK);

    const preimage = new TextEncoder().encode("htlcRefund test preimage (never revealed on this path)");
    const hashLockHex = await sha256Hex(preimage);
    const conditions = htlcConditions({
      hashLockHex,
      refundEpoch: 1n, // already past -- irrelevant here, buildHtlcSpendStatement doesn't check epoch
      claimantPublicKeyHex: toHex(claimant.public_key),
      refunderPublicKeyHex: toHex(refunder.public_key),
    });

    const mask = toHex(generateKeypair().secret_key);
    const value = 500n;

    const statementJson = buildHtlcSpendStatement({
      network: NETWORK,
      conditions,
      leaf: conditions[1]!,
      data: new Uint8Array(0),
      mask,
      value,
      destinationWalletAddress: refunderAddress,
      resourceAddress: RESOURCE,
    });

    expect(() => validateStealthTransfer(statementJson, null)).not.toThrow();
    const statement = JSON.parse(statementJson);
    expect(statement.covenant_claims).toHaveLength(1);
    expect(statement.covenant_claims[0].revealed_amount).toBe(String(value));
    expect(statement.balance_proof).toBeTruthy();
  });
});
