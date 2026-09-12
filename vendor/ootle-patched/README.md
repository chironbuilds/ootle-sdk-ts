# Patched `@tari-project/ootle` (temporary, remove once upstream releases a fix)

Rebased 2026-08-20 onto `tari-project/ootle.ts`'s `main` branch at commit `1f2e8b2`
("feat(deps)!: upgrade the tari package set to the 0.39 protocol (#123)") — the same commit the
officially published `@tari-project/ootle@0.3.0` npm release was built from (confirmed: identical
`version` field, identical `covenant_claims` hardcoding when diffed against the published tarball).
This is a source rebase, not a re-derivation from scratch — the previous vendor copy (built
2026-08-06 from a since-unknown `ootle.ts` `main` commit `2bc5e93e`) carried one patch that no
longer applies and one that still does:

1. ~~One line changed in `packages/ootle/src/stealth/statements.ts` to always include
   `"covenant_claims":[]`~~ — **no longer needed**. Confirmed by grepping the real, published
   `@tari-project/ootle@0.3.0` dist: it already includes `"covenant_claims":[]` unconditionally.
   Upstream picked this up independently at some point after the original 2026-08-06 patch. This
   remains correct for every transfer this wallet builds today, including the HTLC claim/refund
   this rebase was done to unblock — `covenant_claims` is only ever read by
   `SpendScriptExecution::covenant_balanced`, reached only from a `Covenant::BalancePreserved`
   leaf or a `TemplateFunction` calling `SpendContext::covenant_balanced`; a revealed
   `HashLock`/`AfterEpoch`/`AccessRule` leaf (what every HTLC leaf in `src/lib/htlc.ts` is) never
   touches it (confirmed against `tari-project/tari-ootle#2431`'s own review discussion, where a
   maintainer caught an earlier PR description overclaiming this field was "required whenever a
   script-path input is spent").

2. `packages/ootle/src/stealth/transfer.ts`'s `StealthTransfer` builder still needs its two
   wallet-specific public methods, `toRevealedOutputAsBucket(amount, workspaceVarName)` and
   `andThen(instructions)` — **re-applied on top of the current source**, still absent upstream
   (confirmed: `grep -c toRevealedOutputAsBucket` on the fresh `ootle.ts` checkout before
   patching was 0). Upstream's `toRevealedOutput()` always auto-deposits the revealed change back
   into the source account — there's no way to get it as a bucket a caller can route elsewhere.
   The patched methods leave it on the workspace instead and let extra instructions run in the
   *same* signed transaction, consuming that bucket. This exists because a third-party dApp (or
   this wallet's own `withdrawStealthAndExecute`) cannot move Stealth-typed funds (e.g. XTR) into
   its own contract call at all otherwise — a plain `CallMethod withdraw` on a Stealth vault is
   not a standalone-valid instruction; moving Stealth funds anywhere always requires the native
   `StealthTransfer` instruction, paired with `WalletStealthAuthorizer` to sign it — which
   `account.execute()`/plain `TransactionBuilder` never invokes. See `withdrawStealthAndExecute`
   in `src/lib/wallet.ts` for the wallet-side method that uses this. Full method docs are inline
   in `transfer.ts` itself now (copied into this package's own `dist/index.d.ts`).

**Why this rebase happened now**: `@tari-project/ootle-wasm@0.39.0`/`0.39.1` are real, officially
published releases (not a moving branch HEAD) that finally include
`buildScriptPathWitness`/`buildStealthInputsStatementFromInputs`/`buildStealthTransferStatement`
(`tari-project/tari-ootle#2426`, `#2431`) — the primitives `OotleAccount.htlcClaim`/`htlcRefund`
need. Picking those up meant moving off the old `^0.37.0` pin, which meant rebuilding this vendor
copy against a source tree consistent with the new wasm version rather than continuing to build
against the stale 2026-08-06 base.

**Verified before landing**: `packages/ootle`'s own `tsc -b` and `vite build` both clean against
this patch; its non-wasm-dependent test files (240 tests across 17 files) pass unchanged. Its
wasm-dependent test files fail to even load in this build environment with
`TypeError: filename must be a file URL... Received 'file:///__vite-plugin-wasm-helper'` —
confirmed via `git stash` that this happens identically on the *unpatched* upstream source, so
it's a pre-existing `vite-plugin-wasm`/Node version environment issue, not something this patch
introduced or something this patch's correctness can be judged by. `tari-wallet`'s own test suite
(a different vitest config) is the real correctness check for this vendor copy — see this repo's
top-level `README.md` / commit history for that result.

To rebuild after further edits: clone `tari-project/ootle.ts` fresh, re-apply the
`toRevealedOutputAsBucket`/`andThen` patch to `packages/ootle/src/stealth/transfer.ts` (diff
against this vendored `dist/index.d.ts` if the patch itself is lost), then
`cd packages/ootle && pnpm install && npx tsc -b && npx vite build`, and copy `dist/index.js` +
`dist/index.d.ts` into this directory's `dist/`.

Delete `vendor/ootle-patched/` and the `pnpm-workspace.yaml` override once `@tari-project/ootle`
publishes a release that includes fix 2 (fix 1 is already moot) — re-verify shield/unshield *and*
the bucket-output/`andThen` capability (and, once built, HTLC claim/refund) against whatever
version ships, since fix 2 still has no upstream equivalent and would need to be proposed there.
