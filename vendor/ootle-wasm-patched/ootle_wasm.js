/* @ts-self-types="./ootle_wasm.d.ts" */

import * as wasm from "./ootle_wasm_bg.wasm";
import { __wbg_set_wasm } from "./ootle_wasm_bg.js";
__wbg_set_wasm(wasm);
wasm.__wbindgen_start();
export {
    DecryptedOutputResult, KeypairResult, OotlePublicKey, OotleSecretKey, ParsedOotleAddress, SchnorrSignatureResult, StealthOutputsResult, addTransactionSigner, aggregateInputMasks, borEncodeTransaction, buildScriptPathWitness, buildStealthInputsStatement, buildStealthInputsStatementFromInputs, buildStealthTransferStatement, createConfidentialWithdrawProofLiteral, createStealthOutputWitness, decryptElgamalViewableBalance, encryptedDataDhKdfAead, generateElgamalViewableBalanceProof, generateExtendedBulletProof, generateKeypair, generateOotleAddress, generateOotleSecretKey, generateStealthBalanceProofSignature, generateStealthOutputsStatement, hashUnsignedTransaction, on_start, ootlePublicKeyFromSecretKey, parseOotleAddress, publicKeyFromSecretKey, schnorrSign, sealTransaction, stealthDhSecret, unblindOutput, validateBalanceProofSignature, validateStealthTransfer
} from "./ootle_wasm_bg.js";
