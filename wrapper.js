(function () {
    const wasmSupported = (() => {  // from: https://stackoverflow.com/a/47880734
        try {
            if (typeof WebAssembly === "object"
                && typeof WebAssembly.instantiate === "function") {
                const module = new WebAssembly.Module(Uint8Array.of(0x0, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00));
                if (module instanceof WebAssembly.Module)
                    return new WebAssembly.Instance(module) instanceof WebAssembly.Instance;
            }
        } catch (e) {}
        return false;
    })();

    let Module = null;
    if (wasmSupported) {
        try {
            Module = (function () {
                /*PLACEHOLDER-DONOTREMOVE-BUILD:WASMJS*/
                return AESPonyfill();
            })();
        } catch (e) {
            Module = null;
        }
    }

    if (!Module) {
        console.warn("WARNING: WebAssembly not supported, falling back to ASM.JS (this may be slower)");

        try {
            Module = (async function () {
                /*PLACEHOLDER-DONOTREMOVE-BUILD:ASMJS*/
                return AESPonyfill();
            })();
        } catch (e) {
            console.error("Failed to load AESPonyfill WASM or ASMJS module!");
            throw e;
        }
    }

    AESPonyfill = class {
        constructor(passphrase, options = {}) {
            if (window?.crypto?.subtle) {
                if (options?.ignoreSubtleCryptoWarns !== true) {
                    console.warn("WARNING: SubtleCrypto API is available, consider using it over this ponyfill.");
                }
            }

            this.Module = Module;
            this.mode = options.mode || "CBC";
            this.keyLen = options.keyLen || 256;
            this.tagLen = options.tagLen || 16;

            let keyBytes;
            if (typeof passphrase === "string") {
                if (passphrase.length !== this.keyLen / 4) {
                    throw new Error(`Key must be a ${this.keyLen}-bit hex string`);
                }

                keyBytes = Uint8Array.from(passphrase.match(/.{2}/g).map(b => parseInt(b, 16)));
            } else if (passphrase instanceof Uint8Array) {
                if (passphrase.length !== this.keyLen / 8) {
                    throw new Error(`Key must be a ${this.keyLen}-bit Uint8Array`);
                }
                
                keyBytes = passphrase;
            } else {
                throw new Error("Passphrase must be a hex string or Uint8Array");
            }

            this.key = keyBytes;
        }

        async _init() {
            if (typeof this.Module._malloc !== 'function') {
                this.Module = await this.Module;
                this.keyPtr = this.Module._malloc(this.key.length);
                this.HEAPU8 = this.Module.HEAPU8;
                this.HEAPU8.set(this.key, this.keyPtr);
            }
        }

        async encrypt(plaintextBytes, options = {}) {
            await this._init();

            // Accept either Uint8Array or string (for backward compatibility)
            if (typeof plaintextBytes === "string") {
                const enc = new TextEncoder();
                plaintextBytes = enc.encode(plaintextBytes);
            } else if (!(plaintextBytes instanceof Uint8Array)) {
                throw new Error("Plaintext must be a Uint8Array or string");
            }

            if (!options.iv) {
                throw new Error("IV must be provided in options.iv");
            }
            const iv = options.iv;
            const aad = options.aad || new Uint8Array(0);

            const plaintextPtr = this.Module._malloc(plaintextBytes.length);
            const ivPtr = this.Module._malloc(iv.length);
            const aadPtr = this.Module._malloc(aad.length);
            const outPtr = this.Module._malloc(plaintextBytes.length + 64); 
            const tagPtr = this.Module._malloc(this.tagLen);

            this.HEAPU8.set(plaintextBytes, plaintextPtr);
            this.HEAPU8.set(iv, ivPtr);
            if (aad.length > 0) this.HEAPU8.set(aad, aadPtr);

            const modePtr = this.Module._malloc(this.mode.length + 1);
            this.Module.stringToUTF8(this.mode, modePtr, this.mode.length + 1);

            const outLen = this.Module._aes_encrypt(
                plaintextPtr, plaintextBytes.length,
                this.keyPtr, this.keyLen,
                modePtr,
                ivPtr,
                aadPtr, aad.length,
                outPtr,
                tagPtr, this.tagLen
            );

            if (outLen < 0) {
                this._freeAll([plaintextPtr, ivPtr, aadPtr, outPtr, tagPtr, modePtr]);
                throw new Error(`Encryption failed with code ${outLen}`);
            }

            const ciphertext = this.HEAPU8.slice(outPtr, outPtr + outLen);
            const tag = this.HEAPU8.slice(tagPtr, tagPtr + this.tagLen);

            this._freeAll([plaintextPtr, ivPtr, aadPtr, outPtr, tagPtr, modePtr]);

            return { ciphertext, tag };
        }

        async decrypt(ciphertext, iv, tag, aad = new Uint8Array(0)) {
            if (!iv) {
                throw new Error("IV must be provided");
            }

            await this._init();

            const ciphertextPtr = this.Module._malloc(ciphertext.length);
            const ivPtr = this.Module._malloc(iv.length);
            const tagPtr = this.Module._malloc(tag.length);
            const aadPtr = this.Module._malloc(aad.length);
            const outPtr = this.Module._malloc(ciphertext.length + 64);

            this.HEAPU8.set(ciphertext, ciphertextPtr);
            this.HEAPU8.set(iv, ivPtr);
            this.HEAPU8.set(tag, tagPtr);
            if (aad.length > 0) this.HEAPU8.set(aad, aadPtr);

            const modePtr = this.Module._malloc(this.mode.length + 1);
            this.Module.stringToUTF8(this.mode, modePtr, this.mode.length + 1);

            const outLen = this.Module._aes_decrypt(
                ciphertextPtr, ciphertext.length,
                this.keyPtr, this.keyLen,
                modePtr,
                ivPtr,
                aadPtr, aad.length,
                outPtr,
                tagPtr, tag.length
            );

            if (outLen < 0) {
                this._freeAll([ciphertextPtr, ivPtr, tagPtr, aadPtr, outPtr, modePtr]);
                throw new Error(`Decryption failed with code ${outLen}`);
            }

            const plaintextBytes = this.HEAPU8.slice(outPtr, outPtr + outLen);

            this._freeAll([ciphertextPtr, ivPtr, tagPtr, aadPtr, outPtr, modePtr]);
            
            // Return raw bytes instead of decoded string
            return plaintextBytes;
        }

        _freeAll(ptrs) {
            for (let ptr of ptrs) {
                if (ptr) this.Module._free(ptr);
            }
        }

        free() {
            if (this.keyPtr) {
                this.Module._free(this.keyPtr);
                this.keyPtr = null;
            }
        }
    }

    if (typeof module !== "undefined" && module.exports) {
        module.exports = AESPonyfill;
    } else {
        window.AESPonyfill = AESPonyfill;
    }
})();