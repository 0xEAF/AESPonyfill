#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
#endif

#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/gcm.h"
#include "cryptopp/ccm.h"
#include "cryptopp/xts.h"
#include "cryptopp/filters.h"
#include <cstdint>
#include <cstddef>
#include <cstring>

using namespace CryptoPP;
extern "C" {
    #ifdef __EMSCRIPTEN__
    EMSCRIPTEN_KEEPALIVE
    #endif
    int aes_encrypt(const uint8_t* plaintext, size_t plaintext_len,
                    const uint8_t* key, size_t key_len_bits,
                    const char* mode,
                    const uint8_t* iv_or_tweak,
                    const uint8_t* aad, size_t aad_len,
                    uint8_t* out,
                    uint8_t* tag, size_t tag_len) {
        try {
            size_t key_len_bytes = key_len_bits / 8;

            if (key_len_bits != 128 && key_len_bits != 192 && key_len_bits != 256) {
                return -2;
            }

            if (strcmp(mode, "GCM") == 0) {
                if (!iv_or_tweak || !tag || tag_len == 0) return -3;
                CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
                enc.SetKeyWithIV(key, key_len_bytes, iv_or_tweak);

                // Use ArraySink directly to output buffer
                CryptoPP::ArraySink cs(out, plaintext_len + CryptoPP::AES::BLOCKSIZE);
                CryptoPP::AuthenticatedEncryptionFilter aef(enc, &cs, false, tag_len);

                if (aad && aad_len > 0) {
                    aef.ChannelPut(CryptoPP::AAD_CHANNEL, aad, aad_len);
                    aef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
                }

                aef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, plaintext, plaintext_len);
                aef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

                // Get the tag after processing
                aef.Get(tag, tag_len);
                
                return cs.TotalPutLength();
            }

            // For all other modes, use the original sink approach
            CryptoPP::ArraySink cs(out, plaintext_len + CryptoPP::AES::BLOCKSIZE);

            if (strcmp(mode, "ECB") == 0) {
                CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc;
                enc.SetKey(key, key_len_bytes);

                CryptoPP::StreamTransformationFilter stf(enc, &cs, CryptoPP::StreamTransformationFilter::PKCS_PADDING);
                stf.Put(plaintext, plaintext_len);
                stf.MessageEnd();
            }
            else if (strcmp(mode, "CBC") == 0) {
                if (!iv_or_tweak) return -3;
                CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
                enc.SetKeyWithIV(key, key_len_bytes, iv_or_tweak);

                CryptoPP::StreamTransformationFilter stf(enc, &cs, CryptoPP::StreamTransformationFilter::PKCS_PADDING);
                stf.Put(plaintext, plaintext_len);
                stf.MessageEnd();
            }
            else if (strcmp(mode, "CFB") == 0) {
                if (!iv_or_tweak) return -3;
                CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption enc;
                enc.SetKeyWithIV(key, key_len_bytes, iv_or_tweak);

                CryptoPP::StreamTransformationFilter stf(enc, &cs);
                stf.Put(plaintext, plaintext_len);
                stf.MessageEnd();
            }
            else if (strcmp(mode, "OFB") == 0) {
                if (!iv_or_tweak) return -3;
                CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption enc;
                enc.SetKeyWithIV(key, key_len_bytes, iv_or_tweak);

                CryptoPP::StreamTransformationFilter stf(enc, &cs);
                stf.Put(plaintext, plaintext_len);
                stf.MessageEnd();
            }
            else if (strcmp(mode, "CTR") == 0) {
                if (!iv_or_tweak) return -3;
                CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
                enc.SetKeyWithIV(key, key_len_bytes, iv_or_tweak);

                CryptoPP::StreamTransformationFilter stf(enc, &cs);
                stf.Put(plaintext, plaintext_len);
                stf.MessageEnd();
            }
            else if (strcmp(mode, "CTS") == 0) {
                if (!iv_or_tweak) return -3;
                CryptoPP::CBC_CTS_Mode<CryptoPP::AES>::Encryption enc;
                enc.SetKeyWithIV(key, key_len_bytes, iv_or_tweak);

                CryptoPP::StreamTransformationFilter stf(enc, &cs);
                stf.Put(plaintext, plaintext_len);
                stf.MessageEnd();
            }
            else if (strcmp(mode, "XTS") == 0) {
                if (!iv_or_tweak) return -3;
                size_t half_key_len = key_len_bytes / 2;
                if (key_len_bytes % 2 != 0) return -5;

                CryptoPP::XTS_Mode<CryptoPP::AES>::Encryption enc;
                enc.SetKeyWithIV(key, half_key_len * 2, iv_or_tweak);

                enc.ProcessData(out, plaintext, plaintext_len);
                return plaintext_len;
            }
            else if (strcmp(mode, "CCM") == 0) {
                if (!iv_or_tweak || !tag || tag_len == 0) return -3;
                CryptoPP::CCM<CryptoPP::AES, 16>::Encryption enc;
                enc.SetKeyWithIV(key, key_len_bytes, iv_or_tweak, 13);

                enc.SpecifyDataLengths(aad_len, plaintext_len, tag_len);

                CryptoPP::AuthenticatedEncryptionFilter aef(enc,
                    new CryptoPP::ArraySink(cs),
                    false, tag_len);

                if (aad && aad_len > 0) {
                    aef.ChannelPut(CryptoPP::AAD_CHANNEL, aad, aad_len);
                    aef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
                }

                aef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, plaintext, plaintext_len);
                aef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

                aef.Get(tag, tag_len);
            }
            else {
                return -4;
            }

            return cs.TotalPutLength();
        } catch (...) {
            return -1;
        }
    }

    #ifdef __EMSCRIPTEN__
    EMSCRIPTEN_KEEPALIVE
    #endif
    int aes_decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                    const uint8_t* key, size_t key_len_bits,
                    const char* mode,
                    const uint8_t* iv_or_tweak,
                    const uint8_t* aad, size_t aad_len,
                    uint8_t* out,
                    const uint8_t* tag, size_t tag_len) {
        try {
            size_t key_len_bytes = key_len_bits / 8;

            if (key_len_bits != 128 && key_len_bits != 192 && key_len_bits != 256 && key_len_bits != 512) {
                return -2;
            }

            if (strcmp(mode, "GCM") == 0) {
                if (!iv_or_tweak || !tag || tag_len == 0) return -3;
                CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
                dec.SetKeyWithIV(key, key_len_bytes, iv_or_tweak);

                CryptoPP::ArraySink cs(out, ciphertext_len + CryptoPP::AES::BLOCKSIZE);
                CryptoPP::AuthenticatedDecryptionFilter adf(dec, &cs, 
                    CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION, tag_len);

                if (aad && aad_len > 0) {
                    adf.ChannelPut(CryptoPP::AAD_CHANNEL, aad, aad_len);
                    adf.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
                }

                adf.ChannelPut(CryptoPP::DEFAULT_CHANNEL, ciphertext, ciphertext_len);
                adf.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

                // Set the tag for verification
                adf.Put(tag, tag_len);

                if (!adf.GetLastResult()) return -6;
                
                return cs.TotalPutLength();
            }

            // For all other modes, use original approach
            CryptoPP::ArraySink cs(out, ciphertext_len + CryptoPP::AES::BLOCKSIZE);

            if (strcmp(mode, "ECB") == 0) {
                CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption dec;
                dec.SetKey(key, key_len_bytes);

                CryptoPP::StreamTransformationFilter stf(dec, &cs, CryptoPP::StreamTransformationFilter::PKCS_PADDING);
                stf.Put(ciphertext, ciphertext_len);
                stf.MessageEnd();
            }
            else if (strcmp(mode, "CBC") == 0) {
                if (!iv_or_tweak) return -3;
                CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
                dec.SetKeyWithIV(key, key_len_bytes, iv_or_tweak);

                CryptoPP::StreamTransformationFilter stf(dec, &cs, CryptoPP::StreamTransformationFilter::PKCS_PADDING);
                stf.Put(ciphertext, ciphertext_len);
                stf.MessageEnd();
            }
            else if (strcmp(mode, "CFB") == 0) {
                if (!iv_or_tweak) return -3;
                CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption dec;
                dec.SetKeyWithIV(key, key_len_bytes, iv_or_tweak);

                CryptoPP::StreamTransformationFilter stf(dec, &cs);
                stf.Put(ciphertext, ciphertext_len);
                stf.MessageEnd();
            }
            else if (strcmp(mode, "OFB") == 0) {
                if (!iv_or_tweak) return -3;
                CryptoPP::OFB_Mode<CryptoPP::AES>::Decryption dec;
                dec.SetKeyWithIV(key, key_len_bytes, iv_or_tweak);

                CryptoPP::StreamTransformationFilter stf(dec, &cs);
                stf.Put(ciphertext, ciphertext_len);
                stf.MessageEnd();
            }
            else if (strcmp(mode, "CTR") == 0) {
                if (!iv_or_tweak) return -3;
                CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
                dec.SetKeyWithIV(key, key_len_bytes, iv_or_tweak);

                CryptoPP::StreamTransformationFilter stf(dec, &cs);
                stf.Put(ciphertext, ciphertext_len);
                stf.MessageEnd();
            }
            else if (strcmp(mode, "CTS") == 0) {
                if (!iv_or_tweak) return -3;
                CryptoPP::CBC_CTS_Mode<CryptoPP::AES>::Decryption dec;
                dec.SetKeyWithIV(key, key_len_bytes, iv_or_tweak);

                CryptoPP::StreamTransformationFilter stf(dec, &cs);
                stf.Put(ciphertext, ciphertext_len);
                stf.MessageEnd();
            }
            else if (strcmp(mode, "XTS") == 0) {
                if (!iv_or_tweak) return -3;
                size_t half_key_len = key_len_bytes / 2;
                if (key_len_bytes % 2 != 0) return -5;

                CryptoPP::XTS_Mode<CryptoPP::AES>::Decryption dec;
                dec.SetKeyWithIV(key, half_key_len * 2, iv_or_tweak);

                dec.ProcessData(out, ciphertext, ciphertext_len);
                return ciphertext_len;
            }
            else if (strcmp(mode, "CCM") == 0) {
                if (!iv_or_tweak || !tag || tag_len == 0) return -3;
                CryptoPP::CCM<CryptoPP::AES, 16>::Decryption dec;
                dec.SetKeyWithIV(key, key_len_bytes, iv_or_tweak, 13);

                dec.SpecifyDataLengths(aad_len, ciphertext_len, tag_len);

                CryptoPP::AuthenticatedDecryptionFilter adf(dec,
                    new CryptoPP::ArraySink(cs),
                    CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
                    tag_len);

                if (aad && aad_len > 0) {
                    adf.ChannelPut(CryptoPP::AAD_CHANNEL, aad, aad_len);
                    adf.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
                }

                adf.ChannelPut(CryptoPP::DEFAULT_CHANNEL, ciphertext, ciphertext_len);
                adf.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

                if (!adf.GetLastResult()) return -6;
            }
            else {
                return -4;
            }

            return cs.TotalPutLength();
        } catch (...) {
            return -1;
        }
    }
}
