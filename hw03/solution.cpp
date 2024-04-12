#ifndef __PROGTEST__

#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

struct crypto_config {
    const char *m_crypto_function;
    std::unique_ptr<uint8_t[]> m_key;
    std::unique_ptr<uint8_t[]> m_IV;
    size_t m_key_len;
    size_t m_IV_len;
};

#endif /* _PROGTEST_ */

std::unique_ptr<uint8_t[]> generateRandomData(int size) {
    std::unique_ptr<uint8_t[]> ptr = std::make_unique<uint8_t[]>(size);
    RAND_bytes(ptr.get(), size);
    return ptr;
}

class CCipher {
public:
    explicit CCipher(int encrypt) : m_Ctx(EVP_CIPHER_CTX_new()), m_Encrypt(encrypt) {}

    ~CCipher() {
        EVP_CIPHER_CTX_reset(m_Ctx);
        EVP_CIPHER_CTX_free(m_Ctx);
    }

    bool validateConfig(crypto_config &config) {
        if (!m_Encrypt) {
            if ((size_t) EVP_CIPHER_CTX_key_length(m_Ctx) > config.m_key_len
                || (size_t) EVP_CIPHER_CTX_iv_length(m_Ctx) > config.m_IV_len
                || !config.m_key || (EVP_CIPHER_CTX_iv_length(m_Ctx) != 0 && !config.m_IV)) {
                return false;
            }
            return true;
        }
        if ((size_t) EVP_CIPHER_CTX_key_length(m_Ctx) > config.m_key_len || !config.m_key) {
            auto key = generateRandomData(EVP_CIPHER_CTX_key_length(m_Ctx));
            config.m_key.swap(key);
            config.m_key_len = EVP_CIPHER_CTX_key_length(m_Ctx);
        }
        if (EVP_CIPHER_CTX_iv_length(m_Ctx) != 0 &&
            ((size_t) EVP_CIPHER_CTX_iv_length(m_Ctx) > config.m_IV_len || !config.m_IV)) {
            auto iv = generateRandomData(EVP_CIPHER_CTX_iv_length(m_Ctx));
            config.m_IV.swap(iv);
            config.m_IV_len = EVP_CIPHER_CTX_iv_length(m_Ctx);
        }
        return true;
    }

    bool initContext(crypto_config &config) {
        return EVP_CipherInit_ex(m_Ctx, nullptr, nullptr, config.m_key.get(), config.m_IV.get(), m_Encrypt);
    }

    bool applyCipher(const unsigned char *block, unsigned char *cipheredBlock, int blockSize, int &cipherLength) {
        return EVP_CipherUpdate(m_Ctx, cipheredBlock, &cipherLength, block, blockSize);
    }

    operator evp_cipher_ctx_st *() {
        return m_Ctx;
    }

private:
    evp_cipher_ctx_st *m_Ctx;
    int m_Encrypt;
};
bool killThoseFiles(FILE * in, FILE * out) {
    fclose(in);
    fclose(out);
    return false;
}
bool process_data(const std::string &in_filename, const std::string &out_filename, crypto_config &config, int encrypt) {
    FILE *input_file, *output_file;
    input_file = fopen(in_filename.c_str(), "rb");
    output_file = fopen(out_filename.c_str(), "wb");
    auto type = EVP_get_cipherbyname(config.m_crypto_function);
    CCipher cipher(encrypt);
    if (!input_file
     || !output_file
     || !type
     || !cipher
     || !EVP_CipherInit_ex(cipher, type, nullptr, nullptr, nullptr, encrypt)
     || !cipher.validateConfig(config)
     || !cipher.initContext(config)
            ) {
        return false;
    }
    char header[18] = {};
    if (fread(header, sizeof(char), 18, input_file) < 18) return killThoseFiles(input_file, output_file);
    fwrite(header, sizeof(char), 18, output_file);
    if (ferror(input_file) || ferror(output_file)) return killThoseFiles(input_file, output_file);

    auto blockSize = EVP_CIPHER_block_size(type);
    if (blockSize < 0) return killThoseFiles(input_file, output_file);

    auto blockBuffer = (unsigned char *) malloc(blockSize * sizeof(unsigned char));
    auto cipheredText = (unsigned char *) malloc(2 * blockSize * sizeof(unsigned char));
    int cipherLength;
    while (!feof(input_file)) {
        auto size = fread(blockBuffer, sizeof(unsigned char), blockSize, input_file);
        if (ferror(input_file) || ferror(output_file)) {
            free(cipheredText);
            free(blockBuffer);
            return killThoseFiles(input_file, output_file);
        }
        if (!cipher.applyCipher(blockBuffer, cipheredText, (int) size, cipherLength)) {
            free(cipheredText);
            free(blockBuffer);
            return killThoseFiles(input_file, output_file);
        }
        fwrite(cipheredText, sizeof(unsigned char), cipherLength, output_file);
        if (ferror(output_file)) {
            free(cipheredText);
            free(blockBuffer);
            return killThoseFiles(input_file, output_file);
        }
    }

    if (!EVP_CipherFinal_ex(cipher, cipheredText, &cipherLength)) {
        free(cipheredText);
        free(blockBuffer);
        return killThoseFiles(input_file, output_file);
    }
    fwrite(cipheredText, sizeof(unsigned char), cipherLength, output_file);
    if (ferror(input_file) || ferror(output_file)) {
        free(cipheredText);
        free(blockBuffer);
        return killThoseFiles(input_file, output_file);
    }
    free(cipheredText);
    free(blockBuffer);

    fclose(input_file);
    fclose(output_file);
    return true;
}

bool encrypt_data(const std::string &in_filename, const std::string &out_filename, crypto_config &config) {
    return process_data(in_filename, out_filename, config, 1);
}

bool decrypt_data(const std::string &in_filename, const std::string &out_filename, crypto_config &config) {
    return process_data(in_filename, out_filename, config, 0);
}

#ifndef __PROGTEST__

bool compare_files(const char *name1, const char *name2) {
    std::ifstream f1(name1, std::ios_base::binary), f2(name2, std::ios_base::binary);
    if (!f1.is_open() || !f2.is_open()) {
        return false;
    }

    while (true) {
        auto a1 = f1.get();
        auto a2 = f2.get();
        if (a1 != a2) {
            return false;
        }

        if (a1 == EOF || a2 == EOF) break;
    }
    return true;
}

int main() {
    crypto_config config{nullptr, nullptr, nullptr, 0, 0};

    // ECB mode
    config.m_crypto_function = "AES-128-ECB";
    config.m_key = std::make_unique<uint8_t[]>(16);
    memset(config.m_key.get(), 0, 16);
    config.m_key_len = 16;

    assert(encrypt_data("homer-simpson.TGA", "out_file.TGA", config));
    assert(compare_files("out_file.TGA", "homer-simpson_enc_ecb.TGA"));

    assert(decrypt_data("homer-simpson_enc_ecb.TGA", "out_file.TGA", config));
    assert(compare_files("out_file.TGA", "homer-simpson.TGA"));

    assert(encrypt_data("UCM8.TGA", "out_file.TGA", config));
    assert(compare_files("out_file.TGA", "UCM8_enc_ecb.TGA"));

    assert(decrypt_data("UCM8_enc_ecb.TGA", "out_file.TGA", config));
    assert(compare_files("out_file.TGA", "UCM8.TGA"));

    assert(encrypt_data("image_1.TGA", "out_file.TGA", config));
    assert(compare_files("out_file.TGA", "ref_1_enc_ecb.TGA"));

    assert(encrypt_data("image_2.TGA", "out_file.TGA", config));
    assert(compare_files("out_file.TGA", "ref_2_enc_ecb.TGA"));

    assert(decrypt_data("image_3_enc_ecb.TGA", "out_file.TGA", config));
    assert(compare_files("out_file.TGA", "ref_3_dec_ecb.TGA"));

    assert(decrypt_data("image_4_enc_ecb.TGA", "out_file.TGA", config));
    assert(compare_files("out_file.TGA", "ref_4_dec_ecb.TGA"));
    assert(encrypt_data("in_5085845.bin", "out_file.TGA", config));
    assert(compare_files("out_file.TGA", "ref_5085845.bin"));

    //assert(!decrypt_data("in_5090949.bin", "out_file.TGA", config));
    // CBC mode
    config.m_crypto_function = "AES-128-CBC";
    config.m_IV = std::make_unique<uint8_t[]>(16);
    config.m_IV_len = 16;
    memset(config.m_IV.get(), 0, 16);

    assert(encrypt_data("UCM8.TGA", "out_file.TGA", config));
    assert(compare_files("out_file.TGA", "UCM8_enc_cbc.TGA"));

    assert(decrypt_data("UCM8_enc_cbc.TGA", "out_file.TGA", config));
    assert(compare_files("out_file.TGA", "UCM8.TGA"));

    assert(encrypt_data("homer-simpson.TGA", "out_file.TGA", config));
    assert(compare_files("out_file.TGA", "homer-simpson_enc_cbc.TGA"));

    assert(decrypt_data("homer-simpson_enc_cbc.TGA", "out_file.TGA", config));
    assert(compare_files("out_file.TGA", "homer-simpson.TGA"));

    assert(encrypt_data("image_1.TGA", "out_file.TGA", config));
    assert(compare_files("out_file.TGA", "ref_5_enc_cbc.TGA"));

    assert(encrypt_data("image_2.TGA", "out_file.TGA", config));
    assert(compare_files("out_file.TGA", "ref_6_enc_cbc.TGA"));

    assert(decrypt_data("image_7_enc_cbc.TGA", "out_file.TGA", config));
    assert(compare_files("out_file.TGA", "ref_7_dec_cbc.TGA"));

    assert(decrypt_data("image_8_enc_cbc.TGA", "out_file.TGA", config));
    assert(compare_files("out_file.TGA", "ref_8_dec_cbc.TGA"));


    return 0;
}

#endif /* _PROGTEST_ */
