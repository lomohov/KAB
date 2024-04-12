#ifndef __PROGTEST__

#include <cstdio>
#include <iostream>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>

#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace std;

#endif /* __PROGTEST__ */

class CKey {
public:
    explicit CKey(const char *, bool);

    ~CKey();

    evp_pkey_st *operator*();

private:
    evp_pkey_st *m_PubKey;
};

CKey::CKey(const char *keyFile, bool publicKey) {
    FILE *fp = fopen(keyFile, "rb");
    if (!fp) throw std::invalid_argument("Wrong keyFile");
    if (publicKey) {
        m_PubKey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    } else {
        m_PubKey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    }
    fclose(fp);
    if (!m_PubKey) throw std::invalid_argument("Invalid key");
}

CKey::~CKey() {
    EVP_PKEY_free(m_PubKey);
}

evp_pkey_st *CKey::operator*() {
    return m_PubKey;
}

class CHybridCipher {
public:
    explicit CHybridCipher(bool seal);

    ~CHybridCipher();

    evp_cipher_ctx_st *operator*();

    bool init(std::ifstream &, std::ofstream &, const char *, const char *, const char *);

    bool cipherUpdate(unsigned char *, int &, const unsigned char *, int);

    bool cipherFinal(unsigned char *, int &);

    bool m_Seal;
private:
    bool sealInit(std::ofstream &, const char *, evp_pkey_st *);

    bool openInit(std::ifstream &, evp_pkey_st *);

    EVP_CIPHER_CTX *m_Ctx;
};

CHybridCipher::CHybridCipher(bool seal) : m_Seal(seal), m_Ctx(EVP_CIPHER_CTX_new()) {
    if (!m_Ctx) throw std::invalid_argument("Failed to initialize cipher context");
}

CHybridCipher::~CHybridCipher() {
    EVP_CIPHER_CTX_free(m_Ctx);
}

evp_cipher_ctx_st *CHybridCipher::operator*() {
    return m_Ctx;
}

bool CHybridCipher::init(std::ifstream &in, std::ofstream &out, const char *symmetricCipher, const char *publicKeyFile,
                         const char *privateKeyFile) {
    if (m_Seal) {
        CKey pubKey(publicKeyFile, m_Seal);
        if (!sealInit(out, symmetricCipher, *pubKey)) return false;
    } else {
        CKey privateKey(privateKeyFile, m_Seal);
        if (!openInit(in, *privateKey)) return false;
    }
    return true;
}

bool CHybridCipher::cipherUpdate(unsigned char *outBuffer, int &outLen, const unsigned char *buffer, int length) {
    return EVP_CipherUpdate(m_Ctx, outBuffer, &outLen, buffer, length);
}

bool CHybridCipher::cipherFinal(unsigned char *outBuffer, int &outLen) {
    return EVP_CipherFinal(m_Ctx, outBuffer, &outLen);
}

bool CHybridCipher::sealInit(std::ofstream &out, const char *cipher, evp_pkey_st *pubKey) {
    auto type = EVP_get_cipherbyname(cipher);
    if (!type) return false;
    int NID = EVP_CIPHER_nid(type);
    if (NID == NID_undef) return false;
    int ivLen = EVP_CIPHER_iv_length(type);
    if (!out.write(reinterpret_cast<const char *>(&NID), 4)) return false;
    std::vector<unsigned char> encryptedKey(EVP_PKEY_size(pubKey)), iv(ivLen);
    int length;
    unsigned char *keyPtr = &encryptedKey[0];
    return EVP_SealInit(m_Ctx, type, &keyPtr, &length, iv.data(), &pubKey, 1)
           && out.write(reinterpret_cast<const char *>(&length), 4)
           && out.write(reinterpret_cast<const char *>(encryptedKey.data()), length)
           && out.write(reinterpret_cast<const char *>(iv.data()), ivLen);
}

bool CHybridCipher::openInit(std::ifstream &encryptedFile, evp_pkey_st *privateKey) {
    int NID = 0, keyLen = 0;
    if (!encryptedFile.read(reinterpret_cast<char *>(&NID), 4)) return false;
    auto type = EVP_get_cipherbynid(NID);
    if (!type || !encryptedFile.read(reinterpret_cast<char *>(&keyLen), 4) ||
        keyLen != EVP_PKEY_size(privateKey))
        return false;
    int ivLen = EVP_CIPHER_iv_length(type);
    std::vector<unsigned char> encryptedKey(keyLen), iv(ivLen);
    return encryptedFile.read(reinterpret_cast<char *>(encryptedKey.data()), keyLen)
           && encryptedFile.read(reinterpret_cast<char *>(iv.data()), ivLen)
           && EVP_OpenInit(m_Ctx, type, encryptedKey.data(), keyLen, iv.data(), privateKey);
}

void cleanup(const char *file) {
    if (!file) return;
    std::remove(file);
}

constexpr int bufferLen = 4096;

bool cipher(const char *inFile, const char *outFile, bool seal, const char *privateKeyFile = nullptr,
            const char *publicKeyFile = nullptr, const char *symmetricCipher = nullptr) {
    std::ifstream in(inFile, ios_base::binary);
    std::ofstream out(outFile, ios_base::binary);
    if (!in || !out) return false;
    CHybridCipher hybridCipher(seal);
    if (!hybridCipher.init(in, out, symmetricCipher, publicKeyFile, privateKeyFile)) return false;
    int outLength = 0;
    std::vector<unsigned char> inBuf(bufferLen);
    std::vector<unsigned char> outBuf(inBuf.size() + EVP_CIPHER_CTX_block_size(*hybridCipher));

    while (in) {
        in.read(reinterpret_cast<char *>(&inBuf[0]), (int) inBuf.size());
        int inLen = (int) in.gcount();
        if (!hybridCipher.cipherUpdate(&outBuf[0], outLength, &inBuf[0], inLen)) return false;
        if (!out.write(reinterpret_cast<const char *>(&outBuf[0]), outLength)) return false;
    }
    return hybridCipher.cipherFinal(&outBuf[0], outLength)
           && out.write(reinterpret_cast<const char *>(&outBuf[0]), outLength);
}

bool tryCipher(const char *inFile, const char *outFile, bool seal, const char *privateKeyFile = nullptr,
               const char *publicKeyFile = nullptr, const char *symmetricCipher = nullptr) {
    try {
        if (!cipher(inFile, outFile, seal, privateKeyFile, publicKeyFile, symmetricCipher)) {
            return false;
        }
    } catch (const std::invalid_argument &e) {
        return false;
    }
    return true;
}

bool seal(const char *inFile, const char *outFile, const char *publicKeyFile, const char *symmetricCipher) {
    if (!inFile || !outFile || !publicKeyFile || !symmetricCipher
        || !tryCipher(inFile, outFile, true, nullptr, publicKeyFile, symmetricCipher)) {
        cleanup(outFile);
        return false;
    }
    return true;
}

bool open(const char *inFile, const char *outFile, const char *privateKeyFile) {
    if (!inFile || !outFile || !privateKeyFile || !tryCipher(inFile, outFile, false, privateKeyFile)) {
        cleanup(outFile);
        return false;
    }
    return true;
}

#ifndef __PROGTEST__

int main() {
    assert(seal("fileToEncrypt", "sealed.bin", "PublicKey.pem", "aes-128-cbc"));
    assert(open("sealed.bin", "openedFileToEncrypt", "PrivateKey.pem"));

    assert(open("sealed_sample.bin", "opened_sample.txt", "PrivateKey.pem"));
    assert(!open("sealed_sample.bin", "opened_sample1.txt", "corrupted.pem"));

//    assert(!open("sealed.bin", "non_removable", "PrivateKey.pem"));

    return 0;
}

#endif /* __PROGTEST__ */

