#ifndef __PROGTEST__
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

#endif /* __PROGTEST__ */
using byteString = std::basic_string<uint8_t>;
int checkBits(int bits, const byteString & byteStr) {
    if (!bits && (byteStr[0] & (1 << 7)) == 0) return 1;
    for (size_t i = 0; i < byteStr.size(); ++i) {
        if (bits >= 8) {
            if (byteStr[i] == 0) bits -= 8;
            else return 0;
        } else {
            for (int j = 0; j < bits; ++j) if ((byteStr[i] & (1 << (7-j))) != 0) return 0;
            break;
        }
    }
    return 1;
}
class CContext {
public:
    explicit CContext(const evp_md_st * type) {
        m_Ctx = EVP_MD_CTX_new();
        assert(EVP_DigestInit_ex(m_Ctx, type, nullptr));
    }
    ~CContext() {
        EVP_MD_CTX_free(m_Ctx);
    }
    operator EVP_MD_CTX * () {
        return m_Ctx;
    }
private:
    EVP_MD_CTX * m_Ctx;
};
byteString hash (const byteString & message, const evp_md_st * type) {
    byteString h(EVP_MD_size(type), 0);
    CContext ctx(type);
    assert(EVP_DigestUpdate(ctx, message.c_str(), message.size()));
    unsigned int length;
    assert(EVP_DigestFinal_ex(ctx, h.data(), &length));
    return h;
}
std::string bytesToHex (const byteString & byteStr) {
    std::string result(2*byteStr.size(),0);
    for (size_t i = 0; i < byteStr.size(); ++i) snprintf(result.data()+2*i, 3,"%02x",byteStr[i]);
    return result;
}
byteString generateByteString () {
    byteString res(512,0);
    RAND_bytes(res.data(), 512);
    return res;
}
int findHashEx (int bits, char ** m, char ** h, const char * hashFunction) {
    byteString mess;
    OpenSSL_add_all_digests();
    auto type = EVP_get_digestbyname(hashFunction);
    if (bits < 0 || bits > EVP_MD_size(type)) return 0;
    auto randomMessage = generateByteString();
    auto hashedRandomMessage = hash(randomMessage, type);
    while (!checkBits(bits, hashedRandomMessage)) {
        randomMessage = hashedRandomMessage;
        hashedRandomMessage = hash(randomMessage, type);
        if (hashedRandomMessage == randomMessage) randomMessage = generateByteString();
    }
    *m = strdup(bytesToHex(randomMessage).c_str());
    *h = strdup(bytesToHex(hashedRandomMessage).c_str());
    return 1;
}
int findHash (int bits, char ** message, char ** hash) {
    return findHashEx(bits, message, hash, "sha512");
}
#ifndef __PROGTEST__
int main () {
    char * message, * hash;
    findHashEx(20,&message, &hash, "sha512");
    return EXIT_SUCCESS;
}
#endif /* __PROGTEST__ */
