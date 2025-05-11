#ifndef GO_SECURE_UTILS_H
#define GO_SECURE_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char byte;

typedef struct {
    byte* data;
    int length;
    char* error; // NULL if no error
} ByteArray;

// RSA functions
ByteArray GenerateRSAKeyPair_C(int bits);
ByteArray RSAEncrypt_C(byte* publicKey, int publicKeyLen, byte* data, int dataLen);
ByteArray RSADecrypt_C(byte* privateKey, int privateKeyLen, byte* ciphertext, int ciphertextLen);

// Memory management
void FreeByteArray_C(ByteArray array);

#ifdef __cplusplus
}
#endif

#endif // GO_SECURE_UTILS_H
