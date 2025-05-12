#ifndef GO_SECURE_UTILS_H
#define GO_SECURE_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>

// 基本字节数组结构
typedef struct {
    unsigned char* data;
    int length;
    char* error; // NULL表示无错误
} ByteArray;

// 密钥对结构
typedef struct {
    ByteArray publicKey;
    ByteArray privateKey;
    char* error; // NULL表示无错误
} RsaKeyPair;

// 字符串结果结构
typedef struct {
    char* data;
    char* error; // NULL表示无错误
} StringResult;

// 布尔结果结构
typedef struct {
    int success; // 1表示true，0表示false
    char* error; // NULL表示无错误
} BoolResult;

// ========= 旧的API函数，保持向后兼容 =========
// 这些函数仍然可用，但推荐使用新的Rsa前缀的函数
typedef unsigned char byte;

ByteArray goGenerateRSAKeyPair(int bits);
ByteArray goRSAEncrypt(byte* publicKey, int publicKeyLen, byte* data, int dataLen);
ByteArray goRSADecrypt(byte* privateKey, int privateKeyLen, byte* ciphertext, int ciphertextLen);

// ========= 新的RSA API函数 =========

// RSA密钥对生成与管理函数

// 生成RSA密钥对
RsaKeyPair goRsaGenKeyPair(int bits);

// 提取公钥
ByteArray goRsaExtractPublicKey(unsigned char* privateKey, int privateKeyLen);

// 获取Base64编码的公钥
StringResult goRsaGetPublicKeyBase64(unsigned char* publicKey, int publicKeyLen);

// 获取Base64编码的私钥
StringResult goRsaGetPrivateKeyBase64(unsigned char* privateKey, int privateKeyLen);

// RSA加密函数

// 使用公钥加密数据
ByteArray goRsaEncrypt(unsigned char* data, int dataLen, unsigned char* publicKey, int publicKeyLen);

// 使用公钥加密数据并返回Base64编码的结果
StringResult goRsaEncryptBase64(unsigned char* data, int dataLen, unsigned char* publicKey, int publicKeyLen);

// RSA解密函数

// 使用私钥解密数据
ByteArray goRsaDecrypt(unsigned char* encryptedData, int encryptedDataLen, unsigned char* privateKey, int privateKeyLen);

// 解密Base64编码的加密数据
ByteArray goRsaDecryptFromBase64(char* encryptedBase64, unsigned char* privateKey, int privateKeyLen);

// RSA签名函数

// 使用私钥对数据进行签名
ByteArray goRsaSign(unsigned char* data, int dataLen, unsigned char* privateKey, int privateKeyLen);

// 使用私钥对字符串数据进行签名并返回Base64编码的结果
StringResult goRsaSignBase64(char* data, unsigned char* privateKey, int privateKeyLen);

// 使用SHA1哈希算法和私钥对数据进行签名
ByteArray goRsaSignSha1(unsigned char* data, int dataLen, unsigned char* privateKey, int privateKeyLen);

// RSA签名验证函数

// 验证签名
BoolResult goRsaVerify(unsigned char* data, int dataLen, unsigned char* publicKey, int publicKeyLen, unsigned char* signature, int signatureLen);

// 验证Base64编码的签名
BoolResult goRsaVerifyFromBase64(char* data, unsigned char* publicKey, int publicKeyLen, char* signatureBase64);

// 使用SHA1哈希算法验证签名
BoolResult goRsaVerifySha1(unsigned char* data, int dataLen, unsigned char* publicKey, int publicKeyLen, unsigned char* signature, int signatureLen);

// ========= 内存管理函数 =========

// 释放ByteArray结构分配的内存
void goFreeByteArray(ByteArray result);

// 释放RsaKeyPair结构分配的内存
void goFreeRsaKeyPair(RsaKeyPair result);

// 释放StringResult结构分配的内存
void goFreeStringResult(StringResult result);

// 释放BoolResult结构分配的内存
void goFreeBoolResult(BoolResult result);

// 保持对Go内存的引用，防止被垃圾回收
void KeepAlive();

#ifdef __cplusplus
}
#endif

#endif // GO_SECURE_UTILS_H
