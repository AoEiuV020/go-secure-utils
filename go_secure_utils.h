#ifndef GO_SECURE_UTILS_H
#define GO_SECURE_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>

typedef uint8_t byte;

// 基本字节数组结构
typedef struct {
    byte* data;
    int length;
    char* error; // NULL if no error
} ByteArray;

// 密钥对结构
typedef struct {
    ByteArray publicKey;
    ByteArray privateKey;
    char* error; // NULL if no error
} RsaKeyPair;

// 字符串结果结构
typedef struct {
    char* data;
    char* error; // NULL if no error
} StringResult;

// 布尔结果结构
typedef struct {
    int success; // 1 for true, 0 for false
    char* error; // NULL if no error
} BoolResult;

// ========= RSA API函数 =========

// RSA密钥对生成与管理函数

// 生成RSA密钥对
RsaKeyPair goRsaGenKeyPair(int bits);

// 提取公钥
ByteArray goRsaExtractPublicKey(byte* privateKey, int privateKeyLen);

// 获取Base64编码的公钥
StringResult goRsaGetPublicKeyBase64(byte* publicKey, int publicKeyLen);

// 获取Base64编码的私钥
StringResult goRsaGetPrivateKeyBase64(byte* privateKey, int privateKeyLen);

// RSA加密函数

// 使用公钥加密数据
ByteArray goRsaEncrypt(byte* data, int dataLen, byte* publicKey, int publicKeyLen);

// 使用公钥加密数据并返回Base64编码的结果
StringResult goRsaEncryptBase64(byte* data, int dataLen, byte* publicKey, int publicKeyLen);

// RSA解密函数

// 使用私钥解密数据
ByteArray goRsaDecrypt(byte* encryptedData, int encryptedDataLen, byte* privateKey, int privateKeyLen);

// 解密Base64编码的加密数据
ByteArray goRsaDecryptFromBase64(char* encryptedBase64, byte* privateKey, int privateKeyLen);

// RSA签名函数

// 使用私钥对数据进行签名
ByteArray goRsaSign(byte* data, int dataLen, byte* privateKey, int privateKeyLen);

// 使用私钥对字符串数据进行签名并返回Base64编码的结果
StringResult goRsaSignBase64(char* data, byte* privateKey, int privateKeyLen);

// 使用SHA1哈希算法和私钥对数据进行签名
ByteArray goRsaSignSha1(byte* data, int dataLen, byte* privateKey, int privateKeyLen);

// RSA签名验证函数

// 验证签名
BoolResult goRsaVerify(byte* data, int dataLen, byte* publicKey, int publicKeyLen, byte* signature, int signatureLen);

// 验证Base64编码的签名
BoolResult goRsaVerifyFromBase64(char* data, byte* publicKey, int publicKeyLen, char* signatureBase64);

// 使用SHA1哈希算法验证签名
BoolResult goRsaVerifySha1(byte* data, int dataLen, byte* publicKey, int publicKeyLen, byte* signature, int signatureLen);

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
