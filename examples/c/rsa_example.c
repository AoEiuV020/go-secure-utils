#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../go_secure_utils.h"

int main() {
    // 生成RSA密钥对 (2048位)
    RsaKeyPair keyPair = goRsaGenKeyPair(2048);
    if (keyPair.error != NULL) {
        printf("错误: %s\n", keyPair.error);
        return 1;
    }
    
    // 要加密的数据
    const char* message = "需要加密的数据";
    int messageLen = strlen(message);
      // 使用公钥加密
    ByteArray encrypted = goRsaEncrypt((byte*)message, messageLen, keyPair.publicKey.data, keyPair.publicKey.length);
    if (encrypted.error != NULL) {
        printf("加密错误: %s\n", encrypted.error);
        return 1;
    }
    
    // 使用私钥解密
    ByteArray decrypted = goRsaDecrypt(encrypted.data, encrypted.length, keyPair.privateKey.data, keyPair.privateKey.length);
    if (decrypted.error != NULL) {
        printf("解密错误: %s\n", decrypted.error);
        return 1;
    }
    
    // 打印解密结果
    printf("解密后的数据: %.*s\n", decrypted.length, (char*)decrypted.data);
    
    // 释放内存
    return 0;
}
