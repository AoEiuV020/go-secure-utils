# go-secure-utils
Go语言加密工具库，支持纯Go调用和CGO接口

## 功能
- RSA 加密/解密
- 更多功能开发中...

## 使用方法

### Go语言中使用

```go
import (
    "fmt"
    cryptoutils "go-secure-utils"
)

func main() {
    // 生成RSA密钥对
    privateKey, publicKey, err := cryptoutils.GenerateRSAKeyPair(2048)
    if err != nil {
        panic(err)
    }
    
    // 加密数据
    message := []byte("需要加密的数据")
    ciphertext, err := cryptoutils.RSAEncryptWithPublicKey(message, publicKey)
    if err != nil {
        panic(err)
    }
    
    // 解密数据
    decrypted, err := cryptoutils.RSADecryptWithPrivateKey(ciphertext, privateKey)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("解密后的数据: %s\n", string(decrypted))
}
```

### C/C++中使用 (通过CGO)

编译共享库:

```bash
go build -buildmode=c-shared -o libgo_secure_utils.so
```

C语言示例:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "go_secure_utils.h"

int main() {
    // 生成RSA密钥对 (2048位)
    ByteArray keyPair = GenerateRSAKeyPair_C(2048);
    if (keyPair.error != NULL) {
        printf("错误: %s\n", keyPair.error);
        FreeByteArray_C(keyPair);
        return 1;
    }
    
    // 要加密的数据
    const char* message = "需要加密的数据";
    int messageLen = strlen(message);
    
    // 加密
    ByteArray encrypted = RSAEncrypt_C(keyPair.data, keyPair.length, 
                                      (byte*)message, messageLen);
    if (encrypted.error != NULL) {
        printf("加密错误: %s\n", encrypted.error);
        FreeByteArray_C(keyPair);
        FreeByteArray_C(encrypted);
        return 1;
    }
    
    // 解密
    ByteArray decrypted = RSADecrypt_C(keyPair.data, keyPair.length, 
                                      encrypted.data, encrypted.length);
    if (decrypted.error != NULL) {
        printf("解密错误: %s\n", decrypted.error);
        FreeByteArray_C(keyPair);
        FreeByteArray_C(encrypted);
        FreeByteArray_C(decrypted);
        return 1;
    }
    
    // 打印解密结果
    printf("解密后的数据: %.*s\n", decrypted.length, (char*)decrypted.data);
    
    // 释放内存
    FreeByteArray_C(keyPair);
    FreeByteArray_C(encrypted);
    FreeByteArray_C(decrypted);
    
    return 0;
}
```

## 编译

### 编译Go库
```bash
go build
```

### 编译共享库 (用于C/C++)
```bash
go build -buildmode=c-shared -o libgo_secure_utils.so
```
