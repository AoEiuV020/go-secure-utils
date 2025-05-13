# go-secure-utils

![版本](https://img.shields.io/badge/版本-1.0.0-blue.svg)
![Go版本](https://img.shields.io/badge/Go-1.24+-brightgreen.svg)
![许可证](https://img.shields.io/badge/许可证-MIT-green.svg)

Go语言高性能跨平台加密工具库，提供纯Go调用接口、CGO跨语言调用支持和WebAssembly支持，让您在任何平台安全地处理加密需求。

## 功能特性

- **RSA 加密/解密**：支持多种模式的RSA加解密操作
- **签名与验证**：提供SHA-1和SHA-256数字签名算法
- **跨平台支持**：完整覆盖主流平台 (Windows/Linux/macOS/Android/iOS/Web)
- **多种接口**：
  - 纯Go实现（高性能原生支持）
  - CGO接口（C/C++/其他语言集成）
  - WebAssembly接口（浏览器和JavaScript环境）
- **完整示例**：提供多种语言和平台的集成示例
- **持续更新**：更多加密算法和功能正在开发中...

## 使用方法

### Go语言调用

直接导入包即可使用全部加密功能：

```go
import (
    "go-secure-utils/pkg/crypto/rsa"
)

// 生成RSA密钥对
keyPair, _ := rsa.GenKeyPair(2048)

// 加密数据
encrypted, _ := rsa.EncryptBase64([]byte("要加密的数据"), keyPair.PublicKey)

// 解密数据
decrypted, _ := rsa.DecryptFromBase64(encrypted, keyPair.PrivateKey)
```

### C/C++调用 (通过CGO)

在`examples/c`目录中提供了完整的示例代码和编译脚本。

编译共享库:

```bash
make
```

C语言调用示例代码位于：[examples/c/rsa_example.c](examples/c/rsa_example.c)

## 编译指南

### 一键编译所有平台

一行命令即可完成所有平台的编译：

```bash
make
```

### 按需编译特定平台

根据您的需求选择性编译特定平台的库：

```bash
# 编译 Windows 平台库 (DLL)
make windows

# 编译 Linux 平台库 (.so)
make linux

# 编译 Android 平台库 (.so)
make android

# 编译 iOS 平台库 (.a)
make ios

# 编译 WebAssembly 模块 (.wasm)
make web
```

## 示例程序

提供了多种语言和平台的完整示例代码，您可以查看 `examples` 目录获取详细信息：

### C语言示例

使用MinGW（Windows）:
```bash
cd examples/c
build_with_mingw.bat
```

使用GCC（Linux/macOS）:
```bash
cd examples/c
./build.sh
```

### Flutter/Dart示例

库已发布为Flutter插件，支持Android、iOS、macOS、Windows、Linux和Web平台：

```dart
import 'package:go_secure_utils/go_secure_utils.dart';

// 生成RSA密钥对
final keyPair = await RSA.genKeyPair(keySize: 2048);

// 加密数据
final encrypted = await RSA.encryptStringToBase64("Hello, world!", keyPair.publicKey);

// 解密数据
final decrypted = await RSA.decryptStringFromBase64(encrypted, keyPair.privateKey);

// 签名数据
final signature = await RSA.signBase64("数据内容", keyPair.privateKey);

// 验证签名
final isValid = await RSA.verifyFromBase64("数据内容", keyPair.publicKey, signature);
```

完整的Flutter示例应用位于 [examples/flutter](examples/flutter)。

### 其他语言

更多语言示例正在开发中，欢迎贡献您的实现！

## 贡献指南

欢迎通过以下方式为项目做出贡献：
1. Fork 项目仓库
2. 创建您的特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交您的更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 打开一个 Pull Request

## 许可证

本项目采用 MIT 许可证 - 详情请参阅 [LICENSE](LICENSE) 文件。
