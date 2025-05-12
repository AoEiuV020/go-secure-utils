# go-secure-utils

Go语言高性能加密工具库，提供纯Go调用接口和CGO跨语言调用支持。

## 功能特性

- RSA 加密/解密
- 跨平台支持 (Windows/Linux/macOS/Android/iOS)
- 纯Go实现和CGO接口双重支持
- 更多加密功能开发中...

## 使用方法

### Go语言调用

直接导入包即可使用全部加密功能，

### C/C++调用 (通过CGO)

在`examples/c`目录中提供了完整的示例代码和编译脚本。

编译共享库:

```bash
make
```

C语言调用示例代码位于：[examples/c/rsa_example.c](examples/c/rsa_example.c)

## 编译指南

### 一键编译所有平台

```bash
make
```

### 按需编译特定平台

```bash
# 编译 Windows 平台库 (DLL)
make windows

# 编译 Linux 平台库 (.so)
make linux

# 编译 Android 平台库 (.so)
make android

# 编译 iOS 平台库 (.a)
make ios
```

## 示例程序

查看 `examples` 目录获取各种语言的使用示例：

### C语言示例
```bash
cd examples/c
build_with_mingw.bat
```

### 其他语言
陆续添加中...
