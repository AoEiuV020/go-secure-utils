import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'go_secure_utils_bindings_generated.dart';
import 'go_secure_utils_models.dart';

/// 动态库的名称
const String _libName = 'go_secure_utils';

/// 加载本地动态库
final DynamicLibrary _dylib = () {
  if (Platform.isMacOS || Platform.isIOS) {
    return DynamicLibrary.open('$_libName.framework/$_libName');
  }
  if (Platform.isAndroid || Platform.isLinux) {
    return DynamicLibrary.open('lib$_libName.so');
  }
  if (Platform.isWindows) {
    return DynamicLibrary.open('$_libName.dll');
  }
  throw UnsupportedError('不支持的平台: ${Platform.operatingSystem}');
}();

/// 本地函数绑定实例
final GoSecureUtilsBindings _bindings = GoSecureUtilsBindings(_dylib);

/// 将Pointer<Uint8>和长度转换为Uint8List
Uint8List _byteArrayToUint8List(Pointer<Uint8> data, int length) {
  final buffer = data.asTypedList(length);
  return Uint8List.fromList(buffer);
}

/// 检查并处理C字符串错误
void _checkError(Pointer<Char> error) {
  if (error != nullptr) {
    final errorMessage = error.cast<Utf8>().toDartString();
    throw GoSecureUtilsException(errorMessage);
  }
}

/// 将Dart字符串转换为Pointer<Char>
Pointer<Char> _stringToNative(String str) {
  return str.toNativeUtf8().cast<Char>();
}

/// 将Uint8List转换为Pointer<Uint8>
Pointer<Uint8> _uint8ListToPointer(Uint8List data) {
  final ptr = calloc<Uint8>(data.length);
  final buffer = ptr.asTypedList(data.length);
  buffer.setAll(0, data);
  return ptr;
}

/// 从ByteArray结构体获取数据并释放内存
Uint8List _processAndFreeByteArray(ByteArray result) {
  try {
    _checkError(result.error);
    final data = _byteArrayToUint8List(result.data, result.length);
    return Uint8List.fromList(data); // 创建副本
  } finally {
    _bindings.goFreeByteArray(result);
  }
}

/// 从StringResult结构体获取字符串并释放内存
String _processAndFreeStringResult(StringResult result) {
  try {
    _checkError(result.error);
    return result.data.cast<Utf8>().toDartString();
  } finally {
    _bindings.goFreeStringResult(result);
  }
}

/// 从BoolResult结构体获取布尔值并释放内存
bool _processAndFreeBoolResult(BoolResult result) {
  try {
    _checkError(result.error);
    return result.success != 0;
  } finally {
    _bindings.goFreeBoolResult(result);
  }
}

/// 处理并释放RsaKeyPair结构体内存
RsaKeyPairData _processAndFreeRsaKeyPair(RsaKeyPair result) {
  try {
    _checkError(result.error);

    final publicKey = _byteArrayToUint8List(
      result.publicKey.data,
      result.publicKey.length,
    );

    final privateKey = _byteArrayToUint8List(
      result.privateKey.data,
      result.privateKey.length,
    );

    return RsaKeyPairData(
      Uint8List.fromList(publicKey),
      Uint8List.fromList(privateKey),
    );
  } finally {
    _bindings.goFreeRsaKeyPair(result);
  }
}

/// 生成RSA密钥对
/// [bits] 密钥长度，通常为2048或4096
RsaKeyPairData genKeyPair(int bits) {
  final result = _bindings.goRsaGenKeyPair(bits);
  return _processAndFreeRsaKeyPair(result);
}

/// 从私钥中提取公钥
/// [privateKey] 私钥数据
Uint8List extractPublicKey(Uint8List privateKey) {
  final privateKeyPtr = _uint8ListToPointer(privateKey);
  try {
    final result = _bindings.goRsaExtractPublicKey(
      privateKeyPtr,
      privateKey.length,
    );
    return _processAndFreeByteArray(result);
  } finally {
    calloc.free(privateKeyPtr);
  }
}

/// 获取Base64编码的公钥
/// [publicKey] 公钥数据
String getPublicKeyBase64(Uint8List publicKey) {
  final publicKeyPtr = _uint8ListToPointer(publicKey);
  try {
    final result = _bindings.goRsaGetPublicKeyBase64(
      publicKeyPtr,
      publicKey.length,
    );
    return _processAndFreeStringResult(result);
  } finally {
    calloc.free(publicKeyPtr);
  }
}

/// 获取Base64编码的私钥
/// [privateKey] 私钥数据
String getPrivateKeyBase64(Uint8List privateKey) {
  final privateKeyPtr = _uint8ListToPointer(privateKey);
  try {
    final result = _bindings.goRsaGetPrivateKeyBase64(
      privateKeyPtr,
      privateKey.length,
    );
    return _processAndFreeStringResult(result);
  } finally {
    calloc.free(privateKeyPtr);
  }
}

/// 使用公钥加密数据
/// [data] 要加密的数据
/// [publicKey] 公钥
Uint8List encrypt(Uint8List data, Uint8List publicKey) {
  final dataPtr = _uint8ListToPointer(data);
  final publicKeyPtr = _uint8ListToPointer(publicKey);
  try {
    final result = _bindings.goRsaEncrypt(
      dataPtr,
      data.length,
      publicKeyPtr,
      publicKey.length,
    );
    return _processAndFreeByteArray(result);
  } finally {
    calloc.free(dataPtr);
    calloc.free(publicKeyPtr);
  }
}

/// 使用公钥加密数据并返回Base64编码的结果
/// [data] 要加密的数据
/// [publicKey] 公钥
String encryptToBase64(Uint8List data, Uint8List publicKey) {
  final dataPtr = _uint8ListToPointer(data);
  final publicKeyPtr = _uint8ListToPointer(publicKey);
  try {
    final result = _bindings.goRsaEncryptBase64(
      dataPtr,
      data.length,
      publicKeyPtr,
      publicKey.length,
    );
    return _processAndFreeStringResult(result);
  } finally {
    calloc.free(dataPtr);
    calloc.free(publicKeyPtr);
  }
}

/// 使用私钥解密数据
/// [encryptedData] 加密后的数据
/// [privateKey] 私钥
Uint8List decrypt(Uint8List encryptedData, Uint8List privateKey) {
  final encryptedDataPtr = _uint8ListToPointer(encryptedData);
  final privateKeyPtr = _uint8ListToPointer(privateKey);
  try {
    final result = _bindings.goRsaDecrypt(
      encryptedDataPtr,
      encryptedData.length,
      privateKeyPtr,
      privateKey.length,
    );
    return _processAndFreeByteArray(result);
  } finally {
    calloc.free(encryptedDataPtr);
    calloc.free(privateKeyPtr);
  }
}

/// 解密Base64编码的加密数据
/// [encryptedBase64] Base64编码的加密数据
/// [privateKey] 私钥
Uint8List decryptFromBase64(String encryptedBase64, Uint8List privateKey) {
  final encryptedBase64Ptr = _stringToNative(encryptedBase64);
  final privateKeyPtr = _uint8ListToPointer(privateKey);
  try {
    final result = _bindings.goRsaDecryptFromBase64(
      encryptedBase64Ptr,
      privateKeyPtr,
      privateKey.length,
    );
    return _processAndFreeByteArray(result);
  } finally {
    calloc.free(encryptedBase64Ptr);
    calloc.free(privateKeyPtr);
  }
}

/// 使用私钥对数据进行签名
/// [data] 要签名的数据
/// [privateKey] 私钥
Uint8List sign(Uint8List data, Uint8List privateKey) {
  final dataPtr = _uint8ListToPointer(data);
  final privateKeyPtr = _uint8ListToPointer(privateKey);
  try {
    final result = _bindings.goRsaSign(
      dataPtr,
      data.length,
      privateKeyPtr,
      privateKey.length,
    );
    return _processAndFreeByteArray(result);
  } finally {
    calloc.free(dataPtr);
    calloc.free(privateKeyPtr);
  }
}

/// 使用私钥对字符串数据进行签名并返回Base64编码的结果
/// [data] 要签名的字符串数据
/// [privateKey] 私钥
String signBase64(String data, Uint8List privateKey) {
  final dataPtr = _stringToNative(data);
  final privateKeyPtr = _uint8ListToPointer(privateKey);
  try {
    final result = _bindings.goRsaSignBase64(
      dataPtr,
      privateKeyPtr,
      privateKey.length,
    );
    return _processAndFreeStringResult(result);
  } finally {
    calloc.free(dataPtr);
    calloc.free(privateKeyPtr);
  }
}

/// 使用SHA1哈希算法和私钥对数据进行签名
/// [data] 要签名的数据
/// [privateKey] 私钥
Uint8List signSha1(Uint8List data, Uint8List privateKey) {
  final dataPtr = _uint8ListToPointer(data);
  final privateKeyPtr = _uint8ListToPointer(privateKey);
  try {
    final result = _bindings.goRsaSignSha1(
      dataPtr,
      data.length,
      privateKeyPtr,
      privateKey.length,
    );
    return _processAndFreeByteArray(result);
  } finally {
    calloc.free(dataPtr);
    calloc.free(privateKeyPtr);
  }
}

/// 验证签名
/// [data] 原始数据
/// [publicKey] 公钥
/// [signature] 签名数据
bool verify(Uint8List data, Uint8List publicKey, Uint8List signature) {
  final dataPtr = _uint8ListToPointer(data);
  final publicKeyPtr = _uint8ListToPointer(publicKey);
  final signaturePtr = _uint8ListToPointer(signature);
  try {
    final result = _bindings.goRsaVerify(
      dataPtr,
      data.length,
      publicKeyPtr,
      publicKey.length,
      signaturePtr,
      signature.length,
    );
    return _processAndFreeBoolResult(result);
  } finally {
    calloc.free(dataPtr);
    calloc.free(publicKeyPtr);
    calloc.free(signaturePtr);
  }
}

/// 验证Base64编码的签名
/// [data] 原始字符串数据
/// [publicKey] 公钥
/// [signatureBase64] Base64编码的签名
bool verifyFromBase64(
  String data,
  Uint8List publicKey,
  String signatureBase64,
) {
  final dataPtr = _stringToNative(data);
  final publicKeyPtr = _uint8ListToPointer(publicKey);
  final signatureBase64Ptr = _stringToNative(signatureBase64);
  try {
    final result = _bindings.goRsaVerifyFromBase64(
      dataPtr,
      publicKeyPtr,
      publicKey.length,
      signatureBase64Ptr,
    );
    return _processAndFreeBoolResult(result);
  } finally {
    calloc.free(dataPtr);
    calloc.free(publicKeyPtr);
    calloc.free(signatureBase64Ptr);
  }
}

/// 使用SHA1哈希算法验证签名
/// [data] 原始数据
/// [publicKey] 公钥
/// [signature] 签名数据
bool verifySha1(Uint8List data, Uint8List publicKey, Uint8List signature) {
  final dataPtr = _uint8ListToPointer(data);
  final publicKeyPtr = _uint8ListToPointer(publicKey);
  final signaturePtr = _uint8ListToPointer(signature);
  try {
    final result = _bindings.goRsaVerifySha1(
      dataPtr,
      data.length,
      publicKeyPtr,
      publicKey.length,
      signaturePtr,
      signature.length,
    );
    return _processAndFreeBoolResult(result);
  } finally {
    calloc.free(dataPtr);
    calloc.free(publicKeyPtr);
    calloc.free(signaturePtr);
  }
}

/// 保持对Go内存的引用，防止被垃圾回收
void keepAlive() {
  _bindings.KeepAlive();
}
