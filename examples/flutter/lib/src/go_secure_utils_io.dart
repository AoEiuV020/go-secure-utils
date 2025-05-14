import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'go_secure_utils_bindings_generated.dart';
import 'go_secure_utils_models.dart';
import 'isolate_helper.dart';

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
Future<RsaKeyPairData> genKeyPair(int bits) async {
  final helper = IsolateHelper<int, RsaKeyPairData>((input) {
    final result = _bindings.goRsaGenKeyPair(input);
    return _processAndFreeRsaKeyPair(result);
  });
  
  return helper.execute(bits);
}

/// 从私钥中提取公钥
/// [privateKey] 私钥数据
Future<Uint8List> extractPublicKey(Uint8List privateKey) async {
  final helper = IsolateHelper<Uint8List, Uint8List>((input) {
    final privateKeyPtr = _uint8ListToPointer(input);
    try {
      final result = _bindings.goRsaExtractPublicKey(
        privateKeyPtr,
        input.length,
      );
      return _processAndFreeByteArray(result);
    } finally {
      calloc.free(privateKeyPtr);
    }
  });
  
  return helper.execute(privateKey);
}

/// 获取Base64编码的公钥
/// [publicKey] 公钥数据
Future<String> getPublicKeyBase64(Uint8List publicKey) async {
  final helper = IsolateHelper<Uint8List, String>((input) {
    final publicKeyPtr = _uint8ListToPointer(input);
    try {
      final result = _bindings.goRsaGetPublicKeyBase64(
        publicKeyPtr,
        input.length,
      );
      return _processAndFreeStringResult(result);
    } finally {
      calloc.free(publicKeyPtr);
    }
  });
  
  return helper.execute(publicKey);
}

/// 获取Base64编码的私钥
/// [privateKey] 私钥数据
Future<String> getPrivateKeyBase64(Uint8List privateKey) async {
  final helper = IsolateHelper<Uint8List, String>((input) {
    final privateKeyPtr = _uint8ListToPointer(input);
    try {
      final result = _bindings.goRsaGetPrivateKeyBase64(
        privateKeyPtr,
        input.length,
      );
      return _processAndFreeStringResult(result);
    } finally {
      calloc.free(privateKeyPtr);
    }
  });
  
  return helper.execute(privateKey);
}

/// 使用公钥加密数据参数
class EncryptParams {
  final Uint8List data;
  final Uint8List publicKey;
  
  EncryptParams(this.data, this.publicKey);
}

/// 使用公钥加密数据
/// [data] 要加密的数据
/// [publicKey] 公钥
Future<Uint8List> encrypt(Uint8List data, Uint8List publicKey) async {
  final helper = IsolateHelper<EncryptParams, Uint8List>((input) {
    final dataPtr = _uint8ListToPointer(input.data);
    final publicKeyPtr = _uint8ListToPointer(input.publicKey);
    try {
      final result = _bindings.goRsaEncrypt(
        dataPtr,
        input.data.length,
        publicKeyPtr,
        input.publicKey.length,
      );
      return _processAndFreeByteArray(result);
    } finally {
      calloc.free(dataPtr);
      calloc.free(publicKeyPtr);
    }
  });
  
  return helper.execute(EncryptParams(data, publicKey));
}

/// 使用公钥加密数据并返回Base64编码的结果
/// [data] 要加密的数据
/// [publicKey] 公钥
Future<String> encryptToBase64(Uint8List data, Uint8List publicKey) async {
  final helper = IsolateHelper<EncryptParams, String>((input) {
    final dataPtr = _uint8ListToPointer(input.data);
    final publicKeyPtr = _uint8ListToPointer(input.publicKey);
    try {
      final result = _bindings.goRsaEncryptBase64(
        dataPtr,
        input.data.length,
        publicKeyPtr,
        input.publicKey.length,
      );
      return _processAndFreeStringResult(result);
    } finally {
      calloc.free(dataPtr);
      calloc.free(publicKeyPtr);
    }
  });
  
  return helper.execute(EncryptParams(data, publicKey));
}

/// 使用私钥解密数据参数
class DecryptParams {
  final Uint8List encryptedData;
  final Uint8List privateKey;
  
  DecryptParams(this.encryptedData, this.privateKey);
}

/// 使用私钥解密数据
/// [encryptedData] 加密后的数据
/// [privateKey] 私钥
Future<Uint8List> decrypt(Uint8List encryptedData, Uint8List privateKey) async {
  final helper = IsolateHelper<DecryptParams, Uint8List>((input) {
    final encryptedDataPtr = _uint8ListToPointer(input.encryptedData);
    final privateKeyPtr = _uint8ListToPointer(input.privateKey);
    try {
      final result = _bindings.goRsaDecrypt(
        encryptedDataPtr,
        input.encryptedData.length,
        privateKeyPtr,
        input.privateKey.length,
      );
      return _processAndFreeByteArray(result);
    } finally {
      calloc.free(encryptedDataPtr);
      calloc.free(privateKeyPtr);
    }
  });
  
  return helper.execute(DecryptParams(encryptedData, privateKey));
}

/// 从Base64解密参数
class DecryptFromBase64Params {
  final String encryptedBase64;
  final Uint8List privateKey;
  
  DecryptFromBase64Params(this.encryptedBase64, this.privateKey);
}

/// 解密Base64编码的加密数据
/// [encryptedBase64] Base64编码的加密数据
/// [privateKey] 私钥
Future<Uint8List> decryptFromBase64(String encryptedBase64, Uint8List privateKey) async {
  final helper = IsolateHelper<DecryptFromBase64Params, Uint8List>((input) {
    final encryptedBase64Ptr = _stringToNative(input.encryptedBase64);
    final privateKeyPtr = _uint8ListToPointer(input.privateKey);
    try {
      final result = _bindings.goRsaDecryptFromBase64(
        encryptedBase64Ptr,
        privateKeyPtr,
        input.privateKey.length,
      );
      return _processAndFreeByteArray(result);
    } finally {
      calloc.free(encryptedBase64Ptr);
      calloc.free(privateKeyPtr);
    }
  });
  
  return helper.execute(DecryptFromBase64Params(encryptedBase64, privateKey));
}

/// 签名参数
class SignParams {
  final Uint8List data;
  final Uint8List privateKey;
  
  SignParams(this.data, this.privateKey);
}

/// 使用私钥对数据进行签名
/// [data] 要签名的数据
/// [privateKey] 私钥
Future<Uint8List> sign(Uint8List data, Uint8List privateKey) async {
  final helper = IsolateHelper<SignParams, Uint8List>((input) {
    final dataPtr = _uint8ListToPointer(input.data);
    final privateKeyPtr = _uint8ListToPointer(input.privateKey);
    try {
      final result = _bindings.goRsaSign(
        dataPtr,
        input.data.length,
        privateKeyPtr,
        input.privateKey.length,
      );
      return _processAndFreeByteArray(result);
    } finally {
      calloc.free(dataPtr);
      calloc.free(privateKeyPtr);
    }
  });
  
  return helper.execute(SignParams(data, privateKey));
}

/// 字符串签名参数
class SignStringParams {
  final String data;
  final Uint8List privateKey;
  
  SignStringParams(this.data, this.privateKey);
}

/// 使用私钥对字符串数据进行签名并返回Base64编码的结果
/// [data] 要签名的字符串数据
/// [privateKey] 私钥
Future<String> signBase64(String data, Uint8List privateKey) async {
  final helper = IsolateHelper<SignStringParams, String>((input) {
    final dataPtr = _stringToNative(input.data);
    final privateKeyPtr = _uint8ListToPointer(input.privateKey);
    try {
      final result = _bindings.goRsaSignBase64(
        dataPtr,
        privateKeyPtr,
        input.privateKey.length,
      );
      return _processAndFreeStringResult(result);
    } finally {
      calloc.free(dataPtr);
      calloc.free(privateKeyPtr);
    }
  });
  
  return helper.execute(SignStringParams(data, privateKey));
}

/// 使用SHA1哈希算法和私钥对数据进行签名
/// [data] 要签名的数据
/// [privateKey] 私钥
Future<Uint8List> signSha1(Uint8List data, Uint8List privateKey) async {
  final helper = IsolateHelper<SignParams, Uint8List>((input) {
    final dataPtr = _uint8ListToPointer(input.data);
    final privateKeyPtr = _uint8ListToPointer(input.privateKey);
    try {
      final result = _bindings.goRsaSignSha1(
        dataPtr,
        input.data.length,
        privateKeyPtr,
        input.privateKey.length,
      );
      return _processAndFreeByteArray(result);
    } finally {
      calloc.free(dataPtr);
      calloc.free(privateKeyPtr);
    }
  });
  
  return helper.execute(SignParams(data, privateKey));
}

/// 验证参数
class VerifyParams {
  final Uint8List data;
  final Uint8List publicKey;
  final Uint8List signature;
  
  VerifyParams(this.data, this.publicKey, this.signature);
}

/// 验证签名
/// [data] 原始数据
/// [publicKey] 公钥
/// [signature] 签名数据
Future<bool> verify(Uint8List data, Uint8List publicKey, Uint8List signature) async {
  final helper = IsolateHelper<VerifyParams, bool>((input) {
    final dataPtr = _uint8ListToPointer(input.data);
    final publicKeyPtr = _uint8ListToPointer(input.publicKey);
    final signaturePtr = _uint8ListToPointer(input.signature);
    try {
      final result = _bindings.goRsaVerify(
        dataPtr,
        input.data.length,
        publicKeyPtr,
        input.publicKey.length,
        signaturePtr,
        input.signature.length,
      );
      return _processAndFreeBoolResult(result);
    } finally {
      calloc.free(dataPtr);
      calloc.free(publicKeyPtr);
      calloc.free(signaturePtr);
    }
  });
  
  return helper.execute(VerifyParams(data, publicKey, signature));
}

/// 字符串验证参数
class VerifyFromBase64Params {
  final String data;
  final Uint8List publicKey;
  final String signatureBase64;
  
  VerifyFromBase64Params(this.data, this.publicKey, this.signatureBase64);
}

/// 验证Base64编码的签名
/// [data] 原始字符串数据
/// [publicKey] 公钥
/// [signatureBase64] Base64编码的签名
Future<bool> verifyFromBase64(
  String data,
  Uint8List publicKey,
  String signatureBase64,
) async {
  final helper = IsolateHelper<VerifyFromBase64Params, bool>((input) {
    final dataPtr = _stringToNative(input.data);
    final publicKeyPtr = _uint8ListToPointer(input.publicKey);
    final signatureBase64Ptr = _stringToNative(input.signatureBase64);
    try {
      final result = _bindings.goRsaVerifyFromBase64(
        dataPtr,
        publicKeyPtr,
        input.publicKey.length,
        signatureBase64Ptr,
      );
      return _processAndFreeBoolResult(result);
    } finally {
      calloc.free(dataPtr);
      calloc.free(publicKeyPtr);
      calloc.free(signatureBase64Ptr);
    }
  });
  
  return helper.execute(VerifyFromBase64Params(data, publicKey, signatureBase64));
}

/// 使用SHA1哈希算法验证签名
/// [data] 原始数据
/// [publicKey] 公钥
/// [signature] 签名数据
Future<bool> verifySha1(Uint8List data, Uint8List publicKey, Uint8List signature) async {
  final helper = IsolateHelper<VerifyParams, bool>((input) {
    final dataPtr = _uint8ListToPointer(input.data);
    final publicKeyPtr = _uint8ListToPointer(input.publicKey);
    final signaturePtr = _uint8ListToPointer(input.signature);
    try {
      final result = _bindings.goRsaVerifySha1(
        dataPtr,
        input.data.length,
        publicKeyPtr,
        input.publicKey.length,
        signaturePtr,
        input.signature.length,
      );
      return _processAndFreeBoolResult(result);
    } finally {
      calloc.free(dataPtr);
      calloc.free(publicKeyPtr);
      calloc.free(signaturePtr);
    }
  });
  
  return helper.execute(VerifyParams(data, publicKey, signature));
}

/// 保持对Go内存的引用，防止被垃圾回收
void keepAlive() {
  _bindings.KeepAlive();
}
