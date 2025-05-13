// ignore_for_file: avoid_web_libraries_in_flutter

import 'dart:async';
import 'dart:js_interop';
import 'dart:typed_data';
import 'dart:convert';

import 'go_web.dart';
import 'go_secure_utils_models.dart';

/// 确保WASM已经就绪
Future<void> _ensureWasmReady() async {
  if (!isWasmReady()) {
    await waitForWasmReady();
  }
}

/// 处理RSA操作过程中的异常
T _handleRsaException<T>(T Function() operation) {
  try {
    return operation();
  } catch (e) {
    throw GoSecureUtilsException(e.toString());
  }
}

/// 生成RSA密钥对
/// [keySize] 密钥大小，通常为2048或4096
Future<RsaKeyPairData> genKeyPair(int keySize) async {
  await _ensureWasmReady();

  return _handleRsaException(() async {
    final response = await jsWindow.goRsaGenKeyPair(keySize).toDart;

    return processJSResponse<RsaKeyPairData>(response, (data) {
      final publicKeyBase64 = data.publicKey;
      final privateKeyBase64 = data.privateKey;

      if (publicKeyBase64 == null || privateKeyBase64 == null) {
        throw GoSecureUtilsException('生成密钥对失败：响应数据不完整');
      }

      final publicKey = base64Decode(publicKeyBase64);
      final privateKey = base64Decode(privateKeyBase64);

      return RsaKeyPairData(publicKey, privateKey);
    });
  });
}

/// 从私钥中提取公钥
/// [privateKey] 私钥数据
Future<Uint8List> extractPublicKey(Uint8List privateKey) async {
  await _ensureWasmReady();

  return _handleRsaException(() async {
    final jsPrivateKey = uint8ListToJS(privateKey);
    final response = await jsWindow.goRsaExtractPublicKey(jsPrivateKey).toDart;

    return processJSResponse<Uint8List>(response, (data) {
      final publicKey = data.publicKeyArray;
      if (publicKey == null) {
        throw GoSecureUtilsException('提取公钥失败：响应数据不完整');
      }

      return jsUint8ArrayToDart(publicKey as JSAny);
    });
  });
}

/// 获取Base64编码的公钥
/// [publicKey] 公钥数据
String getPublicKeyBase64(Uint8List publicKey) {
  return base64Encode(publicKey);
}

/// 获取Base64编码的私钥
/// [privateKey] 私钥数据
String getPrivateKeyBase64(Uint8List privateKey) {
  return base64Encode(privateKey);
}

/// 使用公钥加密数据
/// [data] 要加密的数据
/// [publicKey] 公钥
Future<Uint8List> encrypt(Uint8List data, Uint8List publicKey) async {
  await _ensureWasmReady();

  return _handleRsaException(() async {
    final jsData = uint8ListToJS(data);
    final jsPublicKey = uint8ListToJS(publicKey);

    final response = await jsWindow.goRsaEncrypt(jsData, jsPublicKey).toDart;
    return processUint8ArrayResult(response, 'encrypted');
  });
}

/// 使用公钥加密数据并返回Base64编码的结果
/// [data] 要加密的数据
/// [publicKey] 公钥
Future<String> encryptToBase64(Uint8List data, Uint8List publicKey) async {
  await _ensureWasmReady();

  return _handleRsaException(() async {
    final jsData = uint8ListToJS(data);
    final jsPublicKey = uint8ListToJS(publicKey);

    final response =
        await jsWindow.goRsaEncryptBase64(jsData, jsPublicKey).toDart;

    return processJSResponse<String>(response, (data) {
      final encrypted = data.encrypted;
      if (encrypted == null) {
        throw GoSecureUtilsException('加密失败：响应数据不完整');
      }

      return encrypted.toString();
    });
  });
}

/// 使用私钥解密数据
/// [encryptedData] 加密后的数据
/// [privateKey] 私钥
Future<Uint8List> decrypt(Uint8List encryptedData, Uint8List privateKey) async {
  await _ensureWasmReady();

  return _handleRsaException(() async {
    final jsEncryptedData = uint8ListToJS(encryptedData);
    final jsPrivateKey = uint8ListToJS(privateKey);

    final response =
        await jsWindow.goRsaDecrypt(jsEncryptedData, jsPrivateKey).toDart;
    return processUint8ArrayResult(response, 'decrypted');
  });
}

/// 解密Base64编码的加密数据
/// [encryptedBase64] Base64编码的加密数据
/// [privateKey] 私钥
Future<Uint8List> decryptFromBase64(
  String encryptedBase64,
  Uint8List privateKey,
) async {
  await _ensureWasmReady();

  return _handleRsaException(() async {
    final jsPrivateKey = uint8ListToJS(privateKey);

    final response =
        await jsWindow
            .goRsaDecryptFromBase64(encryptedBase64, jsPrivateKey)
            .toDart;
    return processUint8ArrayResult(response, 'decrypted');
  });
}

/// 使用私钥对数据进行签名
/// [data] 要签名的数据
/// [privateKey] 私钥
Future<Uint8List> sign(Uint8List data, Uint8List privateKey) async {
  await _ensureWasmReady();

  return _handleRsaException(() async {
    final jsData = uint8ListToJS(data);
    final jsPrivateKey = uint8ListToJS(privateKey);

    final response = await jsWindow.goRsaSign(jsData, jsPrivateKey).toDart;
    return processUint8ArrayResult(response, 'signature');
  });
}

/// 使用私钥对字符串数据进行签名并返回Base64编码的结果
/// [data] 要签名的字符串数据
/// [privateKey] 私钥
Future<String> signBase64(String data, Uint8List privateKey) async {
  await _ensureWasmReady();

  return _handleRsaException(() async {
    final jsPrivateKey = uint8ListToJS(privateKey);

    final response = await jsWindow.goRsaSignBase64(data, jsPrivateKey).toDart;

    return processJSResponse<String>(response, (data) {
      final signature = data.signature;
      if (signature == null) {
        throw GoSecureUtilsException('签名失败：响应数据不完整');
      }

      return signature.toString();
    });
  });
}

/// 使用SHA1哈希算法和私钥对数据进行签名
/// [data] 要签名的数据
/// [privateKey] 私钥
Future<Uint8List> signSha1(Uint8List data, Uint8List privateKey) async {
  await _ensureWasmReady();

  return _handleRsaException(() async {
    final jsData = uint8ListToJS(data);
    final jsPrivateKey = uint8ListToJS(privateKey);

    final response = await jsWindow.goRsaSignSha1(jsData, jsPrivateKey).toDart;
    return processUint8ArrayResult(response, 'signature');
  });
}

/// 验证签名
/// [data] 原始数据
/// [publicKey] 公钥
/// [signature] 签名数据
Future<bool> verify(
  Uint8List data,
  Uint8List publicKey,
  Uint8List signature,
) async {
  await _ensureWasmReady();

  return _handleRsaException(() async {
    final jsData = uint8ListToJS(data);
    final jsPublicKey = uint8ListToJS(publicKey);
    final jsSignature = uint8ListToJS(signature);

    final response =
        await jsWindow.goRsaVerify(jsData, jsPublicKey, jsSignature).toDart;

    return processJSResponse<bool>(response, (data) {
      final verified = data.verified;
      if (verified == null) {
        throw GoSecureUtilsException('验证签名失败：响应数据不完整');
      }

      return verified;
    });
  });
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
  await _ensureWasmReady();

  return _handleRsaException(() async {
    final jsPublicKey = uint8ListToJS(publicKey);

    final response =
        await jsWindow
            .goRsaVerifyFromBase64(data, jsPublicKey, signatureBase64)
            .toDart;

    return processJSResponse<bool>(response, (data) {
      final verified = data.verified;
      if (verified == null) {
        throw GoSecureUtilsException('验证签名失败：响应数据不完整');
      }

      return verified;
    });
  });
}

/// 使用SHA1哈希算法验证签名
/// [data] 原始数据
/// [publicKey] 公钥
/// [signature] 签名数据
Future<bool> verifySha1(
  Uint8List data,
  Uint8List publicKey,
  Uint8List signature,
) async {
  await _ensureWasmReady();

  return _handleRsaException(() async {
    final jsData = uint8ListToJS(data);
    final jsPublicKey = uint8ListToJS(publicKey);
    final jsSignature = uint8ListToJS(signature);

    final response =
        await jsWindow.goRsaVerifySha1(jsData, jsPublicKey, jsSignature).toDart;

    return processJSResponse<bool>(response, (data) {
      final verified = data.verified;
      if (verified == null) {
        throw GoSecureUtilsException('验证SHA1签名失败：响应数据不完整');
      }

      return verified;
    });
  });
}
