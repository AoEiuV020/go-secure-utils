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
      // 预期返回一个数组 [publicKeyBase64, privateKeyBase64]
      final jsArray = data as JSArray;
      if (jsArray.length < 2) {
        throw GoSecureUtilsException('生成密钥对失败：响应数据不完整');
      }

      final publicKeyBase64 = jsArray[0];
      final privateKeyBase64 = jsArray[1];

      if (publicKeyBase64 == null || privateKeyBase64 == null) {
        throw GoSecureUtilsException('生成密钥对失败：数据为空');
      }

      final publicKey = base64Decode(publicKeyBase64.toString());
      final privateKey = base64Decode(privateKeyBase64.toString());

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

    // 直接返回Uint8Array
    return processDirectUint8Array(response);
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
    return processDirectUint8Array(response);
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

    return processDirectString(response);
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
    return processDirectUint8Array(response);
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
    return processDirectUint8Array(response);
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
    return processDirectUint8Array(response);
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
    return processDirectString(response);
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
    return processDirectUint8Array(response);
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
    return response.toDart;
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
    return response.toDart;
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
    return response.toDart;
  });
}
