import 'dart:typed_data';
import 'dart:convert';

/// RSA密钥对类，提供公钥和私钥
class RsaKeyPairData {
  final Uint8List publicKey;
  final Uint8List privateKey;

  RsaKeyPairData(this.publicKey, this.privateKey);

  /// 获取Base64编码的公钥
  String getPublicKeyBase64() {
    return base64Encode(publicKey);
  }

  /// 获取Base64编码的私钥
  String getPrivateKeyBase64() {
    return base64Encode(privateKey);
  }
}

/// 异常类
class GoSecureUtilsException implements Exception {
  final String message;
  GoSecureUtilsException(this.message);

  @override
  String toString() => 'GoSecureUtilsException: $message';
}
