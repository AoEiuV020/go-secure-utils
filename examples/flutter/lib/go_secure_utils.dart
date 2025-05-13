import 'dart:typed_data';
import 'dart:convert';

import 'src/go_secure_utils_web.dart' as io;
import 'src/go_secure_utils_models.dart';

export 'src/go_secure_utils_models.dart';

/// RSA加密工具类
class RSA {
  /// 生成RSA密钥对
  /// [bits] 密钥长度，通常为2048或4096
  static Future<RsaKeyPairData> genKeyPair({int keySize = 2048}) async {
    return await io.genKeyPair(keySize);
  }

  /// 从私钥中提取公钥
  /// [privateKey] 私钥数据
  static Future<Uint8List> extractPublicKey(Uint8List privateKey) async {
    return await io.extractPublicKey(privateKey);
  }

  /// 获取Base64编码的公钥
  /// [publicKey] 公钥数据
  static String getPublicKeyBase64(Uint8List publicKey) {
    return io.getPublicKeyBase64(publicKey);
  }

  /// 获取Base64编码的私钥
  /// [privateKey] 私钥数据
  static String getPrivateKeyBase64(Uint8List privateKey) {
    return io.getPrivateKeyBase64(privateKey);
  }

  /// 使用公钥加密数据
  /// [data] 要加密的数据
  /// [publicKey] 公钥
  static Future<Uint8List> encrypt(Uint8List data, Uint8List publicKey) async {
    return await io.encrypt(data, publicKey);
  }

  /// 使用公钥加密数据并返回Base64编码的结果
  /// [data] 要加密的数据
  /// [publicKey] 公钥
  static Future<String> encryptToBase64(
    Uint8List data,
    Uint8List publicKey,
  ) async {
    return await io.encryptToBase64(data, publicKey);
  }

  /// 使用公钥加密字符串数据并返回Base64编码的结果
  /// [text] 要加密的字符串数据
  /// [publicKey] 公钥
  static Future<String> encryptStringToBase64(
    String text,
    Uint8List publicKey,
  ) async {
    final data = Uint8List.fromList(utf8.encode(text));
    return await io.encryptToBase64(data, publicKey);
  }

  /// 使用私钥解密数据
  /// [encryptedData] 加密后的数据
  /// [privateKey] 私钥
  static Future<Uint8List> decrypt(
    Uint8List encryptedData,
    Uint8List privateKey,
  ) async {
    return await io.decrypt(encryptedData, privateKey);
  }

  /// 解密Base64编码的加密数据
  /// [encryptedBase64] Base64编码的加密数据
  /// [privateKey] 私钥
  static Future<Uint8List> decryptFromBase64(
    String encryptedBase64,
    Uint8List privateKey,
  ) async {
    return await io.decryptFromBase64(encryptedBase64, privateKey);
  }

  /// 解密Base64编码的加密数据并返回字符串
  /// [encryptedBase64] Base64编码的加密数据
  /// [privateKey] 私钥
  static Future<String> decryptStringFromBase64(
    String encryptedBase64,
    Uint8List privateKey,
  ) async {
    final decrypted = await io.decryptFromBase64(encryptedBase64, privateKey);
    return utf8.decode(decrypted);
  }

  /// 使用私钥对数据进行签名
  /// [data] 要签名的数据
  /// [privateKey] 私钥
  static Future<Uint8List> sign(Uint8List data, Uint8List privateKey) async {
    return await io.sign(data, privateKey);
  }

  /// 使用私钥对字符串数据进行签名并返回Base64编码的结果
  /// [data] 要签名的字符串数据
  /// [privateKey] 私钥
  static Future<String> signBase64(String data, Uint8List privateKey) async {
    return await io.signBase64(data, privateKey);
  }

  /// 使用SHA1哈希算法和私钥对数据进行签名
  /// [data] 要签名的数据
  /// [privateKey] 私钥
  static Future<Uint8List> signSha1(
    Uint8List data,
    Uint8List privateKey,
  ) async {
    return await io.signSha1(data, privateKey);
  }

  /// 验证签名
  /// [data] 原始数据
  /// [publicKey] 公钥
  /// [signature] 签名数据
  static Future<bool> verify(
    Uint8List data,
    Uint8List publicKey,
    Uint8List signature,
  ) async {
    return await io.verify(data, publicKey, signature);
  }

  /// 验证Base64编码的签名
  /// [data] 原始字符串数据
  /// [publicKey] 公钥
  /// [signatureBase64] Base64编码的签名
  static Future<bool> verifyFromBase64(
    String data,
    Uint8List publicKey,
    String signatureBase64,
  ) async {
    return await io.verifyFromBase64(data, publicKey, signatureBase64);
  }

  /// 使用SHA1哈希算法验证签名
  /// [data] 原始数据
  /// [publicKey] 公钥
  /// [signature] 签名数据
  static Future<bool> verifySha1(
    Uint8List data,
    Uint8List publicKey,
    Uint8List signature,
  ) async {
    return await io.verifySha1(data, publicKey, signature);
  }
}
