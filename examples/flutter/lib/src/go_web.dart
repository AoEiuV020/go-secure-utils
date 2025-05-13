// ignore_for_file: non_constant_identifier_names, avoid_web_libraries_in_flutter, deprecated_member_use

import 'dart:html' as html;
import 'dart:js_interop';
import 'dart:typed_data';

/// JS Window接口
@JS()
@staticInterop
class JSWindow {}

/// JS上下文的响应类型
extension JSResponseExtension on JSObject {
  @JS('success')
  external bool get success;

  @JS('error')
  external String? get error;

  @JS('data')
  external JSObject? get data;
}

/// JS数据对象
@JS()
@staticInterop
class JSData {}

extension JSDataExtension on JSData {
  @JS('publicKey')
  external String? get publicKey;
  @JS('publicKey')
  external JSUint8Array? get publicKeyArray;

  @JS('privateKey')
  external String? get privateKey;

  @JS('encrypted')
  external JSAny? get encrypted;

  @JS('decrypted')
  external JSAny? get decrypted;

  @JS('signature')
  external JSAny? get signature;

  @JS('verified')
  external bool? get verified;
}

/// JS中的Uint8Array类型
@JS('Uint8Array')
@staticInterop
class JSUint8Array {
  external factory JSUint8Array(int length);
  external factory JSUint8Array.fromLength(int length);
}

extension JSUint8ArrayExtension on JSUint8Array {
  @JS('length')
  external int get length;

  @JS('set')
  external void set(JSUint8Array array, [int offset]);

  external int operator [](int index);

  @JS()
  external void operator []=(int index, int value);
}

/// JS Window扩展，定义与Go WASM交互的所有方法
extension JSWindowExtension on JSWindow {
  // RSA 相关方法
  @JS('goRsaGenKeyPair')
  external JSPromise<JSObject> goRsaGenKeyPair(int keySize);

  @JS('goRsaExtractPublicKey')
  external JSPromise<JSObject> goRsaExtractPublicKey(JSUint8Array privateKey);

  @JS('goRsaEncryptBase64')
  external JSPromise<JSObject> goRsaEncryptBase64(
    JSUint8Array data,
    JSUint8Array publicKey,
  );

  @JS('goRsaEncrypt')
  external JSPromise<JSObject> goRsaEncrypt(
    JSUint8Array data,
    JSUint8Array publicKey,
  );

  @JS('goRsaDecryptFromBase64')
  external JSPromise<JSObject> goRsaDecryptFromBase64(
    String encryptedBase64,
    JSUint8Array privateKey,
  );

  @JS('goRsaDecrypt')
  external JSPromise<JSObject> goRsaDecrypt(
    JSUint8Array encryptedData,
    JSUint8Array privateKey,
  );

  @JS('goRsaSignBase64')
  external JSPromise<JSObject> goRsaSignBase64(
    String data,
    JSUint8Array privateKey,
  );

  @JS('goRsaSign')
  external JSPromise<JSObject> goRsaSign(
    JSUint8Array data,
    JSUint8Array privateKey,
  );

  @JS('goRsaSignSha1')
  external JSPromise<JSObject> goRsaSignSha1(
    JSUint8Array data,
    JSUint8Array privateKey,
  );

  @JS('goRsaVerifyFromBase64')
  external JSPromise<JSObject> goRsaVerifyFromBase64(
    String data,
    JSUint8Array publicKey,
    String signature,
  );

  @JS('goRsaVerify')
  external JSPromise<JSObject> goRsaVerify(
    JSUint8Array data,
    JSUint8Array publicKey,
    JSUint8Array signature,
  );

  @JS('goRsaVerifySha1')
  external JSPromise<JSObject> goRsaVerifySha1(
    JSUint8Array data,
    JSUint8Array publicKey,
    JSUint8Array signature,
  );

  @JS('goWasmReady')
  external bool? get goWasmReady;
}

/// 获取JS窗口对象
JSWindow get jsWindow => html.window as JSWindow;

/// 将Dart的Uint8List转换为JS的Uint8Array
JSUint8Array uint8ListToJS(Uint8List bytes) {
  final result = JSUint8Array.fromLength(bytes.length);
  for (var i = 0; i < bytes.length; i++) {
    result[i] = bytes[i];
  }
  return result;
}

/// 将JS的Uint8Array转换为Dart的Uint8List
Uint8List jsUint8ArrayToDart(JSAny jsArray) {
  // 确保参数是JSUint8Array类型
  final array = jsArray as JSUint8Array;
  final length = array.length;
  final result = Uint8List(length);
  for (var i = 0; i < length; i++) {
    result[i] = array[i];
  }
  return result;
}

/// 检查WASM是否已加载
bool isWasmReady() {
  return jsWindow.goWasmReady == true;
}

/// 等待WASM加载完成
Future<void> waitForWasmReady() async {
  if (isWasmReady()) return;

  // 每100ms检查一次，最多等待10秒
  for (var i = 0; i < 100; i++) {
    await Future.delayed(const Duration(milliseconds: 100));
    if (isWasmReady()) return;
  }

  throw Exception('WASM加载超时');
}

/// 处理JS响应
T processJSResponse<T>(JSObject response, T Function(JSData) dataExtractor) {
  if (!response.success) {
    final error = response.error;
    throw Exception(error ?? '未知错误');
  }

  final data = response.data;
  if (data == null) {
    throw Exception('响应数据为空');
  }

  return dataExtractor(data as JSData);
}

/// 处理Uint8Array类型响应
Uint8List processUint8ArrayResult(JSObject response, String fieldName) {
  return processJSResponse<Uint8List>(response, (data) {
    final value =
        fieldName == 'encrypted'
            ? data.encrypted
            : (fieldName == 'decrypted' ? data.decrypted : data.signature);

    if (value == null) {
      throw Exception('响应中缺少字段: $fieldName');
    }

    return jsUint8ArrayToDart(value);
  });
}
