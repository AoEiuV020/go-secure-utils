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
  // 检查是否为错误响应
  bool isErrorResponse() {
    return hasProperty('success') &&
        hasProperty('error') &&
        !(this as dynamic).success;
  }

  // 获取错误消息（如果是错误响应）
  String? getErrorMessage() {
    if (isErrorResponse()) {
      return (this as dynamic).error as String?;
    }
    return null;
  }
}

extension JSObjectExtension on JSObject {
  @JS('hasOwnProperty')
  external bool hasProperty(String name);
}

// 我们不再需要这个类和扩展

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
  external JSPromise<JSBoolean> goRsaVerifyFromBase64(
    String data,
    JSUint8Array publicKey,
    String signature,
  );

  @JS('goRsaVerify')
  external JSPromise<JSBoolean> goRsaVerify(
    JSUint8Array data,
    JSUint8Array publicKey,
    JSUint8Array signature,
  );

  @JS('goRsaVerifySha1')
  external JSPromise<JSBoolean> goRsaVerifySha1(
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
Uint8List jsUint8ArrayToDart(Object jsArray) {
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
T processJSResponse<T>(JSObject response, T Function(dynamic) dataProcessor) {
  // 检查是否为错误响应对象
  if (response.isErrorResponse()) {
    final error = response.getErrorMessage();
    throw Exception(error ?? '未知错误');
  }

  // 直接将响应作为数据处理
  return dataProcessor(response);
}

/// 处理返回的Uint8Array
Uint8List processDirectUint8Array(JSObject response) {
  return processJSResponse<Uint8List>(response, (data) {
    return jsUint8ArrayToDart(data as JSUint8Array);
  });
}

/// 处理返回的字符串
String processDirectString(JSObject response) {
  return processJSResponse<String>(response, (data) {
    if (data is! String) {
      throw Exception('响应不是有效的字符串');
    }
    return data;
  });
}

/// 处理返回的布尔值
bool processDirectBoolean(JSObject response) {
  return processJSResponse<bool>(response, (data) {
    if (data is! bool) {
      throw Exception('响应不是有效的布尔值');
    }
    return data;
  });
}
