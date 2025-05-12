// Package main provides C-compatible interfaces to Go crypto functions
package main

/*
#include <stdlib.h>
#include <string.h>

typedef unsigned char byte;

// 基本字节数组结构
typedef struct {
    byte* data;
    int length;
    char* error; // NULL if no error
} ByteArray;

// 密钥对结构
typedef struct {
    ByteArray publicKey;
    ByteArray privateKey;
    char* error; // NULL if no error
} RsaKeyPair;

// 字符串结果结构
typedef struct {
    char* data;
    char* error; // NULL if no error
} StringResult;

// 布尔结果结构
typedef struct {
    int success; // 1 for true, 0 for false
    char* error; // NULL if no error
} BoolResult;
*/
import "C"
import (
	"runtime"
	"unsafe"
)

// 内存释放函数
// freeByteArray 释放为ByteArray分配的内存
func freeByteArray(result *C.ByteArray) {
	if result.data != nil {
		C.free(unsafe.Pointer(result.data))
		result.data = nil
	}
	if result.error != nil {
		C.free(unsafe.Pointer(result.error))
		result.error = nil
	}
}

// freeRsaKeyPair 释放为RsaKeyPair分配的内存
func freeRsaKeyPair(result *C.RsaKeyPair) {
	freeByteArray(&result.publicKey)
	freeByteArray(&result.privateKey)
	if result.error != nil {
		C.free(unsafe.Pointer(result.error))
		result.error = nil
	}
}

// freeStringResult 释放为StringResult分配的内存
func freeStringResult(result *C.StringResult) {
	if result.data != nil {
		C.free(unsafe.Pointer(result.data))
		result.data = nil
	}
	if result.error != nil {
		C.free(unsafe.Pointer(result.error))
		result.error = nil
	}
}

// freeBoolResult 释放为BoolResult分配的内存
func freeBoolResult(result *C.BoolResult) {
	if result.error != nil {
		C.free(unsafe.Pointer(result.error))
		result.error = nil
	}
}

// 数据转换工具函数
// goBytes2CByteArray 将Go字节切片转换为C ByteArray
func goBytes2CByteArray(data []byte, err error) C.ByteArray {
	var result C.ByteArray

	if err != nil {
		// 返回错误
		errStr := C.CString(err.Error())
		result.error = errStr
		result.data = nil
		result.length = 0
		return result
	}

	dataLen := len(data)
	if dataLen == 0 {
		result.data = nil
		result.length = 0
		result.error = nil
		return result
	}

	// 分配C内存并复制数据
	cData := C.malloc(C.size_t(dataLen))
	C.memcpy(cData, unsafe.Pointer(&data[0]), C.size_t(dataLen))

	result.data = (*C.byte)(cData)
	result.length = C.int(dataLen)
	result.error = nil

	return result
}

// goBytes2GoSlice 将C字节数组转换为Go切片
func goCBytes2GoSlice(data *C.byte, length C.int) []byte {
	return C.GoBytes(unsafe.Pointer(data), length)
}

// createStringResult 将字符串和错误封装为StringResult
func createStringResult(data string, err error) C.StringResult {
	var result C.StringResult
	
	if err != nil {
		result.error = C.CString(err.Error())
		result.data = nil
		return result
	}
	
	result.data = C.CString(data)
	result.error = nil
	
	return result
}

// createBoolResult 将布尔值和错误封装为BoolResult
func createBoolResult(success bool, err error) C.BoolResult {
	var result C.BoolResult
	
	if err != nil {
		result.error = C.CString(err.Error())
		result.success = 0
		return result
	}
	
	if success {
		result.success = 1
	} else {
		result.success = 0
	}
	result.error = nil
	
	return result
}

// RSA接口导出函数
//export goRsaGenKeyPair
func goRsaGenKeyPair(bits C.int) C.RsaKeyPair {
	var result C.RsaKeyPair

	// 生成密钥对
	keyPair, err := RsaGenKeyPair(int(bits))
	if err != nil {
		result.error = C.CString(err.Error())
		return result
	}

	// 将公钥和私钥转换为C的ByteArray
	result.publicKey = goBytes2CByteArray(keyPair.PublicKey, nil)
	result.privateKey = goBytes2CByteArray(keyPair.PrivateKey, nil)
	result.error = nil

	return result
}

//export goRsaGetPublicKeyBase64
func goRsaGetPublicKeyBase64(publicKey *C.byte, publicKeyLen C.int) C.StringResult {
	// 转换C字节数组为Go切片
	publicKeyGo := goCBytes2GoSlice(publicKey, publicKeyLen)

	// 创建临时密钥对
	keyPair := &RsaKeyPair{
		PublicKey: publicKeyGo,
	}

	// 获取Base64编码的公钥
	base64PublicKey := RsaGetPublicKeyBase64(keyPair)

	// 设置结果
	return createStringResult(base64PublicKey, nil)
}

//export goRsaGetPrivateKeyBase64
func goRsaGetPrivateKeyBase64(privateKey *C.byte, privateKeyLen C.int) C.StringResult {
	// 转换C字节数组为Go切片
	privateKeyGo := goCBytes2GoSlice(privateKey, privateKeyLen)

	// 创建临时密钥对
	keyPair := &RsaKeyPair{
		PrivateKey: privateKeyGo,
	}

	// 获取Base64编码的私钥
	base64PrivateKey := RsaGetPrivateKeyBase64(keyPair)

	// 设置结果
	return createStringResult(base64PrivateKey, nil)
}

//export goRsaExtractPublicKey
func goRsaExtractPublicKey(privateKey *C.byte, privateKeyLen C.int) C.ByteArray {
	// 转换C字节数组为Go切片
	privateKeyGo := goCBytes2GoSlice(privateKey, privateKeyLen)

	// 提取公钥
	publicKey, err := RsaExtractPublicKey(privateKeyGo)

	// 转换结果
	return goBytes2CByteArray(publicKey, err)
}

//export goRsaEncrypt
func goRsaEncrypt(data *C.byte, dataLen C.int, publicKey *C.byte, publicKeyLen C.int) C.ByteArray {
	// 转换C字节数组为Go切片
	dataGo := goCBytes2GoSlice(data, dataLen)
	publicKeyGo := goCBytes2GoSlice(publicKey, publicKeyLen)

	// 加密数据
	encrypted, err := RsaEncrypt(dataGo, publicKeyGo)

	// 转换结果
	return goBytes2CByteArray(encrypted, err)
}

//export goRsaEncryptBase64
func goRsaEncryptBase64(data *C.byte, dataLen C.int, publicKey *C.byte, publicKeyLen C.int) C.StringResult {
	// 转换C字节数组为Go切片
	dataGo := goCBytes2GoSlice(data, dataLen)
	publicKeyGo := goCBytes2GoSlice(publicKey, publicKeyLen)

	// 加密数据
	encryptedBase64, err := RsaEncryptBase64(dataGo, publicKeyGo)

	// 设置结果
	return createStringResult(encryptedBase64, err)
}

//export goRsaDecrypt
func goRsaDecrypt(encryptedData *C.byte, encryptedDataLen C.int, privateKey *C.byte, privateKeyLen C.int) C.ByteArray {
	// 转换C字节数组为Go切片
	encryptedDataGo := goCBytes2GoSlice(encryptedData, encryptedDataLen)
	privateKeyGo := goCBytes2GoSlice(privateKey, privateKeyLen)

	// 解密数据
	decrypted, err := RsaDecrypt(encryptedDataGo, privateKeyGo)

	// 转换结果
	return goBytes2CByteArray(decrypted, err)
}

//export goRsaDecryptFromBase64
func goRsaDecryptFromBase64(encryptedBase64 *C.char, privateKey *C.byte, privateKeyLen C.int) C.ByteArray {
	// 转换C字符串和C字节数组为Go类型
	encryptedBase64Go := C.GoString(encryptedBase64)
	privateKeyGo := goCBytes2GoSlice(privateKey, privateKeyLen)

	// 解密数据
	decrypted, err := RsaDecryptFromBase64(encryptedBase64Go, privateKeyGo)

	// 转换结果
	return goBytes2CByteArray(decrypted, err)
}

//export goRsaSign
func goRsaSign(data *C.byte, dataLen C.int, privateKey *C.byte, privateKeyLen C.int) C.ByteArray {
	// 转换C字节数组为Go切片
	dataGo := goCBytes2GoSlice(data, dataLen)
	privateKeyGo := goCBytes2GoSlice(privateKey, privateKeyLen)

	// 签名数据
	signature, err := RsaSign(dataGo, privateKeyGo)

	// 转换结果
	return goBytes2CByteArray(signature, err)
}

//export goRsaSignBase64
func goRsaSignBase64(data *C.char, privateKey *C.byte, privateKeyLen C.int) C.StringResult {
	// 转换C字符串和C字节数组为Go类型
	dataGo := C.GoString(data)
	privateKeyGo := goCBytes2GoSlice(privateKey, privateKeyLen)

	// 签名数据
	signatureBase64, err := RsaSignBase64(dataGo, privateKeyGo)

	// 设置结果
	return createStringResult(signatureBase64, err)
}

//export goRsaSignSha1
func goRsaSignSha1(data *C.byte, dataLen C.int, privateKey *C.byte, privateKeyLen C.int) C.ByteArray {
	// 转换C字节数组为Go切片
	dataGo := goCBytes2GoSlice(data, dataLen)
	privateKeyGo := goCBytes2GoSlice(privateKey, privateKeyLen)

	// 使用SHA1签名数据
	signature, err := RsaSignSha1(dataGo, privateKeyGo)

	// 转换结果
	return goBytes2CByteArray(signature, err)
}

//export goRsaVerify
func goRsaVerify(data *C.byte, dataLen C.int, publicKey *C.byte, publicKeyLen C.int, signature *C.byte, signatureLen C.int) C.BoolResult {
	// 转换C字节数组为Go切片
	dataGo := goCBytes2GoSlice(data, dataLen)
	publicKeyGo := goCBytes2GoSlice(publicKey, publicKeyLen)
	signatureGo := goCBytes2GoSlice(signature, signatureLen)

	// 验证签名
	verified, err := RsaVerify(dataGo, publicKeyGo, signatureGo)

	// 设置结果
	return createBoolResult(verified, err)
}

//export goRsaVerifyFromBase64
func goRsaVerifyFromBase64(data *C.char, publicKey *C.byte, publicKeyLen C.int, signatureBase64 *C.char) C.BoolResult {
	// 转换C字符串和C字节数组为Go类型
	dataGo := C.GoString(data)
	publicKeyGo := goCBytes2GoSlice(publicKey, publicKeyLen)
	signatureBase64Go := C.GoString(signatureBase64)

	// 验证签名
	verified, err := RsaVerifyFromBase64(dataGo, publicKeyGo, signatureBase64Go)

	// 设置结果
	return createBoolResult(verified, err)
}

//export goRsaVerifySha1
func goRsaVerifySha1(data *C.byte, dataLen C.int, publicKey *C.byte, publicKeyLen C.int, signature *C.byte, signatureLen C.int) C.BoolResult {
	// 转换C字节数组为Go切片
	dataGo := goCBytes2GoSlice(data, dataLen)
	publicKeyGo := goCBytes2GoSlice(publicKey, publicKeyLen)
	signatureGo := goCBytes2GoSlice(signature, signatureLen)

	// 验证SHA1签名
	verified, err := RsaVerifySha1(dataGo, publicKeyGo, signatureGo)

	// 设置结果
	return createBoolResult(verified, err)
}

// 内存管理函数导出

//export goGenerateRSAKeyPair
func goGenerateRSAKeyPair(bits C.int) C.ByteArray {
	// 调用新API生成密钥对
	keyPair := goRsaGenKeyPair(bits)
	// 只返回私钥部分作为向后兼容
	return keyPair.privateKey
}

//export goRSAEncrypt
func goRSAEncrypt(publicKey *C.byte, publicKeyLen C.int, data *C.byte, dataLen C.int) C.ByteArray {
	// 调用新API进行加密
	return goRsaEncrypt(data, dataLen, publicKey, publicKeyLen)
}

//export goRSADecrypt
func goRSADecrypt(privateKey *C.byte, privateKeyLen C.int, ciphertext *C.byte, ciphertextLen C.int) C.ByteArray {
	// 调用新API进行解密
	return goRsaDecrypt(ciphertext, ciphertextLen, privateKey, privateKeyLen)
}

//export goFreeByteArray
func goFreeByteArray(result C.ByteArray) {
	freeByteArray(&result)
}

//export goFreeRsaKeyPair
func goFreeRsaKeyPair(result C.RsaKeyPair) {
	freeRsaKeyPair(&result)
}

//export goFreeStringResult
func goFreeStringResult(result C.StringResult) {
	freeStringResult(&result)
}

//export goFreeBoolResult
func goFreeBoolResult(result C.BoolResult) {
	freeBoolResult(&result)
}

// KeepAlive 保持对Go内存的引用，防止被垃圾回收
//
//export KeepAlive
func KeepAlive() {
	runtime.KeepAlive(nil)
}

func main() {
	// CGO 需要一个main函数，但我们不会使用它
}
