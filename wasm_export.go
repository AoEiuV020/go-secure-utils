//go:build wasm

package main

import (
	"syscall/js"
)

// PromiseFunc 定义需要被Promise化的函数类型
type PromiseFunc func(args []js.Value) interface{}

// 响应类型 - 统一处理返回结果
type Response struct {
	Success bool        `json:"success"`
	Error   string      `json:"error,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// 创建成功响应
func successResponse(data interface{}) interface{} {
	return map[string]interface{}{
		"success": true,
		"data":    data,
	}
}

// 创建错误响应
func errorResponse(err error) interface{} {
	return map[string]interface{}{
		"success": false,
		"error":   err.Error(),
	}
}

// 从JS复制字节数组到Go
func copyBytesFromJS(value js.Value) []byte {
	if value.IsNull() || value.IsUndefined() {
		return nil
	}

	length := value.Get("length").Int()
	if length == 0 {
		return []byte{}
	}

	bytes := make([]byte, length)
	js.CopyBytesToGo(bytes, value)
	return bytes
}

// 从Go复制字节数组到JS
func copyBytesToJS(bytes []byte) js.Value {
	if bytes == nil {
		return js.Null()
	}

	result := js.Global().Get("Uint8Array").New(len(bytes))
	js.CopyBytesToJS(result, bytes)
	return result
}

// ToPromise 将Go函数封装为返回Promise的JS函数
func ToPromise(fn PromiseFunc) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		// 创建Promise对象
		promise := js.Global().Get("Promise")

		// 返回一个新的Promise
		return promise.New(js.FuncOf(func(this js.Value, promiseArgs []js.Value) interface{} {
			resolve := promiseArgs[0]
			reject := promiseArgs[1]

			go func() {
				defer func() {
					if r := recover(); r != nil {
						// 捕获panic并reject
						errMsg := "Unknown error"
						if err, ok := r.(error); ok {
							errMsg = err.Error()
						} else if str, ok := r.(string); ok {
							errMsg = str
						}
						reject.Invoke(js.ValueOf(errMsg))
					}
				}()

				// 执行实际函数
				result := fn(args)
				resolve.Invoke(js.ValueOf(result))
			}()

			return nil
		}))
	})
}

// RSA函数导出
func registerRsaFunctions() {
	// 生成RSA密钥对
	js.Global().Set("goRsaGenKeyPair", ToPromise(func(args []js.Value) interface{} {
		keySize := args[0].Int()
		kp, err := RsaGenKeyPair(keySize)
		if err != nil {
			return errorResponse(err)
		}

		return successResponse(map[string]interface{}{
			"publicKey":  RsaGetPublicKeyBase64(kp),
			"privateKey": RsaGetPrivateKeyBase64(kp),
		})
	}))

	// 提取公钥
	js.Global().Set("goRsaExtractPublicKey", ToPromise(func(args []js.Value) interface{} {
		privateKeyArray := copyBytesFromJS(args[0])

		publicKey, err := RsaExtractPublicKey(privateKeyArray)
		if err != nil {
			return errorResponse(err)
		}

		return successResponse(map[string]interface{}{
			"publicKey": copyBytesToJS(publicKey),
		})
	}))

	// RSA加密（返回Base64编码结果）
	js.Global().Set("goRsaEncryptBase64", ToPromise(func(args []js.Value) interface{} {
		dataArray := copyBytesFromJS(args[0])
		publicKeyArray := copyBytesFromJS(args[1])

		encrypted, err := RsaEncryptBase64(dataArray, publicKeyArray)
		if err != nil {
			return errorResponse(err)
		}

		return successResponse(map[string]interface{}{
			"encrypted": encrypted,
		})
	}))

	// RSA加密（返回二进制结果）
	js.Global().Set("goRsaEncrypt", ToPromise(func(args []js.Value) interface{} {
		dataArray := copyBytesFromJS(args[0])
		publicKeyArray := copyBytesFromJS(args[1])

		encrypted, err := RsaEncrypt(dataArray, publicKeyArray)
		if err != nil {
			return errorResponse(err)
		}

		return successResponse(map[string]interface{}{
			"encrypted": copyBytesToJS(encrypted),
		})
	}))

	// 从Base64解密RSA
	js.Global().Set("goRsaDecryptFromBase64", ToPromise(func(args []js.Value) interface{} {
		encrypted := args[0].String()
		privateKeyArray := copyBytesFromJS(args[1])

		decrypted, err := RsaDecryptFromBase64(encrypted, privateKeyArray)
		if err != nil {
			return errorResponse(err)
		}

		return successResponse(map[string]interface{}{
			"decrypted": copyBytesToJS(decrypted),
		})
	}))

	// RSA解密
	js.Global().Set("goRsaDecrypt", ToPromise(func(args []js.Value) interface{} {
		encryptedArray := copyBytesFromJS(args[0])
		privateKeyArray := copyBytesFromJS(args[1])

		decrypted, err := RsaDecrypt(encryptedArray, privateKeyArray)
		if err != nil {
			return errorResponse(err)
		}

		return successResponse(map[string]interface{}{
			"decrypted": copyBytesToJS(decrypted),
		})
	}))

	// RSA签名（返回Base64编码结果）
	js.Global().Set("goRsaSignBase64", ToPromise(func(args []js.Value) interface{} {
		data := args[0].String()
		privateKeyArray := copyBytesFromJS(args[1])

		signature, err := RsaSignBase64(data, privateKeyArray)
		if err != nil {
			return errorResponse(err)
		}

		return successResponse(map[string]interface{}{
			"signature": signature,
		})
	}))

	// RSA签名
	js.Global().Set("goRsaSign", ToPromise(func(args []js.Value) interface{} {
		dataArray := copyBytesFromJS(args[0])
		privateKeyArray := copyBytesFromJS(args[1])

		signature, err := RsaSign(dataArray, privateKeyArray)
		if err != nil {
			return errorResponse(err)
		}

		return successResponse(map[string]interface{}{
			"signature": copyBytesToJS(signature),
		})
	}))

	// RSA SHA1签名
	js.Global().Set("goRsaSignSha1", ToPromise(func(args []js.Value) interface{} {
		dataArray := copyBytesFromJS(args[0])
		privateKeyArray := copyBytesFromJS(args[1])

		signature, err := RsaSignSha1(dataArray, privateKeyArray)
		if err != nil {
			return errorResponse(err)
		}

		return successResponse(map[string]interface{}{
			"signature": copyBytesToJS(signature),
		})
	}))

	// 验证Base64编码的RSA签名
	js.Global().Set("goRsaVerifyFromBase64", ToPromise(func(args []js.Value) interface{} {
		data := args[0].String()
		publicKeyArray := copyBytesFromJS(args[1])
		signature := args[2].String()

		verified, err := RsaVerifyFromBase64(data, publicKeyArray, signature)
		if err != nil {
			return errorResponse(err)
		}

		return successResponse(map[string]interface{}{
			"verified": verified,
		})
	}))

	// 验证RSA签名
	js.Global().Set("goRsaVerify", ToPromise(func(args []js.Value) interface{} {
		dataArray := copyBytesFromJS(args[0])
		publicKeyArray := copyBytesFromJS(args[1])
		signatureArray := copyBytesFromJS(args[2])

		verified, err := RsaVerify(dataArray, publicKeyArray, signatureArray)
		if err != nil {
			return errorResponse(err)
		}

		return successResponse(map[string]interface{}{
			"verified": verified,
		})
	}))

	// 验证RSA SHA1签名
	js.Global().Set("goRsaVerifySha1", ToPromise(func(args []js.Value) interface{} {
		dataArray := copyBytesFromJS(args[0])
		publicKeyArray := copyBytesFromJS(args[1])
		signatureArray := copyBytesFromJS(args[2])

		verified, err := RsaVerifySha1(dataArray, publicKeyArray, signatureArray)
		if err != nil {
			return errorResponse(err)
		}

		return successResponse(map[string]interface{}{
			"verified": verified,
		})
	}))
}

func main() {
	// 注册所有RSA函数
	registerRsaFunctions()

	// 通知JS运行时WASM已准备就绪
	js.Global().Set("goWasmReady", js.ValueOf(true))

	// 保持程序运行
	select {}
}
