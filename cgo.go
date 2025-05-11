// Package main provides C-compatible interfaces to Go crypto functions
package main

/*
#include <stdlib.h>
#include <string.h>

typedef unsigned char byte;
typedef struct {
    byte* data;
    int length;
    char* error; // NULL if no error
} ByteArray;
*/
import "C"
import (
	"runtime"
	"unsafe"
)

// freeByteArray releases memory allocated for ByteArray
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

// goBytes2CByteArray converts Go byte slice to C ByteArray
func goBytes2CByteArray(data []byte, err error) C.ByteArray {
	var result C.ByteArray

	if err != nil {
		// Return error
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

	// Allocate C memory and copy data
	cData := C.malloc(C.size_t(dataLen))
	C.memcpy(cData, unsafe.Pointer(&data[0]), C.size_t(dataLen))

	result.data = (*C.byte)(cData)
	result.length = C.int(dataLen)
	result.error = nil

	return result
}

//export GenerateRSAKeyPair_C
func GenerateRSAKeyPair_C(bits C.int) C.ByteArray {
	// Generate key pair
	privKey, _, err := GenerateRSAKeyPair(int(bits))
	if err != nil {
		return goBytes2CByteArray(nil, err)
	}

	// Convert private key to bytes (includes public key)
	privKeyBytes := RSAPrivateKeyToBytes(privKey)

	return goBytes2CByteArray(privKeyBytes, nil)
}

//export RSAEncrypt_C
func RSAEncrypt_C(pubKeyBytes *C.byte, pubKeyLen C.int, data *C.byte, dataLen C.int) C.ByteArray {
	// Convert C byte arrays to Go slices
	pubKeyGo := C.GoBytes(unsafe.Pointer(pubKeyBytes), pubKeyLen)
	dataGo := C.GoBytes(unsafe.Pointer(data), dataLen)

	// Convert bytes to public key
	pubKey, err := RSABytesToPublicKey(pubKeyGo)
	if err != nil {
		return goBytes2CByteArray(nil, err)
	}

	// Encrypt data
	encrypted, err := RSAEncryptWithPublicKey(dataGo, pubKey)
	return goBytes2CByteArray(encrypted, err)
}

//export RSADecrypt_C
func RSADecrypt_C(privKeyBytes *C.byte, privKeyLen C.int, ciphertext *C.byte, ciphertextLen C.int) C.ByteArray {
	// Convert C byte arrays to Go slices
	privKeyGo := C.GoBytes(unsafe.Pointer(privKeyBytes), privKeyLen)
	ciphertextGo := C.GoBytes(unsafe.Pointer(ciphertext), ciphertextLen)

	// Convert bytes to private key
	privKey, err := RSABytesToPrivateKey(privKeyGo)
	if err != nil {
		return goBytes2CByteArray(nil, err)
	}

	// Decrypt data
	decrypted, err := RSADecryptWithPrivateKey(ciphertextGo, privKey)
	return goBytes2CByteArray(decrypted, err)
}

// This function is required to keep references to Go memory alive for C code
//
//export KeepAlive
func KeepAlive() {
	runtime.KeepAlive(nil)
}

// FreeByteArray_C frees memory allocated for ByteArray
//
//export FreeByteArray_C
func FreeByteArray_C(result C.ByteArray) {
	freeByteArray(&result)
}

func main() {
	// CGO requires a main function but we won't use it
}
