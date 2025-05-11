// Package main provides centralized exports for all crypto utility functions
package main

import (
	"crypto/rsa"

	rsautils "go-secure-utils/pkg/crypto/rsa"
)

// RSA 加密/解密函数

// GenerateRSAKeyPair 生成指定位数的RSA密钥对
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	return rsautils.GenerateKeyPair(bits)
}

// RSAPrivateKeyToBytes 将RSA私钥转换为PEM格式
func RSAPrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	return rsautils.PrivateKeyToBytes(priv)
}

// RSAPublicKeyToBytes 将RSA公钥转换为PEM格式
func RSAPublicKeyToBytes(pub *rsa.PublicKey) ([]byte, error) {
	return rsautils.PublicKeyToBytes(pub)
}

// RSABytesToPrivateKey 将PEM编码的RSA私钥转换为rsa.PrivateKey
func RSABytesToPrivateKey(privPEM []byte) (*rsa.PrivateKey, error) {
	return rsautils.BytesToPrivateKey(privPEM)
}

// RSABytesToPublicKey 将PEM编码的RSA公钥转换为rsa.PublicKey
func RSABytesToPublicKey(pubPEM []byte) (*rsa.PublicKey, error) {
	return rsautils.BytesToPublicKey(pubPEM)
}

// RSAEncryptWithPublicKey 使用公钥加密数据
func RSAEncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	return rsautils.EncryptWithPublicKey(msg, pub)
}

// RSADecryptWithPrivateKey 使用私钥解密数据
func RSADecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	return rsautils.DecryptWithPrivateKey(ciphertext, priv)
}
