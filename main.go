// Package main provides centralized exports for all crypto utility functions
package main

import (
	rsapkg "go-secure-utils/pkg/crypto/rsa"
)

// RsaKeyPair represents a pair of RSA keys.
type RsaKeyPair = rsapkg.RsaKeyPair

// RsaGetPublicKeyBase64 returns the base64 encoded public key.
func RsaGetPublicKeyBase64(kp *RsaKeyPair) string {
	return kp.GetPublicKeyBase64()
}

// RsaGetPrivateKeyBase64 returns the base64 encoded private key.
func RsaGetPrivateKeyBase64(kp *RsaKeyPair) string {
	return kp.GetPrivateKeyBase64()
}

// RsaGenKeyPair generates a new RSA key pair of the given bit size.
func RsaGenKeyPair(keySize int) (*RsaKeyPair, error) {
	return rsapkg.GenKeyPair(keySize)
}

// RsaExtractPublicKey extracts the public key from a private key.
func RsaExtractPublicKey(privateKey []byte) ([]byte, error) {
	return rsapkg.ExtractPublicKey(privateKey)
}

// RsaEncryptBase64 encrypts data with public key and returns base64 encoded result.
func RsaEncryptBase64(data []byte, publicKey []byte) (string, error) {
	return rsapkg.EncryptBase64(data, publicKey)
}

// RsaEncrypt encrypts data with public key.
func RsaEncrypt(data []byte, publicKey []byte) ([]byte, error) {
	return rsapkg.Encrypt(data, publicKey)
}

// RsaDecryptFromBase64 decrypts base64 encoded data with private key.
func RsaDecryptFromBase64(encrypted string, privateKey []byte) ([]byte, error) {
	return rsapkg.DecryptFromBase64(encrypted, privateKey)
}

// RsaDecrypt decrypts data with private key.
func RsaDecrypt(encryptedData []byte, privateKey []byte) ([]byte, error) {
	return rsapkg.Decrypt(encryptedData, privateKey)
}

// RsaSignBase64 signs data with private key and returns base64 encoded signature.
func RsaSignBase64(data string, privateKey []byte) (string, error) {
	return rsapkg.SignBase64(data, privateKey)
}

// RsaSign signs data with private key.
func RsaSign(data []byte, privateKey []byte) ([]byte, error) {
	return rsapkg.Sign(data, privateKey)
}

// RsaSignSha1 signs data with private key using SHA-1 hash.
func RsaSignSha1(data []byte, privateKey []byte) ([]byte, error) {
	return rsapkg.SignSha1(data, privateKey)
}

// RsaVerifyFromBase64 verifies base64 encoded signature with public key.
func RsaVerifyFromBase64(data string, publicKey []byte, signature string) (bool, error) {
	return rsapkg.VerifyFromBase64(data, publicKey, signature)
}

// RsaVerify verifies signature with public key.
func RsaVerify(data []byte, publicKey []byte, signature []byte) (bool, error) {
	return rsapkg.Verify(data, publicKey, signature)
}

// RsaVerifySha1 verifies signature with public key using SHA-1 hash.
func RsaVerifySha1(data []byte, publicKey []byte, signature []byte) (bool, error) {
	return rsapkg.VerifySha1(data, publicKey, signature)
}
