package rsa

import (
	"encoding/base64"

	internalrsa "go-secure-utils/internal/crypto/rsa"
)

// RSA provides RSA encryption, decryption, signing, and verification functions.
// 私钥是pkcs1, 公钥是pkcs8,
// 加密是RSA/ECB/PKCS1Padding，
// 签名是Sha1withRSA,
type RSA struct {
	// private constructor in Go is achieved by not exporting constructors
}

// RsaKeyPair represents a pair of RSA keys.
type RsaKeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

// GetPublicKeyBase64 returns the base64 encoded public key.
func (kp *RsaKeyPair) GetPublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.PublicKey)
}

// GetPrivateKeyBase64 returns the base64 encoded private key.
func (kp *RsaKeyPair) GetPrivateKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.PrivateKey)
}

// GenKeyPair generates a new RSA key pair of the given bit size.
func GenKeyPair(keySize int) (*RsaKeyPair, error) {
	// Default key size if not provided
	if keySize <= 0 {
		keySize = 2048
	}

	keyPair, err := internalrsa.GenKeyPair(keySize)
	if err != nil {
		return nil, err
	}

	return &RsaKeyPair{
		PublicKey:  keyPair.PublicKey,
		PrivateKey: keyPair.PrivateKey,
	}, nil
}

// ExtractPublicKey extracts the public key from a private key.
func ExtractPublicKey(privateKey []byte) ([]byte, error) {
	return internalrsa.ExtractPublicKey(privateKey)
}

// EncryptBase64 encrypts data with public key and returns base64 encoded result.
func EncryptBase64(data []byte, publicKey []byte) (string, error) {
	return internalrsa.EncryptBase64(data, publicKey)
}

// Encrypt encrypts data with public key.
func Encrypt(data []byte, publicKey []byte) ([]byte, error) {
	return internalrsa.Encrypt(data, publicKey)
}

// DecryptFromBase64 decrypts base64 encoded data with private key.
func DecryptFromBase64(encrypted string, privateKey []byte) ([]byte, error) {
	return internalrsa.DecryptFromBase64(encrypted, privateKey)
}

// Decrypt decrypts data with private key.
func Decrypt(encryptedData []byte, privateKey []byte) ([]byte, error) {
	return internalrsa.Decrypt(encryptedData, privateKey)
}

// SignBase64 signs data with private key and returns base64 encoded signature.
func SignBase64(data string, privateKey []byte) (string, error) {
	return internalrsa.SignBase64(data, privateKey)
}

// Sign signs data with private key.
func Sign(data []byte, privateKey []byte) ([]byte, error) {
	return internalrsa.Sign(data, privateKey)
}

// SignSha1 signs data with private key using SHA-1 hash.
func SignSha1(data []byte, privateKey []byte) ([]byte, error) {
	return internalrsa.SignSha1(data, privateKey)
}

// VerifyFromBase64 verifies base64 encoded signature with public key.
func VerifyFromBase64(data string, publicKey []byte, signature string) (bool, error) {
	return internalrsa.VerifyFromBase64(data, publicKey, signature)
}

// Verify verifies signature with public key.
func Verify(data []byte, publicKey []byte, signature []byte) (bool, error) {
	return internalrsa.Verify(data, publicKey, signature)
}

// VerifySha1 verifies signature with public key using SHA-1 hash.
func VerifySha1(data []byte, publicKey []byte, signature []byte) (bool, error) {
	return internalrsa.VerifySha1(data, publicKey, signature)
}
