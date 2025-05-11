package rsa

import (
	"crypto/rsa"

	internalrsa "go-secure-utils/internal/crypto/rsa"
)

// GenerateKeyPair generates a new RSA key pair of the given bit size.
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	return internalrsa.GenerateKeyPair(bits)
}

// PrivateKeyToBytes converts an RSA private key to PEM format.
func PrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	return internalrsa.PrivateKeyToBytes(priv)
}

// PublicKeyToBytes converts an RSA public key to PEM format.
func PublicKeyToBytes(pub *rsa.PublicKey) ([]byte, error) {
	return internalrsa.PublicKeyToBytes(pub)
}

// BytesToPrivateKey converts PEM encoded RSA private key to rsa.PrivateKey.
func BytesToPrivateKey(privPEM []byte) (*rsa.PrivateKey, error) {
	return internalrsa.BytesToPrivateKey(privPEM)
}

// BytesToPublicKey converts PEM encoded RSA public key to rsa.PublicKey.
func BytesToPublicKey(pubPEM []byte) (*rsa.PublicKey, error) {
	return internalrsa.BytesToPublicKey(pubPEM)
}

// EncryptWithPublicKey encrypts data with public key.
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	return internalrsa.EncryptWithPublicKey(msg, pub)
}

// DecryptWithPrivateKey decrypts data with private key.
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	return internalrsa.DecryptWithPrivateKey(ciphertext, priv)
}
