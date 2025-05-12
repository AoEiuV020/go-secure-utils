package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
)

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
	// 生成 RSA 密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, err
	}

	// 将私钥转换为 PKCS1 格式
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	// 将公钥转换为 PKCS8 格式
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return &RsaKeyPair{
		PublicKey:  publicKeyBytes,
		PrivateKey: privateKeyBytes,
	}, nil
}

// ExtractPublicKey extracts the public key from a private key.
func ExtractPublicKey(privateKeyBytes []byte) ([]byte, error) {
	// 尝试解析 PKCS1 格式的私钥
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
	}

	// 提取公钥并转换为 PKCS8 格式
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return publicKeyBytes, nil
}

// EncryptBase64 encrypts data with public key and returns base64 encoded result.
func EncryptBase64(data []byte, publicKeyBytes []byte) (string, error) {
	encrypted, err := Encrypt(data, publicKeyBytes)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// Encrypt encrypts data with public key.
func Encrypt(data []byte, publicKeyBytes []byte) ([]byte, error) {
	// 解析公钥
	pubInterface, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	pub, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	// 使用 PKCS1v15 进行加密
	return rsa.EncryptPKCS1v15(rand.Reader, pub, data)
}

// DecryptFromBase64 decrypts base64 encoded data with private key.
func DecryptFromBase64(encrypted string, privateKeyBytes []byte) ([]byte, error) {
	encryptedData, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}
	return Decrypt(encryptedData, privateKeyBytes)
}

// Decrypt decrypts data with private key.
func Decrypt(encryptedData []byte, privateKeyBytes []byte) ([]byte, error) {
	// 解析私钥
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// 使用 PKCS1v15 进行解密
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedData)
}

// SignBase64 signs data with private key and returns base64 encoded signature.
func SignBase64(data string, privateKeyBytes []byte) (string, error) {
	signature, err := Sign([]byte(data), privateKeyBytes)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// Sign signs data with private key using SHA-256.
func Sign(data []byte, privateKeyBytes []byte) ([]byte, error) {
	// 解析私钥
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// 计算数据的 SHA-256 哈希
	hashed := sha256.Sum256(data)

	// 使用 PKCS1v15 进行签名
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
}

// SignSha1 signs data with private key using SHA-1 hash.
func SignSha1(data []byte, privateKeyBytes []byte) ([]byte, error) {
	// 解析私钥
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// 计算数据的 SHA-1 哈希
	hashed := sha1.Sum(data)

	// 使用 PKCS1v15 进行签名
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, hashed[:])
}

// VerifyFromBase64 verifies base64 encoded signature with public key.
func VerifyFromBase64(data string, publicKeyBytes []byte, signatureBase64 string) (bool, error) {
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return false, fmt.Errorf("failed to decode base64 signature: %w", err)
	}
	return Verify([]byte(data), publicKeyBytes, signature)
}

// Verify verifies signature with public key using SHA-256.
func Verify(data []byte, publicKeyBytes []byte, signature []byte) (bool, error) {
	// 解析公钥
	pubInterface, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %w", err)
	}

	pub, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return false, errors.New("not an RSA public key")
	}

	// 计算数据的 SHA-256 哈希
	hashed := sha256.Sum256(data)

	// 验证签名
	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], signature)
	return err == nil, err
}

// VerifySha1 verifies signature with public key using SHA-1 hash.
func VerifySha1(data []byte, publicKeyBytes []byte, signature []byte) (bool, error) {
	// 解析公钥
	pubInterface, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %w", err)
	}

	pub, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return false, errors.New("not an RSA public key")
	}

	// 计算数据的 SHA-1 哈希
	hashed := sha1.Sum(data)

	// 验证签名
	err = rsa.VerifyPKCS1v15(pub, crypto.SHA1, hashed[:], signature)
	return err == nil, err
}

// ConvertPkcs8ToPkcs1 converts PKCS#8 encoded key to PKCS#1.
func ConvertPkcs8ToPkcs1(pkcs8Bytes []byte) ([]byte, error) {
	// 解析 PKCS8 格式的私钥
	privateKey, err := x509.ParsePKCS8PrivateKey(pkcs8Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
	}

	// 转换为 *rsa.PrivateKey 类型
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	// 转换为 PKCS1 格式
	return x509.MarshalPKCS1PrivateKey(rsaPrivateKey), nil
}

// ConvertPkcs1ToPkcs8 converts PKCS#1 encoded key to PKCS#8.
func ConvertPkcs1ToPkcs8(pkcs1Bytes []byte) ([]byte, error) {
	// 解析 PKCS1 格式的私钥
	privateKey, err := x509.ParsePKCS1PrivateKey(pkcs1Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
	}

	// 转换为 PKCS8 格式
	return x509.MarshalPKCS8PrivateKey(privateKey)
}
