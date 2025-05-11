package rsa

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptFlow(t *testing.T) {
	// 测试从公共 API 的角度检查加密/解密流程
	priv, pub, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := []byte("hello from public API test!")

	ciphertext, err := EncryptWithPublicKey(message, pub)
	if err != nil {
		t.Fatalf("EncryptWithPublicKey failed: %v", err)
	}

	plaintext, err := DecryptWithPrivateKey(ciphertext, priv)
	if err != nil {
		t.Fatalf("DecryptWithPrivateKey failed: %v", err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Errorf("original message '%s' and decrypted message '%s' do not match", message, plaintext)
	}
}

func TestKeySerializationFlow(t *testing.T) {
	// 测试从公共 API 的角度检查密钥序列化流程
	priv, pub, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// 序列化密钥
	privBytes := PrivateKeyToBytes(priv)
	pubBytes, err := PublicKeyToBytes(pub)
	if err != nil {
		t.Fatalf("PublicKeyToBytes failed: %v", err)
	}

	// 反序列化密钥
	recoveredPriv, err := BytesToPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("BytesToPrivateKey failed: %v", err)
	}

	recoveredPub, err := BytesToPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("BytesToPublicKey failed: %v", err)
	}

	// 使用恢复的密钥进行加密/解密测试
	message := []byte("test with recovered keys")

	ciphertext, err := EncryptWithPublicKey(message, recoveredPub)
	if err != nil {
		t.Fatalf("EncryptWithPublicKey with recovered key failed: %v", err)
	}

	plaintext, err := DecryptWithPrivateKey(ciphertext, recoveredPriv)
	if err != nil {
		t.Fatalf("DecryptWithPrivateKey with recovered key failed: %v", err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Errorf("when using recovered keys: original message '%s' and decrypted message '%s' do not match",
			message, plaintext)
	}
}
