package rsa

import (
	"bytes"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	priv, pub, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if priv == nil {
		t.Error("private key is nil")
	}
	if pub == nil {
		t.Error("public key is nil")
	}
}

func TestPrivateKeyToBytes(t *testing.T) {
	priv, _, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	privBytes := PrivateKeyToBytes(priv)
	if len(privBytes) == 0 {
		t.Error("PrivateKeyToBytes returned empty bytes")
	}
}

func TestPublicKeyToBytes(t *testing.T) {
	_, pub, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pubBytes, err := PublicKeyToBytes(pub)
	if err != nil {
		t.Fatalf("PublicKeyToBytes failed: %v", err)
	}
	if len(pubBytes) == 0 {
		t.Error("PublicKeyToBytes returned empty bytes")
	}
}

func TestBytesToPrivateKey(t *testing.T) {
	priv, _, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	privBytes := PrivateKeyToBytes(priv)
	retrievedPriv, err := BytesToPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("BytesToPrivateKey failed: %v", err)
	}
	if !bytes.Equal(PrivateKeyToBytes(priv), PrivateKeyToBytes(retrievedPriv)) {
		t.Error("original and retrieved private keys do not match")
	}
}

func TestBytesToPublicKey(t *testing.T) {
	_, pub, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pubBytes, _ := PublicKeyToBytes(pub)
	retrievedPub, err := BytesToPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("BytesToPublicKey failed: %v", err)
	}
	originalPubBytes, _ := PublicKeyToBytes(pub)
	retrievedPubBytes, _ := PublicKeyToBytes(retrievedPub)
	if !bytes.Equal(originalPubBytes, retrievedPubBytes) {
		t.Error("original and retrieved public keys do not match")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	priv, pub, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := []byte("hello, world!")

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
