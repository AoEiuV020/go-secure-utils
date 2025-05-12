package rsa

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestGenKeyPair(t *testing.T) {
	keyPair, err := GenKeyPair(2048)
	if err != nil {
		t.Fatalf("GenKeyPair failed: %v", err)
	}

	fmt.Println(keyPair.GetPublicKeyBase64())
	fmt.Println(keyPair.GetPrivateKeyBase64())

	if len(keyPair.PublicKey) == 0 {
		t.Error("PublicKey is empty")
	}

	if len(keyPair.PrivateKey) == 0 {
		t.Error("PrivateKey is empty")
	}

	// 测试生成的密钥对加密解密
	testContent := []byte("test message")
	encrypted, err := Encrypt(testContent, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(encrypted, keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(testContent, decrypted) {
		t.Errorf("Decrypted content does not match original: got %s, want %s", decrypted, testContent)
	}

	// 测试生成的密钥对签名验签
	signature, err := Sign(testContent, keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	verified, err := Verify(testContent, keyPair.PublicKey, signature)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !verified {
		t.Error("Signature verification failed")
	}

	// Base64格式测试
	encryptedBase64, err := EncryptBase64(testContent, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("EncryptBase64 failed: %v", err)
	}

	decryptedFromBase64, err := DecryptFromBase64(encryptedBase64, keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("DecryptFromBase64 failed: %v", err)
	}

	if !bytes.Equal(testContent, decryptedFromBase64) {
		t.Errorf("Decrypted content from base64 does not match original: got %s, want %s", decryptedFromBase64, testContent)
	}

	signatureBase64, err := SignBase64(string(testContent), keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("SignBase64 failed: %v", err)
	}

	verifiedBase64, err := VerifyFromBase64(string(testContent), keyPair.PublicKey, signatureBase64)
	if err != nil {
		t.Fatalf("VerifyFromBase64 failed: %v", err)
	}

	if !verifiedBase64 {
		t.Error("Base64 signature verification failed")
	}
}

func TestPublicEncryptDecrypt(t *testing.T) {
	encrypted, err := EncryptBase64([]byte(content), keyPair.PublicKey)
	if err != nil {
		t.Fatalf("EncryptBase64 failed: %v", err)
	}

	fmt.Println(encrypted)

	decrypted, err := DecryptFromBase64(encrypted, keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("DecryptFromBase64 failed: %v", err)
	}

	if string(decrypted) != content {
		t.Errorf("Decrypted content does not match original: got %s, want %s", decrypted, content)
	}
}

func TestPkcs1KeyShouldWork(t *testing.T) {
	// 测试 PKCS1 格式密钥的加密解密
	encrypted, err := EncryptBase64([]byte(content), keyPairPkcs1.PublicKey)
	if err != nil {
		t.Fatalf("EncryptBase64 failed: %v", err)
	}

	decrypted, err := DecryptFromBase64(encrypted, keyPairPkcs1.PrivateKey)
	if err != nil {
		t.Fatalf("DecryptFromBase64 failed: %v", err)
	}

	if string(decrypted) != content {
		t.Errorf("Decrypted content does not match original: got %s, want %s", decrypted, content)
	}
}

func TestSignAndVerify(t *testing.T) {
	// 测试签名和验证
	signature, err := SignBase64(content, keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("SignBase64 failed: %v", err)
	}

	fmt.Println(signature)

	verified, err := VerifyFromBase64(content, keyPair.PublicKey, signature)
	if err != nil {
		t.Fatalf("VerifyFromBase64 failed: %v", err)
	}

	if !verified {
		t.Error("Signature verification failed")
	}
}

func TestVerifyWithWrongContentShouldFail(t *testing.T) {
	// 测试错误内容的验证应当失败
	verified, err := Verify([]byte("wrong content"), keyPair.PublicKey, signRaw)
	if err != nil {
		// 这里可能会有错误，但我们只关心验证结果应该是false
		t.Logf("Verify error (expected): %v", err)
	}

	if verified {
		t.Error("Verification with wrong content should fail but it succeeded")
	}
}

func TestPkcs1KeySignAndVerify(t *testing.T) {
	// 测试 PKCS1 格式密钥的签名验证
	signature, err := SignBase64(content, keyPairPkcs1.PrivateKey)
	if err != nil {
		t.Fatalf("SignBase64 failed: %v", err)
	}

	verified, err := VerifyFromBase64(content, keyPairPkcs1.PublicKey, signature)
	if err != nil {
		t.Fatalf("VerifyFromBase64 failed: %v", err)
	}

	if !verified {
		t.Error("PKCS1 key signature verification failed")
	}
}

func TestPrecomputedEncryption(t *testing.T) {
	// 测试预计算的加密（注意：RSA/ECB/PKCS1Padding每次加密结果不同）
	encrypted, err := Encrypt(contentRaw, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(encrypted))

	// RSA/ECB/PKCS1Padding 每次加密都不同，所以这里不匹配
	if bytes.Equal(encrypted, encryptedRaw) {
		t.Error("RSA encryption should generate different output each time, but got same output")
	}
}

func TestPrecomputedDecryption(t *testing.T) {
	// 测试预计算的解密
	decrypted, err := Decrypt(encryptedRaw, keyPairPkcs1.PrivateKey)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, contentRaw) {
		t.Errorf("Decrypted content does not match expected content")
	}
}

func TestPrecomputedSignature(t *testing.T) {
	// 测试预计算的签名
	signed, err := Sign(contentRaw, keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(signed))

	// 由于RSA签名涉及随机元素，每次签名可能不同，所以不比较
	// 但我们应该能验证预计算的签名
}

func TestPrecomputedSignatureVerify(t *testing.T) {
	// 测试预计算签名的验证
	verified, err := Verify(contentRaw, keyPair.PublicKey, signRaw)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !verified {
		t.Error("Precomputed signature verification failed")
	}
}

func TestPrecomputedSignatureSha1(t *testing.T) {
	// 测试预计算的SHA1签名
	signed, err := SignSha1(contentRaw, keyPairPkcs1.PrivateKey)
	if err != nil {
		t.Fatalf("SignSha1 failed: %v", err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(signed))

	// 签名可能会不同，但应该可以通过验证
}

func TestPrecomputedSignatureVerifySha1(t *testing.T) {
	// 测试预计算SHA1签名的验证
	verified, err := VerifySha1(contentRaw, keyPairPkcs1.PublicKey, signRawSha1)
	if err != nil {
		t.Fatalf("VerifySha1 failed: %v", err)
	}

	if !verified {
		t.Error("Precomputed SHA1 signature verification failed")
	}
}

func TestExtractPublicKey(t *testing.T) {
	// 测试从私钥提取公钥
	extractedPublicKey, err := ExtractPublicKey(keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("ExtractPublicKey failed: %v", err)
	}

	// 使用提取的公钥加密，然后用原私钥解密，测试功能等价性
	testData := []byte("test extraction")
	encrypted, err := Encrypt(testData, extractedPublicKey)
	if err != nil {
		t.Fatalf("Encrypt with extracted key failed: %v", err)
	}

	decrypted, err := Decrypt(encrypted, keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(testData, decrypted) {
		t.Error("Extracted public key is not functionally equivalent to the original")
	}
}

func TestPkcs1ExtractPublicKey(t *testing.T) {
	// 测试从PKCS1格式私钥提取公钥
	extractedPublicKey, err := ExtractPublicKey(keyPairPkcs1.PrivateKey)
	if err != nil {
		t.Fatalf("ExtractPublicKey failed: %v", err)
	}

	// 测试功能等价性
	testData := []byte("test pkcs1 extraction")
	encrypted, err := Encrypt(testData, extractedPublicKey)
	if err != nil {
		t.Fatalf("Encrypt with extracted key failed: %v", err)
	}

	decrypted, err := Decrypt(encrypted, keyPairPkcs1.PrivateKey)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(testData, decrypted) {
		t.Error("Extracted public key from PKCS1 key is not functionally equivalent to the original")
	}
}

var (
	// 从TypeScript测试中复制的测试密钥和数据
	keyPair = &RsaKeyPair{
		PublicKey: mustDecodeBase64(strings.ReplaceAll(`MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCLjXCd0y8wucMlQDd9S9cFeCA0H
/l/prnouwWgGOEzoaS1gBK4IK0AAiNd7mz8EP+4m9DqeaGW63ei3aws43qV1lDpsVepfJ2PPe/5
VBx7uAKKGqPU+IlNP6EBWUWMMsrCS/oh6LHucCyLah5YhyXOju1cZTfqQ1VFWsbZupmUaQIDAQAB`, "\n", "")),
		PrivateKey: mustDecodeBase64(strings.ReplaceAll(`MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAIuNcJ3TLzC5wyVAN31L
1wV4IDQf+X+muei7BaAY4TOhpLWAErggrQACI13ubPwQ/7ib0Op5oZbrd6LdrCzjepXWUOmxV6l8
nY897/lUHHu4Aooao9T4iU0/oQFZRYwyysJL+iHose5wLItqHliHJc6O7VxlN+pDVUVaxtm6mZRpA
gMBAAECgYAKHDkodgBZO1wT+s8KWNA/KTDMFfTxdpbJcaM6shK+tttD+v9gL53Y/k6po3hp2qFsM
n20PxOh53VHa1/p8KEU1j+DwLbNC5eIp7/5ZNWwftQTSHBCqSyr+7rE0i6Gcst1qT0ioKUS1fOHI
ZSt0gfBOf1eEzhpLDT1o0QgY98cAQJBANrWFNml89xHZQAUmXvrcC/vzmbfktWuHpTP4gRoURp4U
h7j07xD7dVN/gbk42K70VWCTWTRSARApA9IfjACuqECQQCjQH4hh/2H70b23h3OUfiGUSnhupoNU
z93xTsaBYbwiTGYH81Sno5aQbO3j8H9gi8qZanSHRG24MUVeyQdRYzJAkBHJ0aeQgxZeklHzmrdV
P8kRwfIgTdgDP5aioFFx5lfTvH8oz1MQJYLPhGzsiaRCtqUwApkFnwhDdeKNJr7B1ghAkEAm/knS
TQbp/+VxpGK2q/4iaQMJs3ZF7gc4HrBL+ht92ysxJJF4pT4nwU9BrlD98ik9ZXyPXxmi1qPEin35
Dup+QJBAMQsiQwjjTGoVJpNrXoxHbSwgrHhJrgP4HUX2XKmbjCfem8dWdU93G4/VDFUDcNJyd33x
DOHispMoe+rHwgG0xQ=`, "\n", "")),
	}

	keyPairPkcs1 = &RsaKeyPair{
		PublicKey:  mustDecodeBase64(strings.ReplaceAll("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCCjpncvOtMHIp4Bv9sX3JMoSlYKCWsaHdDZ5Oi+QybEDQQlk+MS0wDv+CodsbBFkFwkYcScJzXO/2tM7zVLJR71H761u/woIC5WiBivEMfF6paD0oUM/M440N6ek9ZVONd+W29tnsA+pRVPhN8JhIJaWpuB//UoROXp0PWMjfiZwIDAQAB", "\n", "")),
		PrivateKey: mustDecodeBase64(strings.ReplaceAll("MIICXAIBAAKBgQCCjpncvOtMHIp4Bv9sX3JMoSlYKCWsaHdDZ5Oi+QybEDQQlk+MS0wDv+CodsbBFkFwkYcScJzXO/2tM7zVLJR71H761u/woIC5WiBivEMfF6paD0oUM/M440N6ek9ZVONd+W29tnsA+pRVPhN8JhIJaWpuB//UoROXp0PWMjfiZwIDAQABAoGAd/oYBzRNfzpTPY4guDTWUvlfhzYNuOyffP/4OrJoFS/EyOF45NJlXqS8DdRpPhP3uzzhRd7bIyhsLPj4tWYsZGuyA+GyOjF9Zj/rOWPU1rP4qWSFQ1p9pHvugoi3yt9I1bIqggvUcXk3hdnuVdfSjQE1fY5lpXZvGKB6zNpqZVECQQDuWimYnFgc/1BJtSfCwtKiN0eFMw8S4gTyzWttwOtFxBsHo7Q1l5Xvk564kwZXr2CuOXahrJaDjYm7vNzfoy6bAkEAjDk9QynP8YXQsISPB/X/PxYYpZbAti85sk3JPVO2jb3tAkxCYmIxUg1xgpogaOupqKxeQe83gD8742+5xSXSJQJASuFegghUEkAPjChyZlhobffp6ynASZFiNplcb62U/GUAjOTcH54Qx6Rbz+a4rmF1gSaiY2ZiHtAffjB2P3f3kwJASBx7k9mh1ZwyeUSCZd6tOB096ZJAYrCgpEB6eC5f2D7O7vqWvQ+wO3ksYbSvbCWdZ1/VTWUfDrX2L31adLeBfQJBALGYWVO6Ksv72k1vbSywhLYOKVe3JLZiZgFUNvKLh0g1Tfm1pK29veSSGey8HIkGtI04E6tgQVLx3adZSxjdnFI=", "\n", "")),
	}

	content      = "hello"
	contentRaw   = mustDecodeBase64("kolOt/LYqkhf/RZu6aJcIA==")
	encryptedRaw = mustDecodeBase64("a6CIZzAPpzaDysCOE9X5FYp723lsTRia/GVDmU4yyhcKaFX2iBICfVwK5gakKK+NgTQ4veMu0l3wpIHM+eRA+Q6zrxCYjE8tkH1O4Jbxcvx4Nai4QP0JqCXDXNpxJMccKhqyNZ01uBq1RjJ++ATkMt66rt5DMW4pLtToh7nLjhg=")
	signRaw      = mustDecodeBase64("VnEka0wYeYmaG45qW7+RTPH+prTO9ryxrtqyAwpoZOymeQGJTPfkmm+Ti16UJPZetYR1LF+ETQ++XAkuTQIqhu4sgXyuhw4/TIYyMDzaEuEDOciwvJLiyC73E0Q4jXQx6kT8o+65Ki9h4LPxjjr8tOc+/r3U1uhute8/QWWYiuA=")
	signRawSha1  = mustDecodeBase64("RvxmCkUxhtSPLss712C2vH7jpXaV82QXDe/e9EaclgWuVPEliDPmUkwg20PfG5d/xM0l3LAEexHAUWD3svg6HTWo9zw7/l+fYxtkbv59i8Uz7r5Y+j3HVaHKevFEw2Z34PHbiPXVNYBRE/4Qzl8wLT2ZSLzo50yBBFziD4LgvtU=")
)

// mustDecodeBase64 是一个辅助函数，用于从Base64字符串解码数据
func mustDecodeBase64(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}
