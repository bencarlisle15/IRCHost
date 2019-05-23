package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
)

var BlockSize = 16

func DecryptMessage(encryptedMessage Message, privateKey *rsa.PrivateKey) Message {
	var message Message
	message.User = string(DecryptRSA(encryptedMessage.User, privateKey))
	message.Mac = string(DecryptRSA(encryptedMessage.Mac, privateKey))
	message.IV = string(DecryptRSA(encryptedMessage.IV, privateKey))
	message.AESKey = string(DecryptRSA(encryptedMessage.AESKey, privateKey))
	message.MACKey = string(DecryptRSA(encryptedMessage.MACKey, privateKey))
	signature, _ := base64.StdEncoding.DecodeString(encryptedMessage.Signature)
	message.Signature = string(signature)
	message.Data = encryptedMessage.Data
	return message
}

func GetRandomBytes(length int) []byte {
	randomBytes := make([]byte, length)
	_, _ = io.ReadFull(rand.Reader, randomBytes)
	return randomBytes
}

func GenerateNonce() string {
	return string(GetRandomBytes(4096))
}

func EncryptRSA(publicKeyBytes, data []byte) string {
	publicKey := GetPublicKeyFromBytes(publicKeyBytes)
	if publicKey == nil || data == nil {
		return ""
	}
	ciphertext, _ := rsa.EncryptOAEP(sha512.New(), rand.Reader, publicKey, data, nil)
	if ciphertext == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func GetPrivateKey() *rsa.PrivateKey {
	privatePEM, _ := ioutil.ReadFile("PrivateKey.pem")
	if privatePEM == nil {
		return nil
	}
	block, _ := pem.Decode([]byte(privatePEM))
	if block == nil {
		return nil
	}
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	return privateKey
}

func DecryptAESMACMessage(ciphertext []byte, aesKey []byte, macKey []byte, iv []byte, mac []byte) []byte {
	if !ValidMac(mac, ciphertext, macKey) {
		return nil
	}
	return DecryptAESMessage(ciphertext, aesKey, iv)
}

func DecryptAESMessage(data []byte, aesKey []byte, iv []byte) []byte {
	if data == nil || aesKey == nil || iv == nil {
		return nil
	}
	block, _ := aes.NewCipher(aesKey)
	ciphertext, _ := base64.StdEncoding.DecodeString(string(data))
	if block == nil || len(ciphertext) % aes.BlockSize != 0 {
		return nil
	}
	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	if mode == nil {
		return nil
	}
	mode.CryptBlocks(ciphertext, ciphertext)
	return TrimPadding(ciphertext)
}

func ValidMac(messageMac []byte, ciphertext []byte, key []byte) bool {
	if messageMac == nil || ciphertext == nil || key == nil {
		return false
	}
	mac := hmac.New(sha512.New, key)
	if mac == nil {
		return false
	}
	mac.Write(ciphertext)
	expectedMAC := mac.Sum(nil)
	if expectedMAC == nil {
		return false
	}
	return hmac.Equal(messageMac, expectedMAC)
}

func TrimPadding(plaintext []byte) []byte {
	if plaintext == nil || len(plaintext) == 0 || len(plaintext) % aes.BlockSize != 0 {
		return nil
	}
	padding := plaintext[len(plaintext) - 1]
	if len(plaintext) < int(padding) || padding < 0 || padding > aes.BlockSize{
		return nil
	}
	paddingStart := len(plaintext) - int(padding)
	validPadding := true
	for i := paddingStart; i < len(plaintext); i++ {
		if plaintext[i] != padding {
			validPadding = false
			break
		}
	}
	if !validPadding {
		return nil
	}
	return plaintext[:paddingStart]
}

func DecryptRSA(message string, privateKey *rsa.PrivateKey) string {
	decodedMessage, _ := base64.StdEncoding.DecodeString(message)
	if decodedMessage == nil || privateKey == nil {
		fmt.Println("ERROR")
		return ""
	}
	plaintext, _ := rsa.DecryptOAEP(sha512.New(), rand.Reader, privateKey, decodedMessage, nil)
	if plaintext == nil {
		return ""
	}
	return string(plaintext)
}

func GetPublicKeyFromBytes(publicKeyBytes []byte) *rsa.PublicKey {
	if publicKeyBytes == nil {
		return nil
	}
	publicKeyInterface, _ := x509.ParsePKIXPublicKey(publicKeyBytes)
	if publicKeyInterface == nil {
		return nil
	}
	publicKey, _ := publicKeyInterface.(*rsa.PublicKey)
	return publicKey
}

func GenerateSessionID() []byte {
	return GetRandomBytes(64)
}

func GenerateSalt() []byte {
	return GetRandomBytes(64)
}

func GetIV() []byte {
	return GetRandomBytes(16)
}

func Sign(privateKey *rsa.PrivateKey, message []byte) []byte {
	if privateKey == nil || message == nil {
		return nil
	}
	hashed := GetHash(message)
	if hashed == nil {
		return nil
	}
	signature, _ := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA512, hashed[:], nil)
	return signature
}

func VerifySignature(publicKeyBytes []byte, signature []byte, message []byte) bool {
	if publicKeyBytes == nil || signature == nil || message == nil {
		return false
	}
	publicKey := GetPublicKeyFromBytes(publicKeyBytes)
	if publicKey == nil {
		return false
	}
	hashed := GetHash(message)
	if hashed == nil {
		return false
	}
	return rsa.VerifyPSS(publicKey, crypto.SHA512, hashed[:], signature, nil) == nil
}

func EncryptAES(plaintext []byte, aesKey []byte) ([]byte, []byte) {
	if aesKey == nil || plaintext == nil {
		return nil, nil
	}
	block, _ := aes.NewCipher(aesKey)
	if block == nil {
		return nil, nil
	}
	paddedPlaintext := PadPlaintext(plaintext)
	if paddedPlaintext == nil {
		return nil,nil
	}
	ciphertext := make([]byte, len(paddedPlaintext))
	iv := GetIV()
	if iv == nil {
		return nil, nil
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	if mode == nil {
		return nil,nil
	}
	mode.CryptBlocks(ciphertext, paddedPlaintext)
	return ciphertext, iv
}

func CreateAESKey() []byte {
	aesKey := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, aesKey)
	return aesKey
}

func PadPlaintext(plaintext []byte) []byte {
	if plaintext == nil {
		return nil
	}
	paddingNeeded := BlockSize - (len(plaintext) % BlockSize)
	if paddingNeeded == 0 {
		paddingNeeded = BlockSize
	}
	for i := 0; i < paddingNeeded; i++ {
		plaintext = append(plaintext, byte(paddingNeeded))
	}
	return plaintext
}

func HashPassword(password string, salt []byte) []byte {
	if salt == nil {
		return nil
	}
	salted := []byte(password)
	for i := 0; i < len(salt); i++ {
		salted = append(salted, salt[i])
	}
	return GetHash(salted)
}

func EqualBytes(byte1, byte2 []byte) bool {
	if byte1 == nil || byte2 == nil || len(byte1) != len(byte2) {
		return false
	}
	for i := 0; i < len(byte1); i++ {
		if byte1[i] != byte2[i] {
			return false
		}
	}
	return true
}

func GetHash(toHash []byte) []byte {
	if toHash == nil {
		return nil
	}
	hash := sha512.New()
	hash.Write(toHash)
	return hash.Sum(nil)
}