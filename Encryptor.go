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
	data, _ := base64.StdEncoding.DecodeString(encryptedMessage.Data)
	message.Data = string(data)
	return message
}

func GetPrivateKey() *rsa.PrivateKey {
	privatePEM, _ := ioutil.ReadFile("PrivateKey.pem")
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

func DecryptAESMessage(ciphertext []byte, aesKey []byte, iv []byte) []byte {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil
	}
	if len(ciphertext) % aes.BlockSize != 0 {
		return nil
	}
	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, ciphertext)
	return TrimPadding(ciphertext)
}

func ValidMac(messageMac []byte, ciphertext []byte, key []byte) bool {
	mac := hmac.New(sha512.New, key)
	mac.Write(ciphertext)
	expectedMAC := mac.Sum(nil)
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
		}
	}
	if !validPadding {
		return nil
	}
	return plaintext[:paddingStart]
}

func DecryptRSA(message string, privateKey *rsa.PrivateKey) []byte {
	decodedMessage, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return nil
	}
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, decodedMessage)
	if err != nil {
		return nil
	}
	return plaintext
}

func GetIV() []byte {
	iv := make([]byte, BlockSize)
	_, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil
	}
	return iv
}

func Sign(privateKey *rsa.PrivateKey, message []byte) []byte {
	hashed := GetHash(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, hashed[:])
	if err != nil {
		return signature
	} else {
		return nil
	}
}

func VerifySignature(publicKeyBytes []byte, signature []byte, message []byte) bool {
	publicKey, err := x509.ParsePKCS1PublicKey(publicKeyBytes)
	if err == nil {
		return false
	}
	hashed := GetHash(message)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA512, hashed[:], signature) != nil
}

func EncryptAES(plaintext []byte, aesKey []byte) ([]byte, []byte) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil
	}
	paddedPlaintext := PadPlaintext(plaintext)
	ciphertext := make([]byte, len(paddedPlaintext))
	iv := GetIV()
	if iv == nil {
		return nil, nil
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedPlaintext)
	return ciphertext, iv
}

func PadPlaintext(plaintext []byte) []byte {
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
	salted := []byte(password)
	for i := 0; i < len(salt); i++ {
		salted = append(salted, salt[i])
	}
	return GetHash(salted)
}

func EqualBytes(byte1, byte2 []byte) bool {
	if len(byte1) != len(byte2) {
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
	hash := sha512.New()
	hash.Write(toHash)
	return hash.Sum(nil)
}