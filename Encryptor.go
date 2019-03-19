package main

import (
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

var MacSize = 64
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

func DecryptAESMessage(message Message, aesKey []byte, macKey []byte) []byte {
	ciphertext := []byte(message.Data)
	if !ValidMac([]byte(message.Mac), ciphertext, macKey) {
		return nil
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil
	}
	if len(ciphertext) % aes.BlockSize != 0 {
		return nil
	}
	mode := cipher.NewCBCDecrypter(block, []byte(message.IV))
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

func EncryptAES(plaintext []byte, aesKey []byte, macKey []byte) []byte {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil
	}
	paddedPlaintext := PadPlaintext(plaintext)
	ciphertextTotal := make([]byte, MacSize + BlockSize + len(paddedPlaintext))
	ciphertext := make([]byte, len(paddedPlaintext))
	iv := make([]byte, BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedPlaintext)
	mac := GetMac(ciphertext, macKey)
	_ = copy(ciphertextTotal[0:MacSize], mac)
	_ = copy(ciphertextTotal[MacSize: MacSize + BlockSize], iv)
	_ = copy(ciphertextTotal[MacSize + BlockSize:], ciphertext)
	return ciphertextTotal
}

func GetMac(ciphertext, key []byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(ciphertext)
	return mac.Sum(nil)
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