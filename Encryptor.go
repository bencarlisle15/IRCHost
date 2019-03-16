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

func GetPrivateKey() *rsa.PrivateKey {
	privatePEM, err := ioutil.ReadFile("PrivateKey.pem")
	if err != nil {
		return nil
	}
	block, _ := pem.Decode([]byte(privatePEM))
	if block == nil {
		//todo error occurred
		return nil
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		//todo error occurred
		return nil
	}

	return privateKey
}

func DecryptAESMessage(message Message, aesKey []byte, macKey []byte) []byte {
	//todo padding oracle
	ciphertext, err := base64.StdEncoding.DecodeString(message.Data)
	if err != nil {
		//todo error occurred
		return nil
	}
	mac, err := base64.StdEncoding.DecodeString(message.Mac)
	if err != nil {
		//todo error occurred
		return nil
	}
	iv, err := base64.StdEncoding.DecodeString(message.IV)
	if err != nil {
		//todo error occurred
		return nil
	}
	if !validMac(mac, ciphertext, macKey) {
		//todo invalid mac
		return nil
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		//todo error occurred
		return nil
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		//todo error occurred
		return nil
	}

	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, ciphertext)
	plaintext := TrimPadding(ciphertext)
	return plaintext
}

func validMac(messageMac []byte, ciphertext []byte, key []byte) bool {
	mac := hmac.New(sha512.New, key)
	mac.Write(ciphertext)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMac, expectedMAC)
}

func TrimPadding(plaintext []byte) []byte {
	if plaintext == nil || len(plaintext) == 0 || len(plaintext) % aes.BlockSize != 0 {
		//todo padding error
		return nil
	}
	padding := plaintext[len(plaintext) - 1]
	if len(plaintext) < int(padding) || padding < 0 || padding > aes.BlockSize{
		//todo padding error
		return nil
	}
	paddingStart := len(plaintext) - int(padding)
	for i := paddingStart; i < len(plaintext); i++ {
		if plaintext[i] != padding {
			//todo padding error
			return nil
		}
	}
	return plaintext[:paddingStart]
}

func DecryptRSA(message string, privateKey *rsa.PrivateKey) []byte {
	decodedMessage, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		//todo error occurred
		return nil
	}
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, decodedMessage)
	if err != nil {
		//todo error occurred
		return nil
	}
	return plaintext
}

func EncryptAES(plaintext []byte, aesKey []byte, macKey []byte) []byte {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		//todo error occurred
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
	mac := getMac(ciphertext, macKey)
	_ = copy(ciphertextTotal[0:MacSize], mac);
	_ = copy(ciphertextTotal[MacSize: MacSize + BlockSize], iv)
	_ = copy(ciphertextTotal[MacSize + BlockSize:], ciphertext)
	return ciphertextTotal
}

func getMac(ciphertext, key []byte) []byte {
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