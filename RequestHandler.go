package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"io"
)

func RequestHandler(response []byte, privateKey *rsa.PrivateKey) []byte {
	var message Message
	var err = json.Unmarshal(response, &message)
	var toWrite = []byte("An error occurred")
	if err != nil {
		//todo error occurred
	}
	if IsValidKey(message) {
		toWrite = MessageHandler(message, privateKey, true)
	} else if IsValidUser(message) {
		toWrite = MessageHandler(message, privateKey, false)
	} else {
		//todo error occurred
	}
	return toWrite
}

func MessageHandler(message Message, privateKey *rsa.PrivateKey, isKey bool) []byte {
	var aesKey = GetAESKey(message, privateKey, isKey)
	var macKey = GetMACKey(message, privateKey, isKey)
	var data = DecryptAESMessage(message, aesKey, macKey)
	var innerMessage InnerMessage
	var err = json.Unmarshal(data, &innerMessage)
	if err != nil {
		//todo error occurred
	}
	var toWrite = []byte("An error occurred")
	if IsValidSignIn(innerMessage) {
		if innerMessage.MessageType == "register" {
			toWrite = RegisterUser(innerMessage, aesKey, macKey)
		} else if innerMessage.MessageType == "login" {
			toWrite = LoginUser(innerMessage)
		}
	} else if IsValidRequest(innerMessage) {
		toWrite = SendRequest(innerMessage)
	} else {
		//todo error occurred
	}
	return toWrite
}

func GetMACKey(message Message, privateKey *rsa.PrivateKey, isKey bool) []byte {
	var key []byte
	if isKey {
		key = DecryptRSA(message.MACKey, privateKey)
	} else {
		var user = DecryptRSA(message.User, privateKey )
		key = GetUserMACKey(user)
	}
	return key}

func GetAESKey(message Message, privateKey *rsa.PrivateKey, isKey bool) []byte {
	var key []byte
	if isKey {
		key = DecryptRSA(message.AESKey, privateKey)
	} else {
		var user = DecryptRSA(message.User, privateKey )
		key = GetUserAESKey(user)
	}
	return key
}

func RegisterUser(message InnerMessage, aesKey []byte, macKey []byte) []byte {
	var response Response
	salt := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		//todo error occurred
	} else {
		salted := saltPassword(message.Password, salt)
		hash := sha512.New()
		hash.Write(salted)
		hashedPassword := hash.Sum(nil)
		if AddUser(message.User, hashedPassword) {
			response.Status = 201
			response.Message = "You are now registered"
		} else {
			response.Status = 409
			response.Message = "That username already exists, try another"
		}
	}
	toWrite, err := json.Marshal(response)
	if err != nil {
		//todo error occurred
		return nil
	}
	ciphertext := EncryptAES(toWrite, aesKey, macKey)
	encodedCiphertext := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
	base64.StdEncoding.Encode(encodedCiphertext, []byte(ciphertext))
	return encodedCiphertext
}

func saltPassword(password string, salt []byte) []byte {
	passwordBytes := []byte(password)
	for i := 0; i < len(salt); i++ {
		passwordBytes = append(passwordBytes, salt[i])
	}
	return passwordBytes
}


func LoginUser(message InnerMessage) []byte {
	//todo handle request
	return nil
}

func SendRequest(message InnerMessage) []byte {
	//todo handle request
	return nil
}
