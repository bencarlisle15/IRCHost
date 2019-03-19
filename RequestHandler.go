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

func MessageHandler(encryptedMessage Message, privateKey *rsa.PrivateKey, isKey bool) []byte {
	message := DecryptMessage(encryptedMessage, privateKey)
	userDataResults := GetUserData(message.User)
	var userData UserData
	var aesKey, macKey []byte
	if !isKey && len(userDataResults) == 0 {
		var response Response
		response.Status = 403
		response.Message = "User does not exist"
		return responseToString(response)
	} else if len(userDataResults) > 1 {
		var response Response
		response.Status = 423
		response.Message = "Account deleted as for security protocol"
		return responseToString(response)
	} else if isKey {
		aesKey = []byte(message.AESKey)
		macKey = []byte(message.MACKey)
	} else {
		userData = userDataResults[0]
		aesKey = []byte(userData.AESKey)
		macKey = []byte(userData.MACKey)
	}
	var data = DecryptAESMessage(message, aesKey, macKey)
	var innerMessage InnerMessage
	var err = json.Unmarshal(data, &innerMessage)
	var toWrite []byte
	if err == nil && IsValidSignIn(innerMessage) {
		if innerMessage.MessageType == "register" {
			toWrite = RegisterUser(innerMessage, aesKey, macKey)
		} else if innerMessage.MessageType == "login" {
			toWrite = LoginUser(innerMessage, userData)
		}
	} else if err == nil && IsValidRequest(innerMessage) {
		toWrite = SendRequest(innerMessage, userData)
	} else if err == nil && IsValidPing(innerMessage) {
		toWrite = Ping(innerMessage, userData)
	} else {
		var response Response
		response.Status = 415
		response.Message = "Incorrectly labeled"
		toWrite = responseToString(response)
	}
	ciphertext := EncryptAES(toWrite, aesKey, macKey)
	if ciphertext == nil {
		return toWrite
	}
	encodedCiphertext := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
	base64.StdEncoding.Encode(encodedCiphertext, []byte(ciphertext))
	return encodedCiphertext
}

func PrintMessage(message Message) string {
	return "User: " + message.User + "\nIV: " + message.IV + "\nMAC: " + message.Mac + "\nAESKey: " + message.AESKey + "\nMACKey: " + message.MACKey + "\nData: " + message.Data
}

func RegisterUser(message InnerMessage, aesKey []byte, macKey []byte) []byte {
	var response Response
	salt := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		//todo error occurred
		return []byte("An error occurred")
	}
	hashedPassword := hashPassword(message.Password, salt)
	if AddUser(message.User, hashedPassword, salt, aesKey, macKey) {
		response.Status = 201
		response.Message = "You are now registered"
	} else {
		response.Status = 409
		response.Message = "That username already exists, try another"
	}
	return responseToString(response)
}

func hashPassword(password string, salt []byte) []byte {
	salted := []byte(password)
	for i := 0; i < len(salt); i++ {
		salted = append(salted, salt[i])
	}
	hash := sha512.New()
	hash.Write(salted)
	return hash.Sum(nil)
}

func equalBytes(byte1, byte2 []byte) bool {
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


func LoginUser(message InnerMessage, userData UserData) []byte {
	hashed := hashPassword(message.Password, []byte(userData.Salt))
	if !equalBytes(hashed, []byte(userData.Hash)) {
		var response Response
		response.Status = 401
		response.Message = "Incorrect username or password"
		return responseToString(response)
	}
	sessionIDBytes := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, sessionIDBytes)
	sessionID := base64.StdEncoding.EncodeToString(sessionIDBytes)
	if err != nil {
		//todo error occurred
		return nil
	}
	var loginResponse LoginResponse
	loginResponse.SessionId = string(sessionID)
	if !AddSessionID(message.User, sessionID) {
		loginResponse.Status = 423
		loginResponse.Message = "Account deleted as for security protocol"
	} else {
		loginResponse.Status = 202
		loginResponse.Message = "You have successfully logged in"
	}
	toWrite, err := json.Marshal(loginResponse)
	if err != nil {
		//todo error occurred
		return nil
	}
	return toWrite
}

func responseToString(response Response) []byte {
	toWrite, err := json.Marshal(response)
	if err != nil {
		//todo error occurred
		return nil
	}
	return toWrite
}

func SendRequest(message InnerMessage, userData UserData) []byte {
	sessions := GetSessions(userData.User)
	switch len(sessions) {
	case 0:
		var response Response
		response.Status = 403
		response.Message = "You are not currently authenticated"
		return responseToString(response)
	case 1:
		if sessions[0] == message.SessionId {
			break
		}
		//intentionally goes to default
	default:
		var response Response
		response.Status = 423
		response.Message = "Account deleted as for security protocol"
		//todo delete account
		return responseToString(response)
	}
	AddMessage(message.To, userData.User, message.Message, message.IsFile)
	var response Response
	response.Status = 200
	response.Message = "Message successfully sent"
	return responseToString(response)
}

func Ping(message InnerMessage, userData UserData) []byte {
	sessions := GetSessions(userData.User)
	switch len(sessions) {
	case 0:
		var response Response
		response.Status = 403
		response.Message = "You are not currently authenticated"
		return responseToString(response)
	case 1:
		if sessions[0] == message.SessionId {
			break
		}
		//intentionally goes to default
	default:
		var response Response
		response.Status = 423
		response.Message = "Account deleted as for security protocol"
		//todo delete account
		return responseToString(response)
	}
	UpdateSession(message.SessionId)
	sendable := GetNextMessage(userData.User)
	var toWrite []byte
	if sendable.Sender != "" {
		sendable.Status = 200
		toWrite,_ = json.Marshal(sendable)
	} else {
		var response Response
		response.Status = 100
		response.Message = "No messages found"
		toWrite = responseToString(response)
	}
	return toWrite
}
