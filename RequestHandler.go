package main

import (
	"crypto/rand"
	"crypto/rsa"
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
	if IsValidRegisterMessage(message) {
		toWrite = RegisterMessageHandler(message, privateKey)
	} else if IsValidLoggedMessage(message) {
		toWrite = LoggedMessageHandler(message, privateKey)
	} else {
		//todo error occurred
	}
	return toWrite
}

func RegisterMessageHandler(encryptedMessage Message, privateKey *rsa.PrivateKey) []byte {
	message := DecryptMessage(encryptedMessage, privateKey)
	aesKey := []byte(message.AESKey)
	macKey := []byte(message.MACKey)
	iv := []byte(message.IV)
	mac := []byte(message.Mac)
	data := DecryptAESMACMessage([]byte(message.Data), aesKey, macKey, iv, mac)
	var innerMessage InnerMessage
	var err = json.Unmarshal(data, &innerMessage)
	var toWrite []byte
	if err == nil && IsValidRegister(innerMessage) {
		toWrite = RegisterUser(innerMessage, message.User)
	} else {
		var innerResponse InnerResponse
		innerResponse.Status = 415
		innerResponse.Message = "Incorrectly labeled"
		return InnerResponseToString(innerResponse)
	}
	newAESKey := CreateAESKey()
	ciphertext, responseIV := EncryptAES(toWrite, newAESKey)
	if ciphertext == nil {
		//todo
		return nil
	}
	signature := Sign(privateKey, ciphertext)
	//todo check
	publicKeyBytes, err := base64.StdEncoding.DecodeString(innerMessage.PublicKey)
	//todo invalid public key
	var response Response
	response.AESKey = EncryptRSA(publicKeyBytes, newAESKey)
	response.IV = EncryptRSA(publicKeyBytes, responseIV)
	response.Signature = base64.StdEncoding.EncodeToString(signature)
	response.Data = base64.StdEncoding.EncodeToString(ciphertext)
	return ResponseToString(response)
}

func LoggedMessageHandler(encryptedMessage Message, privateKey *rsa.PrivateKey) []byte {
	message := DecryptMessage(encryptedMessage, privateKey)
	userDataResults := GetUserData(message.User)
	var userData UserData
	if len(userDataResults) == 0 {
		var innerResponse InnerResponse
		innerResponse.Status = 403
		innerResponse.Message = "User does not exist"
		return InnerResponseToString(innerResponse)
	} else if len(userDataResults) > 1 {
		var innerResponse InnerResponse
		innerResponse.Status = 423
		innerResponse.Message = "Account deleted as for security protocol"
		return InnerResponseToString(innerResponse)
	}
	userData = userDataResults[0]
	publicKeyBytes, err := base64.StdEncoding.DecodeString(userData.PublicKey)
	if err != nil {
		return nil
	}
	if !VerifySignature(publicKeyBytes, []byte(message.Signature), []byte(message.Data)) {
		//todo invalid signature
		return nil
	}
	aesKey := []byte(message.AESKey)
	iv := []byte(message.IV)
	var data = DecryptAESMessage([]byte(message.Data), aesKey, iv)
	var innerMessage InnerMessage
	err = json.Unmarshal(data, &innerMessage)
	var toWrite []byte
	if err == nil && IsValidLogIn(innerMessage) {
		toWrite = LoginUser(innerMessage, userData)
	} else if err == nil && IsValidRequest(innerMessage) {
		toWrite = SendRequest(innerMessage, userData)
	} else if err == nil && isValidUserQuery(innerMessage) {
		toWrite = SendUserQuery(innerMessage, userData)
	} else if err == nil && IsValidPing(innerMessage) {
		toWrite = Ping(innerMessage, userData)
	} else {
		var innerResponse InnerResponse
		innerResponse.Status = 415
		innerResponse.Message = "Incorrectly labeled"
		return InnerResponseToString(innerResponse)
	}
	newAESKey := CreateAESKey()
	ciphertext, responseIV := EncryptAES(toWrite, newAESKey)
	if ciphertext == nil {
		//todo
		return nil
	}
	encodedCiphertext := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
	base64.StdEncoding.Encode(encodedCiphertext, []byte(ciphertext))
	signature := Sign(privateKey, encodedCiphertext)
	//todo check
	var response Response
	response.AESKey = EncryptRSA(publicKeyBytes, newAESKey)
	response.IV = EncryptRSA(publicKeyBytes, responseIV)
	response.Signature = base64.StdEncoding.EncodeToString(signature)
	response.Data = base64.StdEncoding.EncodeToString(ciphertext)
	return ResponseToString(response)
}

//func PrintMessage(message Message) string {
//	return "User: " + message.User + "\nIV: " + message.IV + "\nMAC: " + message.Mac + "\nAESKey: " + message.AESKey + "\nMACKey: " + message.MACKey + "\nData: " + message.Data
//}

func RegisterUser(message InnerMessage, user string) []byte {
	//todo check nonce
	var innerResponse InnerResponse
	salt := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		//todo error occurred
		return []byte("An error occurred")
	}
	hashedPassword := HashPassword(message.Password, salt)
	if AddUser(user, hashedPassword, salt, []byte(message.PublicKey)) {
		innerResponse.Status = 201
		innerResponse.Message = "You are now registered"
	} else {
		innerResponse.Status = 409
		innerResponse.Message = "That username already exists, try another"
	}
	return InnerResponseToString(innerResponse)
}

func LoginUser(message InnerMessage, userData UserData) []byte {
	//todo check nonce
	hashed := HashPassword(message.Password, []byte(userData.Salt))
	if !EqualBytes(hashed, []byte(userData.Hash)) {
		var innerResponse InnerResponse
		innerResponse.Status = 401
		innerResponse.Message = "Incorrect username or password"
		return InnerResponseToString(innerResponse)
	}
	sessionIDBytes := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, sessionIDBytes)
	sessionID := base64.StdEncoding.EncodeToString(sessionIDBytes)
	if err != nil {
		//todo error occurred
		return nil
	}
	var loginResponse InnerResponse
	loginResponse.SessionId = string(sessionID)
	if !AddSessionID(userData.User, sessionID) {
		loginResponse.Status = 423
		loginResponse.Message = "Account deleted as for security protocol"
	} else {
		loginResponse.Status = 202
		loginResponse.Message = "You have successfully logged in"
	}
	return InnerResponseToString(loginResponse)
}

func InnerResponseToString(innerResponse InnerResponse) []byte {
	toWrite, err := json.Marshal(innerResponse)
	if err != nil {
		//todo error occurred
		return nil
	}
	return toWrite
}

func ResponseToString(response Response) []byte {
	toWrite, err := json.Marshal(response)
	if err != nil {
		//todo error occurred
		return nil
	}
	return toWrite
}

func SendRequest(message InnerMessage, userData UserData) []byte {
	//todo check and send nonce
	sessions := GetSessions(userData.User)
	switch len(sessions) {
	case 0:
		var innerResponse InnerResponse
		innerResponse.Status = 403
		innerResponse.Message = "You are not currently authenticated"
		return InnerResponseToString(innerResponse)
	case 1:
		if sessions[0] == message.SessionId {
			break
		}
		//intentionally goes to default
	default:
		var innerResponse InnerResponse
		innerResponse.Status = 423
		innerResponse.Message = "Account deleted as for security protocol"
		//todo delete account
		return InnerResponseToString(innerResponse)
	}
	AddMessage(message.To, userData.User, message.Message, message.IsFile)
	var innerResponse InnerResponse
	innerResponse.Status = 200
	innerResponse.Message = "Message successfully sent"
	return InnerResponseToString(innerResponse)
}

func SendUserQuery(message InnerMessage, userData UserData) []byte {
	//todo check and send nonce
	sessions := GetSessions(userData.User)
	switch len(sessions) {
	case 0:
		var innerResponse InnerResponse
		innerResponse.Status = 403
		innerResponse.Message = "You are not currently authenticated"
		return InnerResponseToString(innerResponse)
	case 1:
		if sessions[0] == message.SessionId {
			break
		}
		//intentionally goes to default
	default:
		var innerResponse InnerResponse
		innerResponse.Status = 423
		innerResponse.Message = "Account deleted as for security protocol"
		//todo delete account
		return InnerResponseToString(innerResponse)
	}
	publicKey := GetPublicKey(message.To)
	var innerResponse InnerResponse
	if len(publicKey) == 0 {
		innerResponse.Status = 404
		innerResponse.Message = "User not found"
	}
	innerResponse.Status = 200
	innerResponse.Message = "Public Key Found"
	innerResponse.PublicKey = publicKey
	return InnerResponseToString(innerResponse)
}

func Ping(message InnerMessage, userData UserData) []byte {
	//todo check and send nonce
	sessions := GetSessions(userData.User)
	switch len(sessions) {
	case 0:
		var innerResponse InnerResponse
		innerResponse.Status = 403
		innerResponse.Message = "You are not currently authenticated"
		return InnerResponseToString(innerResponse)
	case 1:
		if sessions[0] == message.SessionId {
			break
		}
		//intentionally goes to default
	default:
		var innerResponse InnerResponse
		innerResponse.Status = 423
		innerResponse.Message = "Account deleted as for security protocol"
		//todo delete account
		return InnerResponseToString(innerResponse)
	}
	UpdateSession(message.SessionId)
	sendable := GetNextMessage(userData.User)
	var toWrite []byte
	if sendable.Sender != "" {
		sendable.Status = 200
		toWrite,_ = json.Marshal(sendable)
	} else {
		var innerResponse InnerResponse
		innerResponse.Status = 100
		innerResponse.Message = "No messages found"
		toWrite = InnerResponseToString(innerResponse)
	}
	return toWrite
}
