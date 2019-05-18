package main

func IsValidRegisterMessage(message Message) bool {
	return message.User != "" && message.AESKey != "" && message.MACKey != "" && message.IV != "" && message.Mac != "" && message.Signature == "" && message.Data != ""
}

func IsValidLoggedMessage(message Message) bool {
	return message.User != "" && message.AESKey == "" && message.MACKey == "" && message.IV != "" && message.Mac != "" && message.Signature != "" && message.Data != ""
}

func IsValidRegister(message InnerMessage) bool {
	return message.MessageType == "register" && message.Nonce != "" && message.To == "" && message.Password != "" && message.SessionId == "" && message.Message == "" && message.PublicKey != ""
}

func IsValidLogIn(message InnerMessage) bool {
	return message.MessageType == "login" && message.Nonce != "" && message.To == "" && message.Password != "" && message.SessionId == "" && message.Message == "" && message.PublicKey == ""
}

func IsValidRequest(message InnerMessage) bool {
	return message.MessageType == "sendMessage" && message.Nonce != "" && message.To != "" && message.Password == "" && message.SessionId != "" && message.Message != "" && message.PublicKey == ""
}

func isValidUserQuery(message InnerMessage) bool {
	return message.MessageType == "queryUser" && message.Nonce != "" && message.To != "" && message.Password == "" && message.SessionId != "" && message.Message == "" && message.PublicKey == ""
}

func IsValidPing(message InnerMessage) bool {
	return message.MessageType == "ping" && message.Nonce != "" && message.To == "" && message.Password == "" && message.SessionId != "" && message.Message == "" && message.PublicKey == ""
}
