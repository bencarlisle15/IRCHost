package main

func IsValidKey(message Message) bool {
	return message.User != "" && message.AESKey != "" && message.MACKey != "" && message.IV != "" && message.Mac != "" && message.Data != ""
}

func IsValidUser(message Message) bool {
	return message.User != "" && message.AESKey == "" && message.MACKey == "" && message.IV != "" && message.Mac != "" && message.Data != ""
}

func IsValidSignIn(message InnerMessage) bool {
	return (message.MessageType == "register" || message.MessageType == "login") && message.User != "" && message.Password != "" && message.To == "" && message.Message == "" && message.SessionId == ""
}

func IsValidRequest(message InnerMessage) bool {
	return message.MessageType == "sendMessage" && message.User == "" && message.Password == "" && message.To != "" && message.Message != "" && message.SessionId != ""

}

func IsValidPing(message InnerMessage) bool {
	return message.MessageType == "ping" && message.User == "" && message.Password == "" && message.To == "" && message.Message == "" && message.SessionId != ""
}
