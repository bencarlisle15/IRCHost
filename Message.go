package main

type Message struct {
	User string `json:"user"`
	AESKey string `json:"aesKey"`
	MACKey string `json:"macKey"`
	IV string `json:"iv"`
	Mac string `json:"mac"`
	Data string `json:"data"`
}

type InnerMessage struct {
	MessageType string `json:"messageType"`
	User string `json:"user"`
	Password string `json:"password"`
	From string `json:"from"`
	To string `json:"to"`
	Message string `json:"message"`
	SessionId string `json:"sessionId"`
}

type Response struct {
	Status int `json:"status"`
	Message string `json:"message"`
}

type LoginResponse struct {
	Status int `json:"status"`
	Message string `json:"message"`
	SessionId string `json:"sessionId"`
}