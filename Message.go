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
	To string `json:"to"`
	Message string `json:"message"`
	IsFile bool `json:"isFile"`
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

type Sendable struct {
	Status int `json:"status"`
	Receiver string `json:"receiver"`
	Sender string `json:"sender"`
	Message string `json:"message"`
	IsFile bool `json:"isFile"`
}