package main

type Message struct {
	User string `json:"user"`
	AESKey string `json:"aesKey"`
	MACKey string `json:"macKey"`
	IV string `json:"iv"`
	Mac string `json:"mac"`
	Signature string `json:"signature"`
	Data string `json:"data"`
}

type InnerMessage struct {
	MessageType string `json:"messageType"`
	Nonce string `json:"nonce"`
	To string `json:"to"`
	Password string `json:"password"`
	Message string `json:"message"`
	IsFile bool `json:"isFile"`
	SessionId string `json:"sessionId"`
	PublicKey string `json:"publicKey"`
}

type Response struct {
	IV string `json:"iv"`
	Signature string `json:"signature"`
	Data string `json:"data"`
}

type InnerResponse struct {
	Status int `json:"status"`
	Nonce string `json:"nonce"`
	Message string `json:"message"`
	SessionId string `json:"sessionId"`
	PublicKey string `json:"publicKey"`
}

type Sendable struct {
	Status int `json:"status"`
	Nonce string `json:"nonce"`
	Receiver string `json:"receiver"`
	Sender string `json:"sender"`
	Message string `json:"message"`
	IsFile bool `json:"isFile"`
}