package main

import (
	"encoding/json"
	"time"
)

func InnerResponseToString(innerResponse InnerResponse) []byte {
	toWrite, err := json.Marshal(innerResponse)
	if err != nil {
		return nil
	}
	return toWrite
}

func ResponseToString(response Response) []byte {
	toWrite, err := json.Marshal(response)
	if err != nil {
		return nil
	}
	return toWrite
}

func GetEpoch() int64 {
	return time.Now().Unix()
}

//func PrintMessage(message Message) string {
//	return "User: " + message.User + "\nIV: " + message.IV + "\nMAC: " + message.Mac + "\nAESKey: " + message.AESKey + "\nMACKey: " + message.MACKey + "\nData: " + message.Data
//}

