package main

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

type UserData struct {
	User string `json:"user"`
	Hash string `json:"hash"`
	Salt string `json:"salt"`
	AESKey string `json:"aeskey"`
	MACKey string `json:"mackey"`
}

func CreateResults(rows *sql.Rows) []UserData {
	results := make([]UserData, 0)
	var currentUser UserData
	for rows.Next() {
		_ = rows.Scan(&currentUser.User, &currentUser.Hash, &currentUser.Salt, &currentUser.AESKey, &currentUser.MACKey)
		results = append(results, currentUser)
	}
	return results
}

func AddUser(user string, password, salt, aesKey, macKey []byte) bool {
	database, _ := sql.Open("sqlite3", "database.db")
	defer database.Close()
	rows, _ := database.Query("SELECT * FROM Users WHERE user=?", user)
	defer rows.Close()
	if rows.Next() {
		return false
	}
	statement, _ := database.Prepare("INSERT INTO Users VALUES (?, ?, ?, ?, ?)")
	defer statement.Close()
	_, err := statement.Exec(user, password, salt, aesKey, macKey)
	return err == nil
}

func GetUserData(user string) []UserData {
	database, _ := sql.Open("sqlite3", "database.db")
	defer database.Close()
	rows, _ := database.Query("SELECT * FROM Users WHERE user=?", user)
	defer rows.Close()
	return CreateResults(rows)
}

func AddSessionID(user string, sessionID []byte) bool {
	database, _ := sql.Open("sqlite3", "database.db")
	statement, _ := database.Prepare("INSERT INTO Sessions ('user', 'id') VALUES (?, ?)")
	defer statement.Close()
	_, err := statement.Exec(user, sessionID)
	return err == nil
}
