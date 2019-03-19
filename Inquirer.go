package main

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"strconv"
	"time"
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

func AddSessionID(user string, sessionID string) bool {
	database, _ := sql.Open("sqlite3", "database.db")
	statement, _ := database.Prepare("INSERT INTO Sessions VALUES (?, ?, ?)")
	defer statement.Close()
	_, err := statement.Exec(user, sessionID, GetEpoch())
	return err == nil
}

func SweepSessions() {
	database, _ := sql.Open("sqlite3", "database.db")
	defer database.Close()
	rows,err := database.Exec("DELETE FROM Sessions WHERE timestamp <= ?", GetEpoch()-10)
	affected, _ := rows.RowsAffected()
	if affected > 0 {
		fmt.Println("Swept " + strconv.Itoa(int(affected)) + " sessions")
	}
}
func SweepMessages() {
	database, _ := sql.Open("sqlite3", "database.db")
	defer database.Close()
	rows, _ := database.Exec("DELETE FROM Messages WHERE timestamp <= ?", GetEpoch()-10)
	affected, _ := rows.RowsAffected()
	if affected > 0 {
		fmt.Println("Swept " + strconv.Itoa(int(affected)) + " messages")
	}
}

func GetSessions(user string) []string {
	database, _ := sql.Open("sqlite3", "database.db")
	defer database.Close()
	rows, _ := database.Query("SELECT sessionId FROM Sessions WHERE user=?", user)
	sessions := make([]string, 0)
	var sessionId string
	for rows.Next() {
		_ = rows.Scan(&sessionId)
		sessions = append(sessions, sessionId)
	}
	return sessions
}

func UpdateSession(sessionId string) {
	database, _ := sql.Open("sqlite3", "database.db")
	defer database.Close()
	_, _ = database.Exec("UPDATE Sessions SET timestamp=? WHERE sessionId=?", GetEpoch(), sessionId)
}

func GetNextMessage(user string) Sendable {
	database, _ := sql.Open("sqlite3", "database.db")
	defer database.Close()
	rows,_ := database.Query("SELECT * FROM Messages WHERE receiver=?", user)
	var sendable Sendable
	if !rows.Next() {
		return sendable
	}
	_ = rows.Scan(&sendable.Receiver, &sendable.Sender, &sendable.Message, &sendable.IsFile)
	rows, err := database.Query("DELETE FROM Messages WHERE receiver=? AND sender=? AND message=? && isFile=? LIMIT 1", sendable.Receiver, sendable.Sender, sendable.Message, sendable.IsFile)
	fmt.Println(rows)
	fmt.Println(err)
	return sendable
}

func AddMessage(to string, from string, message string, isFile bool) {
	database, _ := sql.Open("sqlite3", "database.db")
	defer database.Close()
	statement, _ := database.Prepare("INSERT INTO Messages VALUES (?, ?, ?, ?, ?)")
	defer statement.Close()
	_, _ = statement.Exec(to, from, message, isFile, GetEpoch())
}

func GetEpoch() int64 {
	return time.Now().Unix()
}