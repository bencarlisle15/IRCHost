package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	l, err := net.Listen("tcp4", "127.0.0.1:1515")
	if !CheckForDatabase() {
		fmt.Println("Database could not be created")
		return
	}
	if err != nil {
		fmt.Println(err)
		time.Sleep(100)
		main()
		return
	}
	defer l.Close()
	go Sweep()
	var executor = NewExecutor(8)
	go executor.Start()
	fmt.Println("Started Server")
	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}
		go executor.AddConnection(c)
	}
}

func CheckForDatabase() bool {
	_, err := os.Stat("database.db")
	if err != nil {
		_ = os.Remove("database.db")
		_, _ = os.Create("database.db")
		return CreateDatabase()
	}
	return true
}