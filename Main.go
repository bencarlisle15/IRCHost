package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	l, err := net.Listen("tcp4", "127.0.0.1:1515")
	if err != nil {
		fmt.Println(err)
		time.Sleep(100)
		main()
		return
	}
	defer l.Close()
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