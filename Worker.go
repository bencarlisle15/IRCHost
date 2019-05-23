package main

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"net"
	"sync"
)

type Worker struct {
	Connections ConnectionQueue
	Lock *sync.Mutex
	Condition *sync.Cond
	PrivateKey *rsa.PrivateKey
}

func NewWorker(key *rsa.PrivateKey) *Worker {
	var lock = &sync.Mutex{}
	worker := Worker{NewConnectionQueue(), lock, sync.NewCond(lock), key}
	return &worker
}

func (worker *Worker) Start() {
	for {
		worker.Lock.Lock()
		for worker.Connections.Len() == 0 {
			worker.Condition.Wait()
		}
		var conn = worker.Connections.Pop()
		worker.Lock.Unlock()
		worker.HandleConnection(conn)
	}
}

func (worker *Worker) AddConnection(conn net.Conn) {
	worker.Lock.Lock()
	worker.Connections.Push(conn)
	worker.Condition.Broadcast()
	worker.Lock.Unlock()
}

func (worker Worker) HandleConnection(conn net.Conn) {
	var response, err = ioutil.ReadAll(conn)
	defer conn.Close()
	if err != nil {
		fmt.Printf("An error occured %s", err)
	}
	var toWrite = RequestHandler(response, worker.PrivateKey)
	_, _ = conn.Write(toWrite)
}

func (worker Worker) Len() int {
	return worker.Connections.Len()
}