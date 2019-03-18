package main

import (
	"fmt"
	"net"
	"os"
	"sync"
)

type Executor struct {
	Connections ConnectionQueue
	Workers WorkerQueue
	Lock *sync.Mutex
	Condition *sync.Cond
}

func NewExecutor(MaxThreads int) Executor {
	var workers = NewWorkerQueue()
	var worker *Worker
	var key = GetPrivateKey()
	if key == nil {
		os.Exit(0)
	}
	for i := 0; i < MaxThreads; i++ {
		worker = NewWorker(key)
		workers.Push(worker)
		go worker.Start()
	}
	var mutex = sync.Mutex{}
	executor := Executor{NewConnectionQueue(), workers, &mutex, sync.NewCond(&mutex)}
	return executor
}

func (executor *Executor) Start() {
	for {
		executor.Lock.Lock()
		fmt.Println("Waiting")
		for executor.Connections.Len() == 0 {
			executor.Condition.Wait()
		}
		var conn = executor.Connections.Pop()
		executor.Lock.Unlock()
		fmt.Println("Adding to worker queue")
		var smallestWorker = SmallestWorker(executor.Workers)
		go smallestWorker.AddConnection(conn)
	}
}

func SmallestWorker(queue WorkerQueue) *Worker {
	var smallestWorker = queue.Get(0)
	for i := 1; i < queue.Len(); i++ {
		if smallestWorker.Len() > queue.Get(i).Len() {
			smallestWorker = queue.Get(i)
		}
	}
	return smallestWorker
}

func (executor *Executor) AddConnection(conn net.Conn) {
	executor.Lock.Lock()
	executor.Connections.Push(conn)
	executor.Condition.Broadcast()
	executor.Lock.Unlock()
}