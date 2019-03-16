package main

import (
	"net"
)

type WorkerQueue struct {
	Queue []*Worker
}

type ConnectionQueue struct {
	Queue []net.Conn
}

func NewWorkerQueue() WorkerQueue {
	return WorkerQueue{[]*Worker{}}
}

func NewConnectionQueue() ConnectionQueue {
	return ConnectionQueue{[]net.Conn{}}
}

func (queue *WorkerQueue) Push(worker *Worker) {
	queue.Queue = append(queue.Queue, worker)
}

func (queue *ConnectionQueue) Push(conn net.Conn) {
	queue.Queue = append(queue.Queue, conn)
}

func (queue *ConnectionQueue) Pop() net.Conn {
	var conn = queue.Queue[0]
	queue.Queue = queue.Queue[1:]
	return conn
}

func (queue *WorkerQueue) Len() int {
	return len(queue.Queue)
}

func (queue *ConnectionQueue) Len() int {
	return len(queue.Queue)
}

func (queue *WorkerQueue) Get(i int) *Worker {
	return queue.Queue[i]
}