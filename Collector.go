package main

import "time"

func Sweep() {
	for {
		SweepSessions()
		//SweepMessages()
		time.Sleep(100)
	}
}