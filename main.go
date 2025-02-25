package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/rheilek/go-tcp-tunnel/tcp"
)

func main() {
	tunnel := &tcp.Tunnel{
		Name:   "test",
		Local:  "127.0.0.1:8080",
		Remote: "127.0.0.1:80",
		//Tls: true // server.crt must be present
	}
	go tunnel.Listen()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)
	<-c

	tunnel.Shutdown()
}
