package tcp

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"os"
	"time"
)

type Dial func(network, address string) (net.Conn, error)

type Tunnel struct {
	Name      string
	Local     string
	Remote    string
	Tls       bool
	Insecure  bool
	quit      chan interface{}
	tlsConfig *tls.Config
	listener  net.Listener
}

func (t *Tunnel) Listen() {
	t.quit = make(chan interface{})
	laddr, err := net.ResolveTCPAddr("tcp", t.Local)
	if err != nil {
		log.Fatalf("Tunneling failed: %v", err)
	}
	raddr, err := net.ResolveTCPAddr("tcp", t.Remote)
	if err != nil {
		log.Fatalf("Tunneling failed: %v", err)
		return
	}
	if t.Tls {
		filename := "server.crt"
		if _, err := os.Stat(filename); err != nil {
			log.Fatalf("server.crt missing: %v", err)
			return
		}
		cer, err := tls.LoadX509KeyPair(filename, filename)
		if err != nil {
			log.Fatalf("parsing certificate failed: %v", err)
			return

		}
		t.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cer}} // #nosec
		listener, err := tls.Listen("tcp", laddr.String(), t.tlsConfig)
		if err != nil {
			log.Fatalf("Tunneling failed: %v", err)
			return
		}
		t.listener = listener
	} else {
		listener, err := net.ListenTCP("tcp", laddr)
		if err != nil {
			log.Fatalf("Tunneling failed: %v", err)
			return
		}
		t.listener = listener
	}

	var dial Dial
	dialer := &net.Dialer{Timeout: 1 * time.Minute}
	dial = dialer.Dial
	if t.Tls {
		config := &tls.Config{MinVersion: tls.VersionTLS10} // #nosec disable SSLv3
		if t.Insecure {
			config.InsecureSkipVerify = true
		}
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    config,
		}
		dial = tlsDialer.Dial
	}
	log.Printf("Starting Tunnel '%s' (TLS: %v, Insecure: %v)\n", t.Local, t.Tls, t.Insecure)
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			select {
			case <-t.quit:
				return
			default:
				log.Printf("Failed to accept connection %q\n", err)
				continue
			}
		}
		go t.serve(dial, conn, laddr, raddr)
	}
}

func (t *Tunnel) serve(dial Dial, lconn net.Conn, laddr, raddr *net.TCPAddr) {
	defer lconn.Close()
	_, port, err := net.SplitHostPort(lconn.RemoteAddr().String())
	if err != nil {
		log.Println(err)
		return
	}
	rconn, err := dial("tcp", raddr.String())
	if err != nil {
		log.Println(err)
		return
	}
	defer rconn.Close()

	log.Printf("connection Tunnel '%s' established (%v->%v)\n", port, laddr.String(), raddr.String())
	defer log.Printf("connection Tunnel '%s' closed (%v->%v)\n", port, laddr.String(), raddr.String())

	errc := make(chan error, 2)
	cp := func(out io.Writer, in io.Reader) {
		_, err := io.Copy(out, in)
		errc <- err
	}

	go cp(lconn, rconn)
	go cp(rconn, lconn)
	err = <-errc
	if err != nil {
		log.Fatalf("connection Tunnel '%s' failed with: %v", port, err)
	}
}

func (t *Tunnel) Shutdown() {
	if t.listener != nil {
		log.Printf("Stopping Tunnel %q\n", t.Local)
		close(t.quit)
		if err := t.listener.Close(); err != nil {
			log.Println(err)
		}
	}
}
