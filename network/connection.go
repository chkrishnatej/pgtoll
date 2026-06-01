package network

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"

	"pgtoll/config"
)

// ConnectTCP opens a plain TCP connection — the kernel handles the 3-way handshake
func ConnectTCP(addr string) (net.Conn, error) {
	return net.Dial("tcp", addr)
}

// NegotiateSSL sends the 8-byte SSLRequest and checks the server's 1-byte reply
func NegotiateSSL(conn net.Conn) error {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[0:4], 8)                     // message length
	binary.BigEndian.PutUint32(buf[4:8], config.SSLRequestCode) // magic code
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("write SSLRequest: %w", err)
	}

	resp := make([]byte, 1)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("read SSL response: %w", err)
	}
	if resp[0] != 'S' {
		return fmt.Errorf("server declined SSL: %q", resp[0])
	}
	return nil
}

// UpgradeToTLS wraps the TCP conn in TLS — reads/writes are auto-encrypted after this
func UpgradeToTLS(conn net.Conn, caCertPath string) (*tls.Conn, error) {
	certPool := x509.NewCertPool()
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	certPool.AppendCertsFromPEM(caCert)

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: "localhost",
		RootCAs:    certPool,
	})
	if err := tlsConn.Handshake(); err != nil {
		err := tlsConn.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	return tlsConn, nil
}
