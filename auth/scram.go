package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"

	"pgtoll/protocol"

	"golang.org/x/crypto/pbkdf2"
)

// RunSCRAM drives the full 3-message SCRAM-SHA-256 exchange
func RunSCRAM(conn *tls.Conn, password string, log *slog.Logger) error {
	// Round 1: we send client-first, server replies with challenge
	nonce, clientFirst, err := sendClientFirst(conn)
	if err != nil {
		return fmt.Errorf("SCRAM round 1: %w", err)
	}
	log.Debug("SCRAM sent client-first", "nonce", nonce)

	// Round 2: read server challenge
	serverFirst, err := readServerFirst(conn)
	if err != nil {
		return fmt.Errorf("SCRAM round 2: %w", err)
	}
	log.Debug("SCRAM received server-first", "msg", serverFirst)

	// Round 3: compute proof and send client-final
	if err := sendClientFinal(conn, password, nonce, clientFirst, serverFirst); err != nil {
		return fmt.Errorf("SCRAM round 3: %w", err)
	}
	log.Debug("SCRAM sent client-final with proof")

	// Read AuthSASLFinal — server verifier (we log it, don't verify here)
	_, payload, err := protocol.ReadMessage(conn)
	if err != nil {
		return fmt.Errorf("SCRAM final: %w", err)
	}
	authType := binary.BigEndian.Uint32(payload[:4])
	if authType != 12 {
		return fmt.Errorf("expected AuthSASLFinal(12), got %d", authType)
	}
	log.Debug("AuthSASLFinal", "server_verifier", string(payload[4:]))

	return nil
}

// sendClientFirst generates a nonce and sends the SASLInitialResponse
func sendClientFirst(conn io.Writer) (nonce, clientFirst string, err error) {
	// Random nonce — must be unique per auth attempt
	nonceBytes := make([]byte, 18)
	if _, err = rand.Read(nonceBytes); err != nil {
		return "", "", fmt.Errorf("generate nonce: %w", err)
	}
	nonce = base64.StdEncoding.EncodeToString(nonceBytes)

	// client-first: GS2 header "n" (no channel binding) + bare message
	clientFirst = "n,,n=,r=" + nonce

	// SASLInitialResponse payload: mechanism\0 + int32(len) + message
	var p bytes.Buffer
	p.WriteString("SCRAM-SHA-256")
	p.WriteByte(0)
	msgLen := make([]byte, 4)
	binary.BigEndian.PutUint32(msgLen, uint32(len(clientFirst)))
	p.Write(msgLen)
	p.WriteString(clientFirst)

	return nonce, clientFirst, protocol.WriteMessage(conn, 'p', p.Bytes())
}

// readServerFirst reads AuthSASLContinue and returns the server-first-message
func readServerFirst(conn io.Reader) (string, error) {
	msgType, payload, err := protocol.ReadMessage(conn)
	if err != nil {
		return "", err
	}
	if msgType != 'R' {
		return "", fmt.Errorf("expected 'R', got %c", msgType)
	}
	authType := binary.BigEndian.Uint32(payload[:4])
	if authType != 11 {
		return "", fmt.Errorf("expected SASLContinue(11), got %d", authType)
	}
	// payload[4:] is the server-first-message: r=<nonce>,s=<salt>,i=<iterations>
	return string(payload[4:]), nil
}

// sendClientFinal computes the SCRAM proof and sends the client-final-message
func sendClientFinal(conn io.Writer, password, clientNonce, clientFirst, serverFirst string) error {
	// Parse r=<fullNonce>, s=<saltBase64>, i=<iterations> from server-first
	fields := protocol.ParseKV(serverFirst)
	fullNonce, saltB64, iterStr := fields["r"], fields["s"], fields["i"]

	if !strings.HasPrefix(fullNonce, clientNonce) {
		return fmt.Errorf("server nonce does not start with client nonce")
	}
	iterations, err := strconv.Atoi(iterStr)
	if err != nil {
		return fmt.Errorf("parse iterations: %w", err)
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return fmt.Errorf("decode salt: %w", err)
	}

	// client-first-message-bare = strip the "n,," GS2 header
	clientFirstBare := strings.TrimPrefix(clientFirst, "n,,")

	// c=biws is base64("n,,") — the channel binding header with no binding
	clientFinalNoProof := "c=biws,r=" + fullNonce

	// authMessage is what both sides sign — the full transcript
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalNoProof

	// SCRAM-SHA-256 key derivation
	saltedPassword := pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)
	clientKey := hmacSHA256(saltedPassword, "Client Key")
	storedKey := sha256Digest(clientKey)
	clientSignature := hmacSHA256(storedKey, authMessage)
	clientProof := xorBytes(clientKey, clientSignature)

	clientFinal := clientFinalNoProof + ",p=" + base64.StdEncoding.EncodeToString(clientProof)
	return protocol.WriteMessage(conn, 'p', []byte(clientFinal))
}

// SCRAM crypto helpers

func hmacSHA256(key []byte, msg string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return mac.Sum(nil)
}

func sha256Digest(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}
