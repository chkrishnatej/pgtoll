// pgclient: connects to Postgres and performs full SCRAM-SHA-256 authentication.
// This is the foundation for the proxy — once auth works here, we wrap it.
//
// Run:  go run main.go
// Dep:  go get golang.org/x/crypto
package main

import (
	"fmt"
	"log/slog"
	"os"
	"pgtoll/auth"
	"pgtoll/config"
	"pgtoll/network"
	"pgtoll/protocol"
	"pgtoll/query"
	"pgtoll/utils"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Step 1: plain TCP connection
	conn, err := network.ConnectTCP(config.PgAddr)
	if err != nil {
		log.Error("TCP failed", "err", err)
		os.Exit(1)
	}
	log.Info("TCP connected", "addr", config.PgAddr)

	// Step 2: SSL negotiation — ask Postgres if TLS is available
	if err := network.NegotiateSSL(conn); err != nil {
		log.Error("SSL negotiation failed", "err", err)
		os.Exit(1)
	}
	log.Info("SSL accepted by server")

	// Step 3: upgrade to TLS — all bytes are encrypted from here on
	tlsConn, err := network.UpgradeToTLS(conn, config.CaCertPath)
	if err != nil {
		log.Error("TLS upgrade failed", "err", err)
		os.Exit(1)
	}
	log.Info("TLS handshake complete")

	// Step 4: send StartupMessage — tell Postgres who we are
	if err := protocol.SendStartupMessage(tlsConn, config.PgUser, config.PgDatabase); err != nil {
		log.Error("StartupMessage failed", "err", err)
		os.Exit(1)
	}
	log.Info("StartupMessage sent", "user", config.PgUser, "database", config.PgDatabase)

	// Step 5: auth loop — handle SCRAM exchange until ReadyForQuery
	if err := auth.HandleAuth(tlsConn, config.PgPassword, log); err != nil {
		log.Error("Auth failed", "err", err)
		os.Exit(1)
	}

	// Step 6: execute a simple query
	q := query.NewSimpleQuery("SELECT datname, datdba, encoding FROM pg_database;")
	buf := q.ToBuffer()
	_, err = tlsConn.Write(buf.Bytes())
	if err != nil {
		return
	}

	// Step 7: read and process query results
	for {
		log.Info("Reading new simple query")
		msgType, payload, err := protocol.ReadMessage(tlsConn)
		if err != nil {
			log.Error("read failed", "err", err)
			os.Exit(1)
		}

		switch msgType {
		case 'T': // RowDescription — column names and types
			log.Info("RowDescription", "payload_hex", fmt.Sprintf("%x", payload))
			pr := utils.NewPacketReader(payload)
			fieldCount, _ := pr.Int16()
			log.Info("Number of fields", "fieldCount", fieldCount)
			for i := 0; i < int(fieldCount); i++ {
				result, _ := query.ReadRowDescription(pr)
				log.Info("RowDescription", "payload_hex", result)
			}
		case 'D': // DataRow — one message per row
			log.Info("DataRow", "payload_hex", fmt.Sprintf("%x", payload))
		case 'C': // CommandComplete — query finished
			log.Info("CommandComplete", "tag", string(payload))
		case 'Z': // ReadyForQuery — server idle again
			log.Info("ReadyForQuery — query done")
			return
		case 'E': // ErrorResponse
			log.Error("query error", "detail", protocol.ParseErrorResponse(payload))
			return
		}
	}
}
