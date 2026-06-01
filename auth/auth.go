package auth

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log/slog"

	"pgtoll/protocol"
)

// HandleAuth reads backend messages and drives the SCRAM exchange until ReadyForQuery
func HandleAuth(conn *tls.Conn, password string, log *slog.Logger) error {
	for {
		msgType, payload, err := protocol.ReadMessage(conn)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}

		switch msgType {
		case 'R': // Authentication — server telling us what it needs
			if err := dispatchAuth(conn, payload, password, log); err != nil {
				return err
			}
		case 'S': // ParameterStatus — server reporting connection settings
			key, val := protocol.ParseParameterStatus(payload)
			log.Debug("ParameterStatus", "key", key, "value", val)
		case 'K': // BackendKeyData — PID + secret used for cancel requests
			pid := binary.BigEndian.Uint32(payload[0:4])
			key := binary.BigEndian.Uint32(payload[4:8])
			log.Info("BackendKeyData", "pid", pid, "cancel_key", key)
		case 'Z': // ReadyForQuery — auth done, connection is usable
			log.Info("ReadyForQuery — authenticated successfully")
			return nil
		case 'E': // ErrorResponse — something went wrong
			return fmt.Errorf("postgres: %s", protocol.ParseErrorResponse(payload))
		}
	}
}

// dispatchAuth handles a single 'R' message based on its sub-type
func dispatchAuth(conn *tls.Conn, payload []byte, password string, log *slog.Logger) error {
	authType := binary.BigEndian.Uint32(payload[:4])
	switch authType {
	case 0:
		log.Info("AuthOk")
	case 10: // SASL — server offers SCRAM mechanisms
		mechanisms := protocol.ParseSASLMechanisms(payload[4:])
		log.Info("AuthSASL", "mechanisms", mechanisms)
		return RunSCRAM(conn, password, log)
	default:
		return fmt.Errorf("unsupported auth type: %d", authType)
	}
	return nil
}
