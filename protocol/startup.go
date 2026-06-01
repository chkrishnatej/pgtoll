package protocol

import (
	"bytes"
	"encoding/binary"
	"io"

	"pgtoll/config"
)

// SendStartupMessage tells Postgres our username and target database
func SendStartupMessage(conn io.Writer, user, database string) error {
	var body bytes.Buffer

	// Protocol version 3.0 must be the first 4 bytes of the body
	ver := make([]byte, 4)
	binary.BigEndian.PutUint32(ver, config.ProtocolVersion30)
	body.Write(ver)

	// Parameters: null-terminated key\0value\0 pairs, ended by an extra \0
	body.WriteString("user")
	body.WriteByte(0)
	body.WriteString(user)
	body.WriteByte(0)
	body.WriteString("database")
	body.WriteByte(0)
	body.WriteString(database)
	body.WriteByte(0)
	body.WriteByte(0) // end of parameter list

	// Startup message has no type byte — just length then body
	totalLen := uint32(4 + body.Len()) // 4 = the length field itself
	var msg bytes.Buffer
	lenB := make([]byte, 4)
	binary.BigEndian.PutUint32(lenB, totalLen)
	msg.Write(lenB)
	msg.Write(body.Bytes())

	_, err := conn.Write(msg.Bytes())
	return err
}
