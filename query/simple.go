package query

import (
	"bytes"
	"encoding/binary"
)

// SimpleQuery represents a simple query message
type SimpleQuery struct {
	msgType byte
	payload string
}

// NewSimpleQuery creates a new simple query with the given SQL statement
func NewSimpleQuery(payload string) SimpleQuery {
	return SimpleQuery{
		msgType: 'Q',
		payload: payload,
	}
}

// ToBuffer converts the simple query to a buffer ready to be sent
func (sq *SimpleQuery) ToBuffer() bytes.Buffer {
	var sqBuffer bytes.Buffer

	sqBuffer.WriteByte(sq.msgType)

	lenBytes := make([]byte, 4)
	var messageLen uint32 = uint32(4 + len(sq.payload) + 1)
	binary.BigEndian.PutUint32(lenBytes, messageLen)
	sqBuffer.Write(lenBytes)
	sqBuffer.WriteString(sq.payload)
	sqBuffer.WriteByte(0)

	return sqBuffer
}
