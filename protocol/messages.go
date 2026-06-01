package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

// ReadMessage reads one backend message: 1-byte type + 4-byte length + payload
func ReadMessage(r io.Reader) (msgType byte, payload []byte, err error) {
	hdr := make([]byte, 5)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return 0, nil, fmt.Errorf("read header: %w", err)
	}
	msgType = hdr[0]
	msgLen := binary.BigEndian.Uint32(hdr[1:5])
	payload = make([]byte, msgLen-4) // msgLen counts its own 4 bytes
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("read payload: %w", err)
	}
	return msgType, payload, nil
}

// WriteMessage frames a payload as a Postgres frontend message and sends it
func WriteMessage(w io.Writer, msgType byte, payload []byte) error {
	buf := make([]byte, 5+len(payload))
	buf[0] = msgType
	binary.BigEndian.PutUint32(buf[1:5], uint32(4+len(payload)))
	copy(buf[5:], payload)
	_, err := w.Write(buf)
	return err
}
