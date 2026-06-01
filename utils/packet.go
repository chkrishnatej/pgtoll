package utils

import (
	"bytes"
	"encoding/binary"
	"io"
)

// PacketReader provides utilities for reading binary data from PostgreSQL packets
type PacketReader struct {
	r *bytes.Reader
}

// NewPacketReader creates a new PacketReader from byte data
func NewPacketReader(data []byte) *PacketReader {
	return &PacketReader{
		r: bytes.NewReader(data),
	}
}

// Int16 reads a 16-bit integer in big-endian format
func (p *PacketReader) Int16() (int16, error) {
	var v int16
	err := binary.Read(p.r, binary.BigEndian, &v)
	return v, err
}

// Int32 reads a 32-bit integer in big-endian format
func (p *PacketReader) Int32() (int32, error) {
	var v int32
	err := binary.Read(p.r, binary.BigEndian, &v)
	return v, err
}

// CString reads a null-terminated string
func (p *PacketReader) CString() (string, error) {
	var buf []byte

	for {
		b, err := p.r.ReadByte()
		if err != nil {
			return "", err
		}

		if b == 0 {
			return string(buf), nil
		}

		buf = append(buf, b)
	}
}

// ReadInt32 reads a 32-bit integer from a bytes.Reader
func ReadInt32(r *bytes.Reader) (int32, error) {
	var buf [4]byte

	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return 0, err
	}

	return int32(binary.BigEndian.Uint32(buf[:])), nil
}

// ReadInt16 reads a 16-bit integer from a bytes.Reader
func ReadInt16(r *bytes.Reader) (int16, error) {
	var buf [2]byte

	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return 0, err
	}

	return int16(binary.BigEndian.Uint16(buf[:])), nil
}
