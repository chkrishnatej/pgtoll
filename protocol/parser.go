package protocol

import (
	"fmt"
	"strings"
)

// ParseKV parses "key=value,key=value" into a map (used for SCRAM fields)
func ParseKV(msg string) map[string]string {
	out := make(map[string]string)
	for _, part := range strings.Split(msg, ",") {
		if len(part) >= 2 && part[1] == '=' {
			out[string(part[0])] = part[2:]
		}
	}
	return out
}

// ParseSASLMechanisms extracts null-separated mechanism names from AuthSASL payload
func ParseSASLMechanisms(data []byte) []string {
	var mechs []string
	for _, m := range strings.Split(string(data), "\x00") {
		if m != "" {
			mechs = append(mechs, m)
		}
	}
	return mechs
}

// ParseParameterStatus splits a ParameterStatus payload into key and value
func ParseParameterStatus(payload []byte) (key, val string) {
	parts := strings.SplitN(string(payload), "\x00", 3)
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	return string(payload), ""
}

// ParseErrorResponse extracts severity, code, and message from an ErrorResponse payload
func ParseErrorResponse(payload []byte) string {
	fields := map[byte]string{}
	pos := 0
	for pos < len(payload) {
		code := payload[pos]
		pos++
		if code == 0 {
			break
		}
		start := pos
		for pos < len(payload) && payload[pos] != 0 {
			pos++
		}
		fields[code] = string(payload[start:pos])
		pos++ // skip null
	}
	return fmt.Sprintf("severity=%s code=%s message=%s", fields['S'], fields['C'], fields['M'])
}
