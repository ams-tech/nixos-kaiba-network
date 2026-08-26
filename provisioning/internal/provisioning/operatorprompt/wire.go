package operatorprompt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	wireSchemaVersion = "provisioning.kaiba.network/operator-prompt-wire/v1alpha1"
	maxWireBytes      = 64 * 1024
	wireWriteTimeout  = 5 * time.Second
)

const (
	framePrompt = "prompt"
	frameAck    = "acknowledgement"
	frameResult = "result"
	frameError  = "error"
)

const (
	errorNoActive     = "no_active_prompt"
	errorUnauthorized = "unauthorized_peer"
	errorInvalid      = "invalid_message"
	errorMismatch     = "prompt_mismatch"
	errorExpired      = "prompt_expired"
	errorReplay       = "prompt_replayed"
	errorClosed       = "server_closed"
)

type wireFrame struct {
	SchemaVersion   string           `json:"schema_version"`
	Type            string           `json:"type"`
	Prompt          *Prompt          `json:"prompt,omitempty"`
	PromptID        string           `json:"prompt_id,omitempty"`
	PromptDigest    string           `json:"prompt_digest,omitempty"`
	Acknowledgement *Acknowledgement `json:"acknowledgement,omitempty"`
	ErrorCode       string           `json:"error_code,omitempty"`
}

func (frame wireFrame) validate() error {
	if frame.SchemaVersion != wireSchemaVersion {
		return errors.New("unsupported operator prompt wire schema")
	}
	switch frame.Type {
	case framePrompt:
		if frame.Prompt == nil || frame.PromptID != "" || frame.PromptDigest != "" || frame.Acknowledgement != nil || frame.ErrorCode != "" {
			return errors.New("malformed prompt frame")
		}
		return frame.Prompt.Validate()
	case frameAck:
		if frame.Prompt != nil || !promptIDPattern.MatchString(frame.PromptID) || !digestPattern.MatchString(frame.PromptDigest) || frame.Acknowledgement != nil || frame.ErrorCode != "" {
			return errors.New("malformed acknowledgement frame")
		}
	case frameResult:
		if frame.Prompt != nil || frame.PromptID != "" || frame.PromptDigest != "" || frame.Acknowledgement == nil || frame.ErrorCode != "" {
			return errors.New("malformed result frame")
		}
	case frameError:
		if frame.Prompt != nil || frame.PromptID != "" || frame.PromptDigest != "" || frame.Acknowledgement != nil || !knownErrorCode(frame.ErrorCode) {
			return errors.New("malformed error frame")
		}
	default:
		return errors.New("unknown operator prompt frame type")
	}
	return nil
}

func knownErrorCode(code string) bool {
	switch code {
	case errorNoActive, errorUnauthorized, errorInvalid, errorMismatch, errorExpired, errorReplay, errorClosed:
		return true
	default:
		return false
	}
}

func writeFrame(connection *net.UnixConn, frame wireFrame) error {
	if err := frame.validate(); err != nil {
		return err
	}
	encoded, err := json.Marshal(frame)
	if err != nil {
		return fmt.Errorf("encode operator prompt frame: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxWireBytes {
		return errors.New("operator prompt frame exceeds its fixed limit")
	}
	if err := connection.SetWriteDeadline(time.Now().Add(wireWriteTimeout)); err != nil {
		return err
	}
	_, err = io.Copy(connection, bytes.NewReader(encoded))
	return err
}

// readInitialFrame reads the server's newline-terminated first frame without
// waiting for the bidirectional stream to close.
func readInitialFrame(connection *net.UnixConn, deadline time.Time) (wireFrame, error) {
	if err := connection.SetReadDeadline(deadline); err != nil {
		return wireFrame{}, err
	}
	data := make([]byte, 0, 4096)
	one := make([]byte, 1)
	for len(data) <= maxWireBytes {
		n, err := connection.Read(one)
		if n == 1 {
			data = append(data, one[0])
			if one[0] == '\n' {
				break
			}
		}
		if err != nil {
			return wireFrame{}, fmt.Errorf("read operator prompt frame: %w", err)
		}
	}
	if len(data) == 0 || len(data) > maxWireBytes || data[len(data)-1] != '\n' {
		return wireFrame{}, errors.New("operator prompt frame is empty, unterminated, or oversized")
	}
	var frame wireFrame
	if err := decodeStrict(data, &frame); err != nil {
		return wireFrame{}, err
	}
	if err := frame.validate(); err != nil {
		return wireFrame{}, err
	}
	return frame, nil
}

// readFinalFrame requires EOF, ensuring there is exactly one bounded response
// or acknowledgement frame and no ignored trailing protocol material.
func readFinalFrame(connection *net.UnixConn, deadline time.Time) (wireFrame, error) {
	if err := connection.SetReadDeadline(deadline); err != nil {
		return wireFrame{}, err
	}
	data, err := io.ReadAll(io.LimitReader(connection, maxWireBytes+1))
	if err != nil {
		return wireFrame{}, err
	}
	if len(data) == 0 || len(data) > maxWireBytes {
		return wireFrame{}, errors.New("operator prompt frame is empty or oversized")
	}
	var frame wireFrame
	if err := decodeStrict(data, &frame); err != nil {
		return wireFrame{}, err
	}
	if err := frame.validate(); err != nil {
		return wireFrame{}, err
	}
	return frame, nil
}

type RemoteError struct{ Code string }

func (err RemoteError) Error() string { return "operator prompt server rejected request: " + err.Code }
