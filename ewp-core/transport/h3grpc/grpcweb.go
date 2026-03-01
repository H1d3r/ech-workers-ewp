package h3grpc

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	grpcWebFlagUncompressed = 0x00
	grpcWebFlagCompressed   = 0x01

	ContentTypeGRPCWeb     = "application/grpc-web+proto"
	ContentTypeGRPCWebText = "application/grpc-web-text+proto"
	ContentTypeGRPC        = "application/grpc+proto"
)

// GRPCWebEncoder encodes messages in gRPC-Web binary format.
// Format: [Compressed-Flag: 1 byte][Message-Length: 4 bytes][Protobuf Message]
type GRPCWebEncoder struct {
	writer     io.Writer
	compressed bool
}

func NewGRPCWebEncoder(w io.Writer, compressed bool) *GRPCWebEncoder {
	return &GRPCWebEncoder{writer: w, compressed: compressed}
}

// Encode encodes a message into gRPC-Web format and writes it in one syscall.
func (e *GRPCWebEncoder) Encode(data []byte) error {
	var header [5]byte
	if e.compressed {
		header[0] = grpcWebFlagCompressed
	}
	binary.BigEndian.PutUint32(header[1:], uint32(len(data)))

	if _, err := e.writer.Write(header[:]); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if len(data) > 0 {
		if _, err := e.writer.Write(data); err != nil {
			return fmt.Errorf("failed to write message: %w", err)
		}
	}
	return nil
}

// GRPCWebDecoder decodes messages from gRPC-Web binary format.
type GRPCWebDecoder struct {
	reader io.Reader
}

func NewGRPCWebDecoder(r io.Reader) *GRPCWebDecoder {
	return &GRPCWebDecoder{reader: r}
}

// Decode reads and decodes a single gRPC-Web message.
func (d *GRPCWebDecoder) Decode() ([]byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(d.reader, header[:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	compressed := header[0] == grpcWebFlagCompressed
	messageLen := binary.BigEndian.Uint32(header[1:])

	if messageLen == 0 {
		return []byte{}, nil
	}
	if messageLen > 64*1024*1024 {
		return nil, fmt.Errorf("message too large: %d bytes", messageLen)
	}

	message := make([]byte, messageLen)
	if _, err := io.ReadFull(d.reader, message); err != nil {
		return nil, fmt.Errorf("failed to read message body: %w", err)
	}

	if compressed {
		return nil, fmt.Errorf("compressed messages not supported")
	}

	return message, nil
}
