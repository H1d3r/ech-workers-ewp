package ewp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
)

const (
	AddressTypeIPv4   byte = 0x01
	AddressTypeDomain byte = 0x02
	AddressTypeIPv6   byte = 0x03
)

type Address struct {
	Type byte
	Host string
	Port uint16
}

func ParseAddress(addr string) (Address, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return Address{}, fmt.Errorf("invalid address format: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return Address{}, errors.New("invalid port")
	}

	a := Address{
		Host: host,
		Port: uint16(port),
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			a.Type = AddressTypeIPv4
		} else {
			a.Type = AddressTypeIPv6
		}
	} else {
		a.Type = AddressTypeDomain
	}

	return a, nil
}

func (a Address) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port)))
}

func (a Address) Encode() ([]byte, error) {
	buf := new(bytes.Buffer)

	buf.WriteByte(a.Type)

	switch a.Type {
	case AddressTypeIPv4:
		ip := net.ParseIP(a.Host).To4()
		if ip == nil {
			return nil, errors.New("invalid IPv4 address")
		}
		buf.WriteByte(4)
		buf.Write(ip)

	case AddressTypeDomain:
		if len(a.Host) > 255 {
			return nil, errors.New("domain name too long")
		}
		buf.WriteByte(byte(len(a.Host)))
		buf.WriteString(a.Host)

	case AddressTypeIPv6:
		ip := net.ParseIP(a.Host).To16()
		if ip == nil {
			return nil, errors.New("invalid IPv6 address")
		}
		buf.WriteByte(16)
		buf.Write(ip)

	default:
		return nil, errors.New("unknown address type")
	}

	binary.Write(buf, binary.BigEndian, a.Port)

	return buf.Bytes(), nil
}

func DecodeAddress(data []byte) (Address, int, error) {
	if len(data) < 1 {
		return Address{}, 0, errors.New("empty address data")
	}

	addr := Address{Type: data[0]}
	offset := 1

	if len(data) < offset+1 {
		return Address{}, 0, errors.New("truncated address length")
	}

	addrLen := int(data[offset])
	offset++

	switch addr.Type {
	case AddressTypeIPv4:
		if addrLen != 4 {
			return Address{}, 0, errors.New("invalid IPv4 length")
		}
		if len(data) < offset+4+2 {
			return Address{}, 0, errors.New("truncated IPv4 address")
		}
		ip := net.IP(data[offset : offset+4])
		addr.Host = ip.String()
		offset += 4

	case AddressTypeDomain:
		if len(data) < offset+addrLen+2 {
			return Address{}, 0, errors.New("truncated domain address")
		}
		addr.Host = string(data[offset : offset+addrLen])
		offset += addrLen

	case AddressTypeIPv6:
		if addrLen != 16 {
			return Address{}, 0, errors.New("invalid IPv6 length")
		}
		if len(data) < offset+16+2 {
			return Address{}, 0, errors.New("truncated IPv6 address")
		}
		ip := net.IP(data[offset : offset+16])
		addr.Host = ip.String()
		offset += 16

	default:
		return Address{}, 0, errors.New("unknown address type")
	}

	if len(data) < offset+2 {
		return Address{}, 0, errors.New("truncated port")
	}

	addr.Port = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	return addr, offset, nil
}
