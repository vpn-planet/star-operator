package wireguard

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func parseIPPrefix(s string) (net.IP, uint8, error) {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			ip := ParseIP(s[:i])
			if ip == nil {
				return net.IP{}, 0, fmt.Errorf("failed to parse IP part: %q", s[:i])
			}

			pre, err := strconv.Atoi(s[i+1:])
			if err != nil {
				return net.IP{}, 0, err
			}

			if pre > len(ip)*8 {
				return net.IP{}, 0, fmt.Errorf("IP mask prefix length out of range: %d", pre)
			}

			return ip, uint8(pre), nil
		}
	}

	ip := ParseIP(s)
	if ip == nil {
		return net.IP{}, 0, fmt.Errorf("failed to parse IP: %q", s)
	}

	return ip, uint8(len(ip) * 8), nil
}

// Specific private IP address bound to single interface.
type ipAddress struct {
	ip  net.IP
	pre uint8
}

func NewIPAddress(ip net.IP, pre uint8) (ipAddress, error) {
	if ip[len(ip)-1]&1 == 0 {
		return ipAddress{}, errors.New("IP address bound to interface cannot end with 0")
	}
	return ipAddress{
		ip:  ip,
		pre: pre,
	}, nil
}

func (r ipAddress) String() string {
	return fmt.Sprintf("%s/%d", r.ip, r.pre)
}

func ParseIPAddress(s string) (ipAddress, error) {
	ip, pre, err := parseIPPrefix(s)
	if err != nil {
		return ipAddress{}, err
	}

	a, err := NewIPAddress(ip, pre)
	if err != nil {
		return ipAddress{}, err
	}

	return a, nil
}

type IPAddresses []ipAddress

func (as IPAddresses) String() string {
	var ss []string
	for _, a := range as {
		ss = append(ss, a.String())
	}
	return strings.Join(ss, ", ")
}

type ipRange struct {
	ip  net.IP
	pre uint8
}

func NewIPRange(ip net.IP, pre uint8) (ipRange, error) {
	for i := pre; int(i) < len(ip)*8; i++ {
		if (ip[i/8] & (1 << (7 - i%8))) != 0 {
			return ipRange{}, fmt.Errorf("outside of IP range mask should be ending with 0 at %d", i)
		}
	}
	return ipRange{
		ip:  ip,
		pre: pre,
	}, nil
}

func (r ipRange) String() string {
	return fmt.Sprintf("%s/%d", r.ip, r.pre)
}

func ParseIP(s string) net.IP {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '.':
			return net.ParseIP(s).To4()
		case ':':
			return net.ParseIP(s).To16()
		}
	}
	return nil
}

func ParseIPRange(s string) (ipRange, error) {
	ip, pre, err := parseIPPrefix(s)
	if err != nil {
		return ipRange{}, err
	}

	r, err := NewIPRange(ip, pre)
	if err != nil {
		return ipRange{}, err
	}

	return r, nil
}

type IPRanges []ipRange

func (rs IPRanges) String() string {
	var ss []string
	for _, r := range rs {
		ss = append(ss, r.String())
	}
	return strings.Join(ss, ", ")
}

// Endpoint address that is accessible externally.
// IP address or DNS resolvable name and port number.
type ExternalEndpoint struct {
	host string
	port uint16
}

func (a ExternalEndpoint) String() string {
	return fmt.Sprintf("%s:%d", a.host, a.port)
}
