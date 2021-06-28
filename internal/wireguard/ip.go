package wireguard

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	valid "github.com/asaskevich/govalidator"
)

const (
	portMin = 1
	portMax = 65535
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
type IPAddress struct {
	IP net.IP
	// Prefix bits length of mask.
	Pre uint8
}

func NewIPAddress(ip net.IP, pre uint8) (IPAddress, error) {
	for i := pre; int(i) < len(ip)*8; i++ {
		if (ip[i/8] & (1 << (7 - i%8))) != 0 {
			return IPAddress{
				IP:  ip,
				Pre: pre,
			}, nil
		}
	}
	return IPAddress{}, errors.New("host part of IP address bound to interface should not be 0")
}

func (r IPAddress) String() string {
	return fmt.Sprintf("%s/%d", r.IP, r.Pre)
}

func ParseIPAddress(s string) (IPAddress, error) {
	ip, pre, err := parseIPPrefix(s)
	if err != nil {
		return IPAddress{}, err
	}

	a, err := NewIPAddress(ip, pre)
	if err != nil {
		return IPAddress{}, err
	}

	return a, nil
}

type IPAddresses []IPAddress

func (as IPAddresses) String() string {
	var ss []string
	for _, a := range as {
		ss = append(ss, a.String())
	}
	return strings.Join(ss, ", ")
}

type IPRange struct {
	IP net.IP
	// Prefix bits length of mask.
	Pre uint8
}

func NewIPRange(ip net.IP, pre uint8) (IPRange, error) {
	for i := pre; int(i) < len(ip)*8; i++ {
		if (ip[i/8] & (1 << (7 - i%8))) != 0 {
			return IPRange{}, fmt.Errorf("outside of IP range mask should be ending with 0 at %d", i)
		}
	}
	return IPRange{
		IP:  ip,
		Pre: pre,
	}, nil
}

func (r IPRange) String() string {
	return fmt.Sprintf("%s/%d", r.IP, r.Pre)
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

func ParseIPRange(s string) (IPRange, error) {
	ip, pre, err := parseIPPrefix(s)
	if err != nil {
		return IPRange{}, err
	}

	r, err := NewIPRange(ip, pre)
	if err != nil {
		return IPRange{}, err
	}

	return r, nil
}

type IPRanges []IPRange

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
	Host string
	Port uint16
}

func (a ExternalEndpoint) String() string {
	return fmt.Sprintf("%s:%d", a.Host, a.Port)
}

func ParseExternalEndpoint(s string) (ExternalEndpoint, error) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			h := s[:i]
			p := s[i+1:]

			if !valid.IsDNSName(h) {
				return ExternalEndpoint{}, fmt.Errorf("invalid DNS name in host part %q", h)
			}

			port, err := strconv.Atoi(p)
			if err != nil {
				return ExternalEndpoint{}, fmt.Errorf("invalid form in port part %q: %s", p, err)
			}
			if port < portMin || port > portMax {
				return ExternalEndpoint{}, fmt.Errorf("port number %d is out of port range", port)
			}

			return ExternalEndpoint{
				Host: h,
				Port: uint16(port),
			}, nil
		}
	}
	return ExternalEndpoint{}, errors.New("not seperated into host and port parts by colon")
}
