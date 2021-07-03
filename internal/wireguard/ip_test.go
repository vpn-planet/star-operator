package wireguard

import (
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestNewIPAddress(t *testing.T) {
	type Case struct {
		in    IPAddress
		isErr bool
	}
	cases := []Case{
		// IPv4 cases
		{
			in: IPAddress{
				IP:  net.IP{10, 10, 1, 0},
				Pre: 16,
			},
		},

		// IPv4 error cases
		{
			in: IPAddress{
				IP:  net.IP{10, 10, 0, 0},
				Pre: 16,
			},
			isErr: true,
		},

		// IPv6 cases
		{
			in: IPAddress{
				IP:  net.IP{0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
				Pre: 64,
			},
		},

		// IPv6 error cases
		{
			in: IPAddress{
				IP:  net.IP{0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				Pre: 64,
			},
			isErr: true,
		},
	}

	for i, c := range cases {
		out, err := NewIPAddress(c.in.IP, c.in.Pre)
		if !c.isErr {
			if err != nil {
				t.Errorf(
					"#%d: error of NewIPAddress(%q) is %q, but expected to be nil",
					i,
					c.in,
					err,
				)
			}
			if !reflect.DeepEqual(out, c.in) {
				t.Errorf(
					"#%d: output of NewIPAddress(%q) is %#v, but expected to be %#v",
					i,
					c.in,
					out,
					c.in,
				)
			}
		} else {
			if err == nil {
				t.Errorf(
					"#%d: error of NewIPAddress(%q) is nil, but expected not to be nil",
					i,
					c.in,
				)
			}
		}
	}
}

func TestNewIPRange(t *testing.T) {
	type Case struct {
		in    IPRange
		isErr bool
	}
	cases := []Case{
		// IPv4 cases
		{
			in: IPRange{
				IP:  net.IP{10, 10, 0, 0},
				Pre: 16,
			},
		},

		// IPv4 error cases
		{
			in: IPRange{
				IP:  net.IP{10, 10, 0, 1},
				Pre: 16,
			},
			isErr: true,
		},
		{
			in: IPRange{
				IP:  net.IP{10, 10, 0, 0},
				Pre: 8,
			},
			isErr: true,
		},

		// IPv6 cases
		{
			in: IPRange{
				IP:  net.IP{0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				Pre: 64,
			},
		},

		// IPv6 error cases
		{
			in: IPRange{
				IP:  net.IP{0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				Pre: 64,
			},
			isErr: true,
		},
		{
			in: IPRange{
				IP:  net.IP{0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				Pre: 64,
			},
			isErr: true,
		},
	}

	for i, c := range cases {
		out, err := NewIPRange(c.in.IP, c.in.Pre)
		if !c.isErr {
			if err != nil {
				t.Errorf(
					"#%d: error of NewIPRange(%q) is %q, but expected to be nil",
					i,
					c.in,
					err,
				)
			}
			if !reflect.DeepEqual(out, c.in) {
				t.Errorf(
					"#%d: output of NewIPRange(%q) is %#v, but expected to be %#v",
					i,
					c.in,
					out,
					c.in,
				)
			}
		} else {
			if err == nil {
				t.Errorf(
					"#%d: error of NewIPRange(%q) is nil, but expected not to be nil",
					i,
					c.in,
				)
			}
		}
	}
}

func TestIPAddressesString(t *testing.T) {
	type Case struct {
		in  IPAddresses
		out string
	}
	cases := []Case{
		{
			in: IPAddresses{
				{
					IP:  net.IP{10, 10, 0, 1},
					Pre: 16,
				},
			},
			out: "10.10.0.1/16",
		},
		{
			in: IPAddresses{
				{
					IP:  net.IP{10, 10, 0, 1},
					Pre: 16,
				},
				{
					IP:  net.IP{0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
					Pre: 64,
				},
			},
			out: "10.10.0.1/16, fc00::1/64",
		},
	}

	for i, c := range cases {
		out := c.in.String()
		if out != c.out {
			t.Errorf(
				"#%d: output of (%#v).String() is %q, but expected to be %q",
				i,
				c.in,
				out,
				c.out,
			)
		}
	}
}

func TestParseIPPrefix(t *testing.T) {
	type Case struct {
		in    string
		ip    net.IP
		pre   uint8
		isErr bool
		err   string
	}
	cases := []Case{
		// IPv4 cases
		{
			in:  "10.10.10.0/24",
			ip:  net.IP{10, 10, 10, 0},
			pre: 24,
		},
		{
			in:  "10.10.10.0/27",
			ip:  net.IP{10, 10, 10, 0},
			pre: 27,
		},
		{
			in:  "10.0.0.0/32",
			ip:  net.IP{10, 0, 0, 0},
			pre: 32,
		},
		{
			in:  "10.0.0.0",
			ip:  net.IP{10, 0, 0, 0},
			pre: 32,
		},

		// IPv4 error cases
		{
			in:    "10.10.10.0/33",
			isErr: true,
			err:   "out of range",
		},

		// IPv6 cases
		{
			in:  "fd00::/64",
			ip:  net.IP{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			pre: 64,
		},
		{
			in:  "fc00:1000::/65",
			ip:  net.IP{0xfc, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			pre: 65,
		},
		{
			in:  "fc00:1000:1000::1000:1000/128",
			ip:  net.IP{0xfc, 0x00, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00},
			pre: 128,
		},
		{
			in:  "2001:db8:1000::1000:1000",
			ip:  net.IP{0x20, 0x01, 0x0d, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00},
			pre: 128,
		},

		// IPv4 error cases
		{
			in:    "2001:db8::/129",
			isErr: true,
			err:   "out of range",
		},

		// invalid format IP cases
		{
			in:    "a/",
			isErr: true,
			err:   "failed to parse IP part: \"a\"",
		},
		{
			in:    "/a",
			isErr: true,
			err:   "failed to parse IP part: \"\"",
		},
		{
			in:    "",
			isErr: true,
			err:   "failed to parse IP: \"\"",
		},
		{
			in:    "/",
			isErr: true,
			err:   "failed to parse IP part: \"\"",
		},
		{
			in:    "a",
			isErr: true,
			err:   "failed to parse IP: \"a\"",
		},
		{
			in:    ":",
			isErr: true,
			err:   "failed to parse IP: \":\"",
		},
	}

	for i, c := range cases {
		ip, pre, err := ParseIPPrefix(c.in)
		if !c.isErr {
			if err != nil {
				t.Errorf(
					"#%d: error of parseIPPrefix(%q) is %q, but expected to be nil",
					i,
					c.in,
					err,
				)
			}
			if !reflect.DeepEqual(ip, c.ip) || pre != c.pre {
				t.Errorf(
					"#%d: output of parseIPPrefix(%q) is %s/%d, but expected to be %s/%d",
					i,
					c.in,
					ip,
					pre,
					c.ip,
					c.pre,
				)
			}
		} else {
			if err == nil {
				t.Errorf(
					"#%d: error of parseIPPrefix(%q) is nil, but expected not to be nil",
					i,
					c.in,
				)
			}

			es := err.Error()

			if !strings.Contains(es, c.err) {
				t.Errorf(
					"#%d: error of parseIPPrefix(%q) is %q, but expected to contain %q",
					i,
					c.in,
					es,
					c.err,
				)
			}
		}
	}
}

func TestIPRangesString(t *testing.T) {
	type Case struct {
		in  IPRanges
		out string
	}
	cases := []Case{
		{
			in: IPRanges{
				{
					IP:  net.IP{10, 10, 0, 0},
					Pre: 16,
				},
			},
			out: "10.10.0.0/16",
		},
		{
			in: IPRanges{
				{
					IP:  net.IP{10, 10, 0, 0},
					Pre: 16,
				},
				{
					IP:  net.IP{0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
					Pre: 64,
				},
			},
			out: "10.10.0.0/16, fc00::/64",
		},
	}

	for i, c := range cases {
		out := c.in.String()
		if out != c.out {
			t.Errorf(
				"#%d: output of (%#v).String() is %q, but expected to be %q",
				i,
				c.in,
				out,
				c.out,
			)
		}
	}
}

func TestExternalEndpointString(t *testing.T) {
	type Case struct {
		in  ExternalEndpoint
		out string
	}
	cases := []Case{
		{
			in: ExternalEndpoint{
				Host: "localhost",
				Port: 8080,
			},
			out: "localhost:8080",
		},
	}

	for i, c := range cases {
		out := c.in.String()
		if out != c.out {
			t.Errorf(
				"#%d: output of (%#v).String() is %q, but expected to be %q",
				i,
				c.in,
				out,
				c.out,
			)
		}
	}
}

func TestParseExternalEndpoint(t *testing.T) {
	type Case struct {
		in    string
		out   ExternalEndpoint
		isErr bool
		err   string
	}
	cases := []Case{
		{
			in: "localhost:8000",
			out: ExternalEndpoint{
				Host: "localhost",
				Port: 8000,
			},
		},
		{
			in: "vpn1.example.com:51820",
			out: ExternalEndpoint{
				Host: "vpn1.example.com",
				Port: 51820,
			},
		},
		{
			in:    "vpn2.example.com",
			isErr: true,
			err:   "not seperated",
		},
	}

	for i, c := range cases {
		out, err := ParseExternalEndpoint(c.in)
		if !c.isErr {
			if err != nil {
				t.Errorf(
					"#%d: error of ParseExternalEndpoint(%q) is %q, but expected to be nil",
					i,
					c.in,
					err,
				)
			}
			if !reflect.DeepEqual(out, c.out) {
				t.Errorf(
					"#%d: output of ParseExternalEndpoint(%q) is %v, but expected to be %v",
					i,
					c.in,
					out,
					c.out,
				)
			}
		} else {
			if err == nil {
				t.Errorf(
					"#%d: error of ParseExternalEndpoint(%q) is nil, but expected not to be nil",
					i,
					c.in,
				)
			}

			es := err.Error()

			if !strings.Contains(es, c.err) {
				t.Errorf(
					"#%d: error of ParseExternalEndpoint(%q) is %q, but expected to contain %q",
					i,
					c.in,
					es,
					c.err,
				)
			}
		}
	}
}
