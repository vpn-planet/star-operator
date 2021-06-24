package wireguard

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	ipv4PostUp = "iptables -A FORWARD -i %i -j ACCEPT; " +
		"iptables -A FORWARD -o %i -j ACCEPT; " +
		"iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
	ipv6PostUp = "ip6tables -A FORWARD -i %i -j ACCEPT; " +
		"ip6tables -A FORWARD -o %i -j ACCEPT; " +
		"ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
	ipv4PostDown = "iptables -D FORWARD -i %i -j ACCEPT; " +
		"iptables -D FORWARD -o %i -j ACCEPT; " +
		"iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE"
	ipv6PostDown = "ip6tables -D FORWARD -i %i -j ACCEPT; " +
		"ip6tables -D FORWARD -o %i -j ACCEPT; " +
		"ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE"
	portMin = 1
	portMax = 65535
)

var (
	osToVPNSubType = map[string]string{
		"ios":   "com.wireguard.ios",
		"macos": "com.wireguard.macos",
	}
)

type ServerConf struct {
	IPv4Enabled      bool
	IPv6Enabled      bool
	ListenPort       uint16
	ServerPrivateKey PrivateKey
	ServerAddress    IPAddresses
	Devices          []ServerConfDevice
}

type ServerConfDevice struct {
	DevicePublicKey  PublicKey
	PeerPresharedKey PresharedKey
	AllowedIPs       IPRanges
}

func (d ServerConfDevice) toRecipient() srvConfDevice {
	return srvConfDevice{
		DevicePublicKey:  base64.StdEncoding.EncodeToString(d.DevicePublicKey[:]),
		PeerPresharedKey: base64.StdEncoding.EncodeToString(d.PeerPresharedKey[:]),
		AllowedIPs:       d.AllowedIPs.String(),
	}
}

type DevConf struct {
	DevicePrivateKey PrivateKey
	DeviceAddress    IPAddresses
	ServerPublicKey  PublicKey
	PeerPresharedKey PresharedKey
	AllowedIPs       IPRanges
	ServerEndpoint   ExternalEndpoint
}

type DevMobileconfig struct {
	PayloadOrganization string
	PayloadDisplayName  string
	DevConf             DevConf
	WgQuickConfig       string
	RemoteAddress       string
	// One of "ios", "macos"
	OS                                  string
	PayloadIdentifierUUID               string
	PayloadUUID                         string
	PayloadContentPayloadIdentifierUUID string
	PayloadContentPayloadUUID           string
	OnDemandEnabled                     bool
}

func BuildSrvConf(c ServerConf) (string, error) {
	var ups []string
	var downs []string

	if !c.IPv4Enabled && !c.IPv6Enabled {
		return "", errors.New("at least one of IPv4 and IPv6 should be enabled")
	}

	if c.IPv4Enabled {
		ups = append(ups, ipv4PostUp)
		downs = append(downs, ipv4PostDown)
	}

	if c.IPv6Enabled {
		ups = append(ups, ipv6PostUp)
		downs = append(downs, ipv6PostDown)
	}

	var devs []srvConfDevice
	for _, d := range c.Devices {
		devs = append(devs, d.toRecipient())
	}
	if c.ListenPort < portMin || c.ListenPort > portMax {
		return "", fmt.Errorf("port number %d is out of port range", c.ListenPort)
	}

	return buildSrvConf(srvConfRecipient{
		ServerPrivateKey: base64.StdEncoding.EncodeToString(c.ServerPrivateKey[:]),
		ServerAddress:    c.ServerAddress.String(),
		ListenPort:       c.ListenPort,
		PostUp:           strings.Join(ups, "; "),
		PostDown:         strings.Join(downs, "; "),
		Devices:          devs,
	}), nil
}

func BuildDevConf(c DevConf) (string, error) {
	return buildDevConf(devConfRecipient{
		DevicePrivateKey: base64.StdEncoding.EncodeToString(c.DevicePrivateKey[:]),
		DeviceAddress:    c.DeviceAddress.String(),
		ServerPublicKey:  base64.StdEncoding.EncodeToString(c.ServerPublicKey[:]),
		PeerPresharedKey: base64.StdEncoding.EncodeToString(c.PeerPresharedKey[:]),
		AllowedIPs:       c.AllowedIPs.String(),
		ServerEndpoint:   c.ServerEndpoint.String(),
	}), nil
}

func BuildDevMobileconfig(c DevMobileconfig) (string, error) {
	vpnSubType, ok := osToVPNSubType[c.OS]
	if !ok {
		return "", fmt.Errorf("%v is not supported OS type", c.OS)
	}

	dem := "0"
	if c.OnDemandEnabled {
		dem = "1"
	}

	devConf, err := BuildDevConf(c.DevConf)
	if err != nil {
		return "", err
	}

	return buildDevMobileconfig(devMobileconfigRecipient{
		PayloadOrganization:                 c.PayloadOrganization,
		PayloadDisplayName:                  c.PayloadDisplayName,
		WgQuickConfig:                       devConf,
		RemoteAddress:                       c.RemoteAddress,
		VPNSubType:                          vpnSubType,
		PayloadIdentifierUUID:               c.PayloadIdentifierUUID,
		PayloadUUID:                         c.PayloadUUID,
		PayloadContentPayloadIdentifierUUID: c.PayloadContentPayloadIdentifierUUID,
		PayloadContentPayloadUUID:           c.PayloadContentPayloadUUID,
		OnDemandEnabled:                     dem,
	}), nil
}
