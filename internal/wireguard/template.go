package wireguard

import (
	"bytes"
	"text/template"
)

const (
	srvConfTmpl = `[Interface]
PrivateKey = {{.ServerPrivateKey}}
Address = {{.ServerAddress}}
ListenPort = {{.ListenPort}}
PostUp = {{.PostUp}}
PostDown = {{.PostDown}}{{range .Devices}}

[Peer]
PublicKey = {{.DevicePublicKey}}
PresharedKey = {{.PeerPresharedKey}}
AllowedIPs = {{.AllowedIPs}}{{end}}`
	devConfTmpl = `[Interface]
PrivateKey = {{.DevicePrivateKey}}
Address = {{.DeviceAddress}}{{if .DNS}}
DNS = {{.DNS}}{{end}}

[Peer]
PublicKey = {{.ServerPublicKey}}
PresharedKey = {{.PeerPresharedKey}}
AllowedIPs = {{.AllowedIPs}}
Endpoint = {{.ServerEndpoint}}`
	devMobileconfigTmpl = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
	<dict>
		<key>PayloadDisplayName</key>
		<string>{{.PayloadDisplayName}}</string>

		<key>PayloadIdentifier</key>
		<string>com.vpn-planet.star.wireguard.{{.PayloadIdentifierUUID}}</string>

		<key>PayloadOrganization</key>
		<string>{{.PayloadOrganization}}</string>

		<key>PayloadRemovalDisallowed</key>
		<false/>

		<key>PayloadType</key>
		<string>Configuration</string>

		<key>PayloadUUID</key>
		<string>{{.PayloadUUID}}</string>

		<key>PayloadVersion</key>
		<integer>1</integer>

		<key>PayloadContent</key>
		<array>
			<dict>
				<key>PayloadDescription</key>
				<string>Configures VPN settings</string>

				<key>PayloadDisplayName</key>
				<string>VPN</string>

				<key>PayloadIdentifier</key>
				<string>donut.local.{{.PayloadContentPayloadIdentifierUUID}}</string>

				<key>PayloadType</key>
				<string>com.apple.vpn.managed</string>

				<key>PayloadUUID</key>
				<string>{{.PayloadContentPayloadUUID}}</string>

				<key>PayloadVersion</key>
				<integer>1</integer>

				<key>UserDefinedName</key>
				<string>{{.UserDefinedName}}</string>

				<key>VPN</key>
				<dict>
					<key>AuthenticationMethod</key>
					<string>Password</string>

					<key>RemoteAddress</key>
					<string>{{.RemoteAddress}}</string>
				</dict>

				<key>VPNSubType</key>
				<string>{{.VPNSubType}}</string>

				<key>VPNType</key>
				<string>VPN</string>

				<key>VendorConfig</key>
				<dict>
					<key>WgQuickConfig</key>
					<string>{{.WgQuickConfig}}</string>
				</dict>
			</dict>
		</array>
	</dict>
</plist>`
)

type srvConfRecipient struct {
	ServerPrivateKey string
	ServerAddress    string
	ListenPort       uint16
	PostUp           string
	PostDown         string
	Devices          []srvConfDevice
}

type srvConfDevice struct {
	DevicePublicKey  string
	PeerPresharedKey string
	AllowedIPs       string
}

type devConfRecipient struct {
	DevicePrivateKey string
	DeviceAddress    string
	DNS              string
	ServerPublicKey  string
	PeerPresharedKey string
	AllowedIPs       string
	ServerEndpoint   string
}

// https://github.com/WireGuard/wireguard-apple/blob/master/MOBILECONFIG.md
type devMobileconfigRecipient struct {
	PayloadOrganization string
	// The name of the configuration profile, visible when installing the profile
	PayloadDisplayName string
	// Should be a WireGuard configuration in wg-quick(8) / wg(8) format. The keys 'FwMark', 'Table', 'PreUp', 'PostUp', 'PreDown', 'PostDown' and 'SaveConfig' are not supported.
	WgQuickConfig string
	// The name of the WireGuard tunnel. This name shall be used to represent the tunnel in the WireGuard app, and in the System UI for VPNs (Settings > VPN on iOS, System Preferences > Network on macOS).
	UserDefinedName string
	// A non-empty string. This string is displayed as the server name in the System UI for VPNs (Settings > VPN on iOS, System Preferences > Network on macOS).
	RemoteAddress string
	// Should be set as the bundle identifier of the WireGuard app.
	VPNSubType string
	// A reverse-DNS style unique identifier for the profile file. If you install another .mobileconfig file with the same identifier, the new one overwrites the old one.
	PayloadIdentifierUUID string
	// A randomly generated UUID for this payload
	PayloadUUID string
	// Last part of a reverse-DNS style unique identifier for the WireGuard configuration profile.
	PayloadContentPayloadIdentifierUUID string
	// A randomly generated UUID for this payload
	PayloadContentPayloadUUID string
	// "0" or "1"
	OnDemandEnabled string
}

func buildSrvConf(r srvConfRecipient) string {
	t := template.Must(template.New("server.conf.tmpl").Parse(srvConfTmpl))
	buf := new(bytes.Buffer)
	err := t.Execute(buf, r)
	if err != nil {
		panic(err)
	}
	return buf.String()
}

func buildDevConf(r devConfRecipient) string {
	t := template.Must(template.New("device.conf.tmpl").Parse(devConfTmpl))
	buf := new(bytes.Buffer)
	err := t.Execute(buf, r)
	if err != nil {
		panic(err)
	}
	return buf.String()
}

func buildDevMobileconfig(r devMobileconfigRecipient) string {
	t := template.Must(template.New("device.mobileconfig.tmpl").Parse(devMobileconfigTmpl))
	buf := new(bytes.Buffer)
	err := t.Execute(buf, r)
	if err != nil {
		panic(err)
	}
	return buf.String()
}
