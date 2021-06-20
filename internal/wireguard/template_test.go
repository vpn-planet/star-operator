package wireguard

import (
	"testing"
)

func TestBuildSrvConf(t *testing.T) {
	_ = buildSrvConf(srvConfRecipient{
		Devices: []srvConfDevice{{}},
	})
}

func TestBuildDevConf(t *testing.T) {
	_ = buildDevConf(devConfRecipient{})
}

func TestBuildDevMobileconfig(t *testing.T) {
	_ = buildDevMobileconfig(devMobileconfigRecipient{})
}
