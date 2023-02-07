package util

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSysSupportPowershell(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.SkipNow()
	}
	s := SysSupportPowershell()
	assert.True(t, s)
}

func TestSysPowershellMajorVersion(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.SkipNow()
	}
	v := SysPowershellMajorVersion()
	assert.GreaterOrEqual(t, v, 3)
}

func TestSysGatewayAndDevice(t *testing.T) {
	gw, dev, err := SysGatewayAndDevice()
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		assert.Nil(t, err)
		assert.NotEmpty(t, gw)
		assert.NotEmpty(t, dev)
	default:
		t.SkipNow()
	}
}
