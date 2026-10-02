//go:build !linux

package tun

import (
	"errors"
)

var ErrTunNotSupported = errors.New("TUN is only supported on Linux")

type DummyTun struct{}

func OpenTun(name string, ipCIDR string, mtu int) (Device, error) {
	return nil, ErrTunNotSupported
}

func (d *DummyTun) Read(b []byte) (int, error)  { return 0, ErrTunNotSupported }
func (d *DummyTun) Write(b []byte) (int, error) { return 0, ErrTunNotSupported }
func (d *DummyTun) Close() error                { return nil }
func (d *DummyTun) Name() string                { return "dummy" }
