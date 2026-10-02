//go:build !windows

package wintun

import (
	"errors"
)

var ErrWintunNotSupported = errors.New("Wintun is only supported on Windows")

type DummyWintun struct{}

func OpenWintun(name string, ipStr string, maskStr string, mtu int) (VirtualAdapter, error) {
	return nil, ErrWintunNotSupported
}

func (d *DummyWintun) AdapterName() string         { return "dummy" }
func (d *DummyWintun) IfIndex() uint32             { return 0 }
func (d *DummyWintun) Read(b []byte) (int, error)  { return 0, ErrWintunNotSupported }
func (d *DummyWintun) Write(b []byte) (int, error) { return 0, ErrWintunNotSupported }
func (d *DummyWintun) Close() error                { return nil }
