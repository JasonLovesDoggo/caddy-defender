package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
)

// ipToAddrFast is a function to convert net.IP to netip.Addr with potential optimizations  /*Slowest*/
func ipToAddrFast(ip net.IP) (netip.Addr, error) { //nolint:unparam
	if ip == nil {
		return netip.Addr{}, fmt.Errorf("ip is nil")
	}
	if ip4 := ip.To4(); ip4 != nil {
		var addr4 [4]byte
		copy(addr4[:], ip4)
		return netip.AddrFrom4(addr4), nil
	}
	if ip16 := ip.To16(); ip16 != nil {
		var addr16 [16]byte
		copy(addr16[:], ip16)
		return netip.AddrFrom16(addr16), nil
	}
	return netip.Addr{}, fmt.Errorf("invalid IP address")
}

// ipToAddr is the function provided by the user for comparison
func netIPToNetipAddr(ip net.IP) (netip.Addr, error) { //nolint:unparam
	if ip4 := ip.To4(); ip4 != nil {
		return netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}), nil
	}

	if len(ip) == net.IPv6len {
		var addr [16]byte
		copy(addr[:], ip)
		return netip.AddrFrom16(addr), nil
	}

	return netip.Addr{}, errors.New("invalid IP address format")
}

func ipToAddrStd(ip net.IP) (netip.Addr, error) { //nolint:unparam
	if ip == nil {
		return netip.Addr{}, fmt.Errorf("ip is nil")
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid IP address")
	}
	return addr, nil
}

func BenchmarkIPToAddrFastIPv4(b *testing.B) {
	ip := net.ParseIP("192.168.1.1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ipToAddrFast(ip)
	}
}

func BenchmarkNetIPToNetipAddrIPv4(b *testing.B) {
	ip := net.ParseIP("192.168.1.1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = netIPToNetipAddr(ip)
	}
}

func BenchmarkIPToAddrStdIPv4(b *testing.B) {
	ip := net.ParseIP("192.168.1.1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ipToAddrStd(ip)
	}
}

func BenchmarkIPToAddrFastIPv6(b *testing.B) {
	ip := net.ParseIP("2001:db8::1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ipToAddrFast(ip)
	}
}

func BenchmarkNetIPToNetipAddrIPv6(b *testing.B) {
	ip := net.ParseIP("2001:db8::1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = netIPToNetipAddr(ip)
	}
}

func BenchmarkIPToAddrStdIPv6(b *testing.B) {
	ip := net.ParseIP("2001:db8::1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ipToAddrStd(ip)
	}
}
