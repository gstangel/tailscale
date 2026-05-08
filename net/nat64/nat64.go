// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package nat64 contains helpers for discovering and using NAT64 prefixes.
package nat64

import "net/netip"

// IPv4OnlyARPA is the DNS name specified by RFC 7050 for NAT64 prefix
// discovery.
const IPv4OnlyARPA = "ipv4only.arpa"

var (
	ipv4OnlyARPAAddrs = [...]netip.Addr{
		netip.AddrFrom4([4]byte{192, 0, 0, 170}),
		netip.AddrFrom4([4]byte{192, 0, 0, 171}),
	}
	validPrefixLens = [...]int{32, 40, 48, 56, 64, 96}
)

// Synthesize returns the IPv6 representation of v4 using prefix, following the
// address embedding format from RFC 6052.
func Synthesize(prefix netip.Prefix, v4 netip.Addr) (_ netip.Addr, ok bool) {
	if !v4.Is4() || !prefix.IsValid() || !prefix.Addr().Is6() || !validPrefixLen(prefix.Bits()) {
		return netip.Addr{}, false
	}

	out := prefix.Masked().Addr().As16()
	v4b := v4.As4()
	writeBit := prefix.Bits()
	for _, b := range v4b {
		for bit := 7; bit >= 0; bit-- {
			if writeBit == 64 {
				// Bits 64 through 71 are reserved and must be zero for
				// prefix lengths shorter than 96 bits.
				writeBit = 72
			}
			if b&(1<<bit) != 0 {
				out[writeBit/8] |= 1 << (7 - (writeBit % 8))
			}
			writeBit++
		}
	}
	return netip.AddrFrom16(out), true
}

// DiscoverPrefixFromAAAA derives the NAT64 prefix from AAAA answers for
// ipv4only.arpa, as specified by RFC 7050.
func DiscoverPrefixFromAAAA(addrs []netip.Addr) (_ netip.Prefix, ok bool) {
	seen := map[netip.Prefix]map[netip.Addr]bool{}
	for _, a := range addrs {
		if !a.Is6() {
			continue
		}
		for _, v4 := range ipv4OnlyARPAAddrs {
			for _, bits := range validPrefixLens {
				p := netip.PrefixFrom(a, bits).Masked()
				if got, ok := Synthesize(p, v4); ok && got == a {
					if seen[p] == nil {
						seen[p] = map[netip.Addr]bool{}
					}
					seen[p][v4] = true
					if len(seen[p]) >= len(ipv4OnlyARPAAddrs) {
						return p, true
					}
				}
			}
		}
	}
	return netip.Prefix{}, false
}

func validPrefixLen(bits int) bool {
	for _, b := range validPrefixLens {
		if bits == b {
			return true
		}
	}
	return false
}
