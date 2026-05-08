// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package nat64

import (
	"net/netip"
	"testing"
)

func TestSynthesize(t *testing.T) {
	tests := []struct {
		prefix string
		v4     string
		want   string
	}{
		{"64:ff9b::/96", "102.67.165.185", "64:ff9b::6643:a5b9"},
		{"2001:db8::/32", "192.0.2.33", "2001:db8:c000:221::"},
		{"2001:db8:1::/48", "192.0.2.33", "2001:db8:1:c000:2:2100::"},
		{"2001:db8:1:2::/64", "192.0.2.33", "2001:db8:1:2:c0:2:2100:0"},
	}
	for _, tt := range tests {
		prefix := netip.MustParsePrefix(tt.prefix)
		v4 := netip.MustParseAddr(tt.v4)
		got, ok := Synthesize(prefix, v4)
		if !ok {
			t.Fatalf("Synthesize(%v, %v) failed", prefix, v4)
		}
		if got != netip.MustParseAddr(tt.want) {
			t.Errorf("Synthesize(%v, %v) = %v, want %v", prefix, v4, got, tt.want)
		}
	}
}

func TestDiscoverPrefixFromAAAA(t *testing.T) {
	addrs := []netip.Addr{
		netip.MustParseAddr("64:ff9b::c000:aa"),
		netip.MustParseAddr("64:ff9b::c000:ab"),
	}
	got, ok := DiscoverPrefixFromAAAA(addrs)
	if !ok {
		t.Fatal("DiscoverPrefixFromAAAA failed")
	}
	want := netip.MustParsePrefix("64:ff9b::/96")
	if got != want {
		t.Fatalf("DiscoverPrefixFromAAAA = %v, want %v", got, want)
	}
}
