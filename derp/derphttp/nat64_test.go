// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derphttp

import (
	"net/netip"
	"testing"

	"tailscale.com/tailcfg"
)

func TestDialTargetsIncludesNAT64Candidate(t *testing.T) {
	n := &tailcfg.DERPNode{
		HostName: "derp.example.com",
		IPv4:     "102.67.165.185",
		IPv6:     "2c0f:edb0:0:10::b59",
	}
	got := dialTargets(n, netip.MustParsePrefix("64:ff9b::/96"), true)
	want := []dialTarget{
		{addr: "102.67.165.185", proto: "tcp4"},
		{addr: "64:ff9b::6643:a5b9", proto: "tcp6"},
		{addr: "2c0f:edb0:0:10::b59", proto: "tcp6"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v targets, want %v: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("target %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
