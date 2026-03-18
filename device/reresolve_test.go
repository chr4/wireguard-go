/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// reResolvingBind is a Bind whose ParseEndpoint simulates DNS changes by
// returning a different IP address after the first resolution.
type reResolvingBind struct {
	resolveCount atomic.Int32
	ip1          netip.Addr
	ip2          netip.Addr
	port         uint16
}

func (b *reResolvingBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return nil, 0, nil
}
func (b *reResolvingBind) Close() error                               { return nil }
func (b *reResolvingBind) SetMark(mark uint32) error                  { return nil }
func (b *reResolvingBind) Send(bufs [][]byte, ep conn.Endpoint) error { return nil }
func (b *reResolvingBind) BatchSize() int                             { return 1 }

func (b *reResolvingBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	count := b.resolveCount.Add(1)
	ip := b.ip1
	if count > 1 {
		ip = b.ip2
	}
	return &reResolvingEndpoint{addrPort: netip.AddrPortFrom(ip, b.port)}, nil
}

// reResolvingEndpoint is a minimal conn.Endpoint backed by a netip.AddrPort.
type reResolvingEndpoint struct {
	addrPort netip.AddrPort
}

func (e *reResolvingEndpoint) ClearSrc()           {}
func (e *reResolvingEndpoint) SrcToString() string { return "" }
func (e *reResolvingEndpoint) DstToString() string { return e.addrPort.String() }
func (e *reResolvingEndpoint) DstToBytes() []byte  { b := e.addrPort.Addr().As16(); return b[:] }
func (e *reResolvingEndpoint) DstIP() netip.Addr   { return e.addrPort.Addr() }
func (e *reResolvingEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// TestReResolveConfiguredEndpoint verifies that when a peer's configured
// endpoint is a hostname (not a raw IP), reResolveConfiguredEndpoint actually
// performs a fresh DNS lookup and updates the endpoint to the new IP address.
func TestReResolveConfiguredEndpoint(t *testing.T) {
	ip1 := netip.MustParseAddr("1.2.3.4")
	ip2 := netip.MustParseAddr("5.6.7.8")

	bind := &reResolvingBind{ip1: ip1, ip2: ip2, port: 51820}

	tun := tuntest.NewChannelTUN()

	dev := NewDevice(tun.TUN(), bind, NewLogger(LogLevelSilent, ""))
	defer dev.Close()

	if err := dev.Up(); err != nil {
		t.Fatalf("failed to bring up device: %v", err)
	}

	// Generate a key pair for our own device.
	privKey, err := newPrivateKey()
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	// Generate a key pair for the peer.
	peerPrivKey, err := newPrivateKey()
	if err != nil {
		t.Fatalf("failed to generate peer private key: %v", err)
	}
	peerPubKey := peerPrivKey.publicKey()

	// Configure the device and peer. The endpoint is set as a hostname string
	// so that reResolveConfiguredEndpoint will call ParseEndpoint (simulating
	// DNS re-resolution) rather than just parsing a static IP.
	cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=myserver.example.com:51820\nallowed_ip=10.0.0.1/32\n",
		hex.EncodeToString(privKey[:]),
		hex.EncodeToString(peerPubKey[:]),
	)
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatalf("IpcSet failed: %v", err)
	}

	// Retrieve the peer.
	dev.peers.RLock()
	peer := dev.peers.keyMap[peerPubKey]
	dev.peers.RUnlock()
	if peer == nil {
		t.Fatal("peer not found after IpcSet")
	}

	// After IpcSet, ParseEndpoint was called once → endpoint should be ip1.
	peer.endpoint.Lock()
	initialIP := peer.endpoint.val.DstIP()
	peer.endpoint.Unlock()

	if initialIP != ip1 {
		t.Errorf("initial endpoint IP: got %v, want %v", initialIP, ip1)
	}

	// Simulate a DNS change: the next ParseEndpoint call will return ip2.
	// reResolveConfiguredEndpoint must call ParseEndpoint again with the
	// hostname, not cache the previously-resolved IP.
	peer.reResolveConfiguredEndpoint()

	peer.endpoint.Lock()
	resolvedIP := peer.endpoint.val.DstIP()
	peer.endpoint.Unlock()

	if resolvedIP != ip2 {
		t.Errorf("after re-resolution, endpoint IP: got %v, want %v (re-resolution did not use new DNS result)", resolvedIP, ip2)
	}
}
