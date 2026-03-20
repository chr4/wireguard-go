/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

	privKey, err := newPrivateKey()
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
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

// controlledEndpointBind wraps a real Bind but overrides ParseEndpoint so that
// tests can change which address a hostname resolves to, simulating a server
// moving to a new IP while its DNS name stays the same.
type controlledEndpointBind struct {
	conn.Bind
	mu     sync.RWMutex
	target netip.AddrPort
}

func (b *controlledEndpointBind) setTarget(addr netip.AddrPort) {
	b.mu.Lock()
	b.target = addr
	b.mu.Unlock()
}

// ParseEndpoint ignores the input string (the hostname) and returns an endpoint
// for the currently configured target address, mimicking what a DNS lookup
// returning the current server IP would produce.
func (b *controlledEndpointBind) ParseEndpoint(_ string) (conn.Endpoint, error) {
	b.mu.RLock()
	target := b.target
	b.mu.RUnlock()
	return b.Bind.ParseEndpoint(target.String())
}

// sendPing injects a fake ICMP packet into src's TUN and waits for it to
// arrive at dst's TUN, proving that the WireGuard session between them works.
func sendPing(t *testing.T, src, dst *testPeer, timeout time.Duration) {
	t.Helper()
	msg := tuntest.Ping(src.ip, dst.ip)
	select {
	case dst.tun.Outbound <- msg:
	case <-time.After(timeout):
		t.Fatal("timed out injecting ping packet")
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case got := <-src.tun.Inbound:
		if !bytes.Equal(msg, got) {
			t.Error("ping payload was corrupted in transit")
		}
	case <-timer.C:
		t.Fatal("timed out waiting for ping to arrive")
	}
}

// TestReconnectAfterServerIPChange is an end-to-end integration test that
// verifies automatic reconnection when a server moves to a different IP address.
//
// It uses real UDP sockets on loopback, simulating an IP change by moving the
// server to a new port (equivalent on a single machine) and updating the
// client's endpoint resolution to point there.
func TestReconnectAfterServerIPChange(t *testing.T) {
	// Generate key pairs for both sides.
	clientPriv, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	serverPriv, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	clientPub := clientPriv.publicKey()
	serverPub := serverPriv.publicKey()

	clientIP := netip.AddrFrom4([4]byte{1, 0, 0, 1})
	serverIP := netip.AddrFrom4([4]byte{1, 0, 0, 2})
	loopback := netip.MustParseAddr("127.0.0.1")

	// --- Server 1: first "IP address" ---
	serverTUN1 := tuntest.NewChannelTUN()
	serverBind1 := conn.NewDefaultBind()
	serverDev1 := NewDevice(serverTUN1.TUN(), serverBind1, NewLogger(LogLevelSilent, ""))
	defer serverDev1.Close()

	if err := serverDev1.IpcSet(uapiCfg(
		"private_key", hex.EncodeToString(serverPriv[:]),
		"listen_port", "0",
		"replace_peers", "true",
		"public_key", hex.EncodeToString(clientPub[:]),
		"replace_allowed_ips", "true",
		"allowed_ip", clientIP.String()+"/32",
	)); err != nil {
		t.Fatalf("server1 IpcSet: %v", err)
	}
	if err := serverDev1.Up(); err != nil {
		t.Fatalf("server1 Up: %v", err)
	}
	serverPort1 := serverDev1.net.port
	t.Logf("server1 listening on 127.0.0.1:%d", serverPort1)

	// --- Client: wraps a real bind with controllable endpoint resolution ---
	clientTUN := tuntest.NewChannelTUN()
	clientRealBind := conn.NewDefaultBind()
	clientBind := &controlledEndpointBind{
		Bind:   clientRealBind,
		target: netip.AddrPortFrom(loopback, serverPort1),
	}
	clientDev := NewDevice(clientTUN.TUN(), clientBind, NewLogger(LogLevelSilent, ""))
	defer clientDev.Close()

	if err := clientDev.IpcSet(uapiCfg(
		"private_key", hex.EncodeToString(clientPriv[:]),
		"listen_port", "0",
		"replace_peers", "true",
		"public_key", hex.EncodeToString(serverPub[:]),
		"replace_allowed_ips", "true",
		"allowed_ip", serverIP.String()+"/32",
	)); err != nil {
		t.Fatalf("client IpcSet: %v", err)
	}
	// Set endpoint as a hostname string so peer.endpoint.configured holds
	// "server.example.com:0" and reResolveConfiguredEndpoint will call
	// ParseEndpoint (i.e. our controlled resolver) on each retry.
	if err := clientDev.IpcSet(uapiCfg(
		"public_key", hex.EncodeToString(serverPub[:]),
		"endpoint", fmt.Sprintf("server.example.com:%d", serverPort1),
	)); err != nil {
		t.Fatalf("client endpoint IpcSet: %v", err)
	}
	if err := clientDev.Up(); err != nil {
		t.Fatalf("client Up: %v", err)
	}

	// Point server1 at the client's actual listen port.
	clientPort := clientDev.net.port
	if err := serverDev1.IpcSet(uapiCfg(
		"public_key", hex.EncodeToString(clientPub[:]),
		"endpoint", fmt.Sprintf("127.0.0.1:%d", clientPort),
	)); err != nil {
		t.Fatalf("server1 client-endpoint IpcSet: %v", err)
	}

	clientPeer := &testPeer{tun: clientTUN, ip: clientIP}
	serverPeer1 := &testPeer{tun: serverTUN1, ip: serverIP}

	// Phase 1: verify the session works on the original IP.
	t.Log("Phase 1: verifying connectivity to server1")
	sendPing(t, clientPeer, serverPeer1, 5*time.Second)

	// --- Server 2: the "new IP address" (new port on loopback) ---
	// Bring it up with the same server private key so the WireGuard identity
	// (public key) is unchanged — only the network address changes.
	t.Log("Bringing up server2 on new port (simulating IP change)")
	serverTUN2 := tuntest.NewChannelTUN()
	serverBind2 := conn.NewDefaultBind()
	serverDev2 := NewDevice(serverTUN2.TUN(), serverBind2, NewLogger(LogLevelSilent, ""))
	defer serverDev2.Close()

	if err := serverDev2.IpcSet(uapiCfg(
		"private_key", hex.EncodeToString(serverPriv[:]),
		"listen_port", "0",
		"replace_peers", "true",
		"public_key", hex.EncodeToString(clientPub[:]),
		"replace_allowed_ips", "true",
		"allowed_ip", clientIP.String()+"/32",
		"endpoint", fmt.Sprintf("127.0.0.1:%d", clientPort),
	)); err != nil {
		t.Fatalf("server2 IpcSet: %v", err)
	}
	if err := serverDev2.Up(); err != nil {
		t.Fatalf("server2 Up: %v", err)
	}
	serverPort2 := serverDev2.net.port
	t.Logf("server2 listening on 127.0.0.1:%d (new IP)", serverPort2)

	// Shut down server1 — the old IP is now gone.
	serverDev1.Close()

	// Update the client's DNS resolution to point at the new address.
	clientBind.setTarget(netip.AddrPortFrom(loopback, serverPort2))
	t.Logf("DNS updated: server.example.com now resolves to 127.0.0.1:%d", serverPort2)

	// Trigger re-resolution on the client peer — this is what the WireGuard
	// handshake-retry timer calls when handshakes fail (expiredRetransmitHandshake
	// and expiredNewHandshake both call reResolveConfiguredEndpoint).
	clientDev.peers.RLock()
	clientSidePeer := clientDev.peers.keyMap[serverPub]
	clientDev.peers.RUnlock()
	if clientSidePeer == nil {
		t.Fatal("client-side server peer not found")
	}
	clientSidePeer.reResolveConfiguredEndpoint()

	// Confirm the endpoint was updated to the new address before proceeding.
	clientSidePeer.endpoint.Lock()
	gotIP := clientSidePeer.endpoint.val.DstIP()
	clientSidePeer.endpoint.Unlock()
	if gotIP != loopback {
		t.Errorf("re-resolved endpoint IP: got %v, want %v", gotIP, loopback)
	}

	// Force a new handshake now that the endpoint points to server2.  This is
	// what the WireGuard retransmit/new-handshake timers do in production after
	// calling reResolveConfiguredEndpoint.
	// Clear the rate-limit timestamp so SendHandshakeInitiation doesn't skip
	// the send because phase 1's handshake was too recent (within RekeyTimeout).
	clientSidePeer.handshake.mutex.Lock()
	clientSidePeer.handshake.lastSentHandshake = time.Time{}
	clientSidePeer.handshake.mutex.Unlock()
	clientSidePeer.SendHandshakeInitiation(true)

	// Wait for server2 to see the completed handshake before we probe data
	// flow — avoids a race between the async handshake and the ping.
	serverDev2.peers.RLock()
	serverSidePeer2 := serverDev2.peers.keyMap[clientPub]
	serverDev2.peers.RUnlock()
	if serverSidePeer2 == nil {
		t.Fatal("server2-side client peer not found")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if serverSidePeer2.lastHandshakeNano.Load() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if serverSidePeer2.lastHandshakeNano.Load() == 0 {
		t.Fatal("handshake with server2 did not complete within 5 seconds")
	}

	serverPeer2 := &testPeer{tun: serverTUN2, ip: serverIP}

	// Phase 2: verify connectivity is restored through the new address.
	t.Log("Phase 2: verifying connectivity restored to server2 after IP change")
	sendPing(t, clientPeer, serverPeer2, 5*time.Second)
}
