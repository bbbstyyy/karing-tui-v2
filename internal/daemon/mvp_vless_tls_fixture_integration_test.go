//go:build integration && linux

package daemon

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A constrained, independent TLS/VLESS TCP peer for the pinned Core client.
// Authentication is checked before any loopback target is dialed. This
// fixture does not use a remote subscription or third-party relay.
const mvpVLESSServerName = "mvp-vless.internal.invalid"
const mvpVLESSUUID = "01234567-89ab-cdef-0123-456789abcdef"

func startMVPLocalVLESSTLS(t *testing.T, target netip.AddrPort) (netip.AddrPort, string, <-chan struct{}, func()) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: mvpVLESSServerName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(3 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              []string{mvpVLESSServerName},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: priv})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "trusted-test-vless.pem")
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := tls.NewListener(raw, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{pair},
	})
	endpoint, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	uuidHex := strings.ReplaceAll(mvpVLESSUUID, "-", "")
	id, err := hex.DecodeString(uuidHex)
	if err != nil || len(id) != 16 {
		t.Fatal("test fixture UUID is not canonical")
	}
	var wantUUID [16]byte
	copy(wantUUID[:], id)
	hits := make(chan struct{}, 32)
	var wg sync.WaitGroup
	var once sync.Once
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				serveMVPLocalVLESS(conn, target, wantUUID, hits)
			}()
		}
	}()
	cleanup := func() {
		once.Do(func() {
			_ = listener.Close()
			wg.Wait()
		})
	}
	return endpoint, caPath, hits, cleanup
}

func serveMVPLocalVLESS(raw net.Conn, target netip.AddrPort, uuid [16]byte, hits chan<- struct{}) {
	defer raw.Close()
	tlsConn, ok := raw.(*tls.Conn)
	if !ok {
		return
	}
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil ||
		tlsConn.ConnectionState().ServerName != mvpVLESSServerName {
		return
	}
	if !readMVPLocalVLESSRequest(tlsConn, target, uuid) {
		// Wrong credentials/target/command must not be mapped to DIRECT.
		return
	}
	upstream, err := (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp4", target.String())
	if err != nil {
		return
	}
	defer upstream.Close()
	if _, err := tlsConn.Write([]byte{0x00, 0x00}); err != nil {
		return
	}
	select {
	case hits <- struct{}{}:
	default:
	}
	// Target sends an "ok" marker and closes; a second copy handles
	// client-to-target data without assuming the tunneled HTTP method.
	go func() {
		_, _ = io.Copy(upstream, tlsConn)
		_ = upstream.Close()
	}()
	_, _ = io.Copy(tlsConn, upstream)
}

func readMVPLocalVLESSRequest(r io.Reader, target netip.AddrPort, wantUUID [16]byte) bool {
	var fixed [18]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil || fixed[0] != 0x00 ||
		!bytes.Equal(fixed[1:17], wantUUID[:]) {
		return false
	}
	if _, err := io.CopyN(io.Discard, r, int64(fixed[17])); err != nil {
		return false
	}
	var cmdPortType [4]byte
	if _, err := io.ReadFull(r, cmdPortType[:]); err != nil || cmdPortType[0] != 0x01 ||
		binary.BigEndian.Uint16(cmdPortType[1:3]) != target.Port() ||
		cmdPortType[3] != 0x01 || !target.Addr().Is4() {
		return false
	}
	var address [4]byte
	if _, err := io.ReadFull(r, address[:]); err != nil {
		return false
	}
	ip := target.Addr().As4()
	return address == ip
}
