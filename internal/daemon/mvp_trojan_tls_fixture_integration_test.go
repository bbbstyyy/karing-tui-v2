//go:build integration && linux

package daemon

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
	"sync"
	"testing"
	"time"
)

const mvpTrojanServerName = "mvp-trojan.internal.invalid"
const mvpTrojanSecret = "MVP_TROJAN_PASSWORD_NOT_FOR_LOGS"

// An independent loopback Trojan TLS peer: it checks the real SHA224 password
// frame, TCP command, and target BEFORE opening any connection to the echo.
func startMVPLocalTrojanTLS(t *testing.T, target netip.AddrPort) (netip.AddrPort, string, <-chan struct{}, func()) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: mvpTrojanServerName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(3 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              []string{mvpTrojanServerName},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKey})
	pair, err := tls.X509KeyPair(rootPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(t.TempDir(), "trojan-test-root.pem")
	if err := os.WriteFile(rootPath, rootPEM, 0o600); err != nil {
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
	sum := sha256.Sum224([]byte(mvpTrojanSecret))
	wantHash := []byte(hex.EncodeToString(sum[:]))
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
				serveMVPLocalTrojan(conn, target, wantHash, hits)
			}()
		}
	}()
	cleanup := func() {
		once.Do(func() {
			_ = listener.Close()
			wg.Wait()
		})
	}
	return endpoint, rootPath, hits, cleanup
}

func serveMVPLocalTrojan(raw net.Conn, target netip.AddrPort, hash []byte, hits chan<- struct{}) {
	defer raw.Close()
	tlsConn, ok := raw.(*tls.Conn)
	if !ok {
		return
	}
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil ||
		tlsConn.ConnectionState().ServerName != mvpTrojanServerName {
		return
	}
	if !readMVPLocalTrojanRequest(tlsConn, target, hash) {
		return
	}
	upstream, err := (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp4", target.String())
	if err != nil {
		return
	}
	defer upstream.Close()
	select {
	case hits <- struct{}{}:
	default:
	}
	go func() {
		_, _ = io.Copy(upstream, tlsConn)
		_ = upstream.Close()
	}()
	_, _ = io.Copy(tlsConn, upstream)
}

func readMVPLocalTrojanRequest(r io.Reader, target netip.AddrPort, wantHash []byte) bool {
	var credential [58]byte
	if _, err := io.ReadFull(r, credential[:]); err != nil ||
		credential[56] != '\r' || credential[57] != '\n' ||
		subtle.ConstantTimeCompare(credential[:56], wantHash) != 1 {
		return false
	}
	// TCP CONNECT + IPv4 + destination + big-endian port + final CRLF.
	var cmd [2]byte
	if _, err := io.ReadFull(r, cmd[:]); err != nil ||
		cmd != [2]byte{0x01, 0x01} || !target.Addr().Is4() {
		return false
	}
	var destination [8]byte
	if _, err := io.ReadFull(r, destination[:]); err != nil {
		return false
	}
	ip := target.Addr().As4()
	return bytes.Equal(destination[:4], ip[:]) &&
		binary.BigEndian.Uint16(destination[4:6]) == target.Port() &&
		destination[6] == '\r' && destination[7] == '\n'
}

func TestManagedCoreRealTrojanFixtureRejectsWrongAuthenticationAndDestination(t *testing.T) {
	target := netip.MustParseAddrPort("127.0.0.1:23456")
	sum := sha256.Sum224([]byte(mvpTrojanSecret))
	hash := []byte(hex.EncodeToString(sum[:]))
	address := target.Addr().As4()
	frame := make([]byte, 0, 68)
	frame = append(frame, hash...)
	frame = append(frame, '\r', '\n', 0x01, 0x01)
	frame = append(frame, address[:]...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], target.Port())
	frame = append(frame, port[:]...)
	frame = append(frame, '\r', '\n')
	if len(frame) != 68 || !readMVPLocalTrojanRequest(bytes.NewReader(frame), target, hash) {
		t.Fatal("fixture rejected valid Trojan TCP authenticated frame")
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"wrong password", func(b []byte) []byte {
			if b[0] == '0' {
				b[0] = '1'
			} else {
				b[0] = '0'
			}
			return b
		}},
		{"missing password delimiter", func(b []byte) []byte { b[57] = 0; return b }},
		{"UDP command", func(b []byte) []byte { b[58] = 3; return b }},
		{"domain address type", func(b []byte) []byte { b[59] = 3; return b }},
		{"wrong target IP", func(b []byte) []byte { b[60] ^= 1; return b }},
		{"wrong target port", func(b []byte) []byte { b[65] ^= 1; return b }},
		{"missing request delimiter", func(b []byte) []byte { b[67] = 'x'; return b }},
		{"truncated frame", func(b []byte) []byte { return b[:67] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := tc.mutate(append([]byte(nil), frame...))
			if readMVPLocalTrojanRequest(bytes.NewReader(candidate), target, hash) {
				t.Fatal("independent Trojan fixture accepted invalid credential, command or target")
			}
		})
	}
}
