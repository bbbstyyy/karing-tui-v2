//go:build integration && linux

package daemon

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// Classic Shadowsocks AEAD (SIP004/SIP007), not Shadowsocks 2022.
// Keep the fixture independent of the Core and its crypto implementation.
const mvpSSMethod = "aes-256-gcm"
const mvpSSPassword = "MVP_SHADOWSOCKS_SECRET_NEVER_IN_API"
const mvpSSKeySize = 32
const mvpSSMaxChunk = 0x3fff

type mvpSSCipher struct {
	aead  cipher.AEAD
	nonce [12]byte
}

// Legacy EVP_BytesToKey: chained MD5 blocks, no salt and one iteration.
// This is required by the classic 2017 Shadowsocks protocol, not a generic
// password-storage primitive and never used for project credentials.
func mvpSSMasterKey(password string) []byte {
	key := make([]byte, 0, mvpSSKeySize)
	var previous []byte
	for len(key) < mvpSSKeySize {
		h := md5.New()
		_, _ = h.Write(previous)
		_, _ = h.Write([]byte(password))
		previous = h.Sum(nil)
		key = append(key, previous...)
	}
	return key[:mvpSSKeySize]
}

// HKDF-SHA1(master,salt,"ss-subkey"), implemented here only to give
// independent fixed-Core interop evidence without a production dependency.
func mvpSSSubkey(master, salt []byte) []byte {
	extract := hmac.New(sha1.New, salt)
	_, _ = extract.Write(master)
	prk := extract.Sum(nil)
	out := make([]byte, 0, mvpSSKeySize)
	var previous []byte
	for counter := byte(1); len(out) < mvpSSKeySize; counter++ {
		expand := hmac.New(sha1.New, prk)
		_, _ = expand.Write(previous)
		_, _ = expand.Write([]byte("ss-subkey"))
		_, _ = expand.Write([]byte{counter})
		previous = expand.Sum(nil)
		out = append(out, previous...)
	}
	return out[:mvpSSKeySize]
}

func newMVPSSCipher(master, salt []byte) (*mvpSSCipher, error) {
	block, err := aes.NewCipher(mvpSSSubkey(master, salt))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &mvpSSCipher{aead: aead}, nil
}

func (c *mvpSSCipher) nextNonce() {
	for i := range c.nonce {
		c.nonce[i]++
		if c.nonce[i] != 0 {
			break
		}
	}
}

func (c *mvpSSCipher) seal(plaintext []byte) []byte {
	encrypted := c.aead.Seal(nil, c.nonce[:], plaintext, nil)
	c.nextNonce()
	return encrypted
}

func (c *mvpSSCipher) open(ciphertext []byte) ([]byte, error) {
	plaintext, err := c.aead.Open(nil, c.nonce[:], ciphertext, nil)
	if err != nil {
		return nil, err
	}
	c.nextNonce()
	return plaintext, nil
}

func (c *mvpSSCipher) readChunk(r io.Reader) ([]byte, bool) {
	// First authenticated part is two bytes of BE payload length.
	var encryptedLength [2 + 16]byte
	if _, err := io.ReadFull(r, encryptedLength[:]); err != nil {
		return nil, false
	}
	encodedLength, err := c.open(encryptedLength[:])
	if err != nil || len(encodedLength) != 2 {
		return nil, false
	}
	size := binary.BigEndian.Uint16(encodedLength)
	if size == 0 || size > mvpSSMaxChunk {
		return nil, false
	}
	// Authenticate payload BEFORE considering its destination address.
	encryptedPayload := make([]byte, int(size)+c.aead.Overhead())
	if _, err := io.ReadFull(r, encryptedPayload); err != nil {
		return nil, false
	}
	plaintext, err := c.open(encryptedPayload)
	if err != nil || len(plaintext) != int(size) {
		return nil, false
	}
	return plaintext, true
}

func mvpSSEncryptedFrame(master, salt, payload []byte) ([]byte, bool) {
	if len(salt) != mvpSSKeySize || len(payload) == 0 || len(payload) > mvpSSMaxChunk {
		return nil, false
	}
	s, err := newMVPSSCipher(master, salt)
	if err != nil {
		return nil, false
	}
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(payload)))
	encoded := append([]byte(nil), salt...)
	encoded = append(encoded, s.seal(size[:])...)
	encoded = append(encoded, s.seal(payload)...)
	return encoded, true
}

func mvpSSRequestMatches(r io.Reader, master []byte, target netip.AddrPort) bool {
	var salt [mvpSSKeySize]byte
	if _, err := io.ReadFull(r, salt[:]); err != nil {
		return false
	}
	c, err := newMVPSSCipher(master, salt[:])
	if err != nil {
		return false
	}
	payload, ok := c.readChunk(r)
	if !ok || len(payload) < 7 || payload[0] != 0x01 || !target.Addr().Is4() {
		return false
	}
	wantIP := target.Addr().As4()
	return bytes.Equal(payload[1:5], wantIP[:]) &&
		binary.BigEndian.Uint16(payload[5:7]) == target.Port()
}

func startMVPLocalShadowsocksAEAD(t *testing.T, target netip.AddrPort) (netip.AddrPort, <-chan struct{}, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	master := mvpSSMasterKey(mvpSSPassword)
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
				serveMVPLocalShadowsocksAEAD(conn, target, master, hits)
			}()
		}
	}()
	closeFn := func() {
		once.Do(func() {
			_ = listener.Close()
			wg.Wait()
		})
	}
	return address, hits, closeFn
}

func serveMVPLocalShadowsocksAEAD(conn net.Conn, target netip.AddrPort, master []byte, hits chan<- struct{}) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if !mvpSSRequestMatches(conn, master, target) {
		// Wrong password/salt/tag/target/command never opens upstream.
		return
	}
	remote, err := (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp4", target.String())
	if err != nil {
		return
	}
	defer remote.Close()
	_ = remote.SetReadDeadline(time.Now().Add(3 * time.Second))
	var marker [2]byte
	if _, err := io.ReadFull(remote, marker[:]); err != nil || marker != [2]byte{'o', 'k'} {
		return
	}
	var responseSalt [mvpSSKeySize]byte
	if _, err := rand.Read(responseSalt[:]); err != nil {
		return
	}
	frame, ok := mvpSSEncryptedFrame(master, responseSalt[:], marker[:])
	if !ok {
		return
	}
	// One independent reply stream with a new salt and nonce counter.
	if _, err := io.Copy(conn, bytes.NewReader(frame)); err != nil {
		return
	}
	select {
	case hits <- struct{}{}:
	default:
	}
}

// Fixture correctness checks ensure invalid ciphertext, credentials and
// destinations are rejected before this server could create false evidence.
func TestMVPLocalShadowsocksAEADFixtureAuthentication(t *testing.T) {
	target := netip.MustParseAddrPort("127.0.0.1:23456")
	var salt [mvpSSKeySize]byte
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	master := mvpSSMasterKey(mvpSSPassword)
	ip := target.Addr().As4()
	payload := append([]byte{0x01}, ip[:]...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], target.Port())
	payload = append(payload, port[:]...)
	good, ok := mvpSSEncryptedFrame(master, salt[:], payload)
	if !ok || !mvpSSRequestMatches(bytes.NewReader(good), master, target) {
		t.Fatal("fixture cannot read a correct AES-256-GCM Shadowsocks TCP frame")
	}
	wrongKey := mvpSSMasterKey("INVALID_PASSWORD")
	if mvpSSRequestMatches(bytes.NewReader(good), wrongKey, target) {
		t.Fatal("wrong AES-GCM key was accepted")
	}
	if mvpSSRequestMatches(bytes.NewReader(good), master, netip.MustParseAddrPort("127.0.0.2:23456")) ||
		mvpSSRequestMatches(bytes.NewReader(good), master, netip.MustParseAddrPort("127.0.0.1:23457")) {
		t.Fatal("unauthorized address or port was accepted")
	}
	for _, tc := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{"salt", func(b []byte) []byte { b[0] ^= 1; return b }},
		{"length tag", func(b []byte) []byte { b[35] ^= 1; return b }},
		{"payload tag", func(b []byte) []byte { b[len(b)-1] ^= 1; return b }},
		{"truncated", func(b []byte) []byte { return b[:len(b)-1] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.edit(append([]byte(nil), good...))
			if mvpSSRequestMatches(bytes.NewReader(b), master, target) {
				t.Fatal("tampered or truncated Shadowsocks AEAD frame authenticated")
			}
		})
	}
	if _, ok := mvpSSEncryptedFrame(master, salt[:], make([]byte, mvpSSMaxChunk+1)); ok {
		t.Fatal("oversized Shadowsocks AEAD TCP chunk was accepted")
	}
}
