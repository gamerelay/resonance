// TURN over TCP and TLS (RFC 8656 §12.5): pion's client on a stream, relaying with players on
// UDP and on other streams, since everyone in a room shares the relay whatever they reach it by.
package interop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pion/turn/v4"
)

// A certificate for "turn.test", and a pool that trusts it: the client checks it, as browsers do.
func testCert(t *testing.T) (certFile, keyFile string, roots *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "turn.test"},
		DNSNames:     []string{"turn.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	roots = x509.NewCertPool()
	roots.AddCert(cert)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600)
	return
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// A node with TCP on its TURN port and TLS on another: its UDP/TCP address, its TLS address, and
// the roots that trust its certificate.
func startStreamNode(t *testing.T, env ...string) (string, string, *x509.CertPool) {
	t.Helper()
	certFile, keyFile, roots := testCert(t)
	tlsPort := freeTCPPort(t)
	server := startNodeWith(t, append([]string{
		"TURN_TLS_CERT=" + certFile, "TURN_TLS_KEY=" + keyFile,
		fmt.Sprintf("TURN_TLS_PORT=%d", tlsPort), "TURN_TLS_HOST=turn.test",
	}, env...)...)
	return server, fmt.Sprintf("127.0.0.1:%d", tlsPort), roots
}

// A client over a stream: "tcp" to server, or "tls" to server checked against roots.
func streamClient(t *testing.T, how, server string, roots *x509.CertPool, room, player string) (*turn.Client, net.PacketConn, net.Conn) {
	t.Helper()
	var conn net.Conn
	var err error
	switch how {
	case "tcp":
		conn, err = net.Dial("tcp4", server)
	case "tls":
		conn, err = tls.Dial("tcp4", server, &tls.Config{RootCAs: roots, ServerName: "turn.test"})
	}
	if err != nil {
		t.Fatalf("%s to %s: %v", how, server, err)
	}
	user, pass := credentials(room, player)
	c, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: server, TURNServerAddr: server, Conn: turn.NewSTUNConn(conn),
		Username: user, Password: pass, Realm: "gamerelay",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Listen(); err != nil {
		t.Fatal(err)
	}
	relayConn, err := c.Allocate()
	if err != nil {
		t.Fatalf("allocate over %s as %s: %v", how, player, err)
	}
	t.Cleanup(func() { _ = relayConn.Close(); c.Close(); _ = conn.Close() })
	return c, relayConn, conn
}

// burst: n packets a→b once channels are bound (ChannelData, padded on a stream); how many came.
func burst(t *testing.T, a, b net.PacketConn, n int) int {
	t.Helper()
	buf := make([]byte, 1500)
	for i := range n {
		// Odd lengths, so a stream's ChannelData needs padding.
		if _, err := a.WriteTo([]byte(fmt.Sprintf("n%d-%s", i, "xyz"[:i%3])), b.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	got := 0
	for {
		_ = b.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, _, err := b.ReadFrom(buf); err != nil {
			return got
		}
		got++
	}
}

func TestStreamPlayersRelayWithEveryone(t *testing.T) {
	server, tlsServer, roots := startStreamNode(t)
	_, udpA := client(t, server, "g1", "p_udp")
	_, tcpB, _ := streamClient(t, "tcp", server, roots, "g1", "p_tcp")
	_, tlsC, _ := streamClient(t, "tls", tlsServer, roots, "g1", "p_tls")
	for _, pair := range []struct {
		name string
		a, b net.PacketConn
	}{{"udp-tcp", udpA, tcpB}, {"udp-tls", udpA, tlsC}, {"tcp-tls", tcpB, tlsC}} {
		aGot, bGot := exchange(pair.a, pair.b, 3*time.Second)
		if !aGot || !bGot {
			t.Fatalf("%s: a got %v, b got %v", pair.name, aGot, bGot)
		}
		if got := burst(t, pair.a, pair.b, 50); got < 50 {
			t.Fatalf("%s: %d of 50 arrived", pair.name, got)
		}
		if got := burst(t, pair.b, pair.a, 50); got < 50 {
			t.Fatalf("%s back: %d of 50 arrived", pair.name, got)
		}
	}
}

func TestAClosedStreamFreesItsAllocation(t *testing.T) {
	// One allocation per player: the second only fits once the first is gone.
	server, _, roots := startStreamNode(t, "TURN_MAX_PER_PLAYER=1")
	c, relay, conn := streamClient(t, "tcp", server, roots, "g1", "p_a")
	_ = relay
	c.Close()
	_ = conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		user, pass := credentials("g1", "p_a")
		conn2, err := net.Dial("tcp4", server)
		if err != nil {
			t.Fatal(err)
		}
		c2, err := turn.NewClient(&turn.ClientConfig{
			STUNServerAddr: server, TURNServerAddr: server, Conn: turn.NewSTUNConn(conn2),
			Username: user, Password: pass, Realm: "gamerelay",
		})
		if err != nil {
			t.Fatal(err)
		}
		_ = c2.Listen()
		r, err := c2.Allocate()
		if err == nil {
			_ = r.Close()
			c2.Close()
			_ = conn2.Close()
			return
		}
		c2.Close()
		_ = conn2.Close()
		if time.Now().After(deadline) {
			t.Fatalf("the closed stream's allocation is still held: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestJunkOnTheTCPPortIsHungUpOn(t *testing.T) {
	server, tlsServer, _ := startStreamNode(t)
	for _, addr := range []string{server, tlsServer} {
		conn, err := net.Dial("tcp4", addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadAll(conn); err != nil {
			t.Fatalf("%s: not hung up on: %v", addr, err)
		}
		_ = conn.Close()
	}
}

func TestTLSIsCheckedLikeABrowser(t *testing.T) {
	_, tlsServer, roots := startStreamNode(t)
	// Another name than the certificate's: refused by the client.
	if _, err := tls.Dial("tcp4", tlsServer, &tls.Config{RootCAs: roots, ServerName: "other.test"}); err == nil {
		t.Fatal("a certificate for turn.test accepted as other.test")
	}
	conn, err := tls.Dial("tcp4", tlsServer, &tls.Config{RootCAs: roots, ServerName: "turn.test"})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

// A stream writing as fast as it can doesn't hold up everyone else: each client is read for a
// bounded share of each turn of the node's loop.
func TestAFloodingStreamDoesntStallOthers(t *testing.T) {
	server, _, _ := startStreamNode(t)
	flood, err := net.Dial("tcp4", server)
	if err != nil {
		t.Fatal(err)
	}
	defer flood.Close()
	// Binding requests back to back, never reading the answers.
	req := make([]byte, 0, 20*1024)
	for i := range 1024 {
		req = append(req, 0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42)
		req = append(req, byte(i), byte(i>>8), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
	}
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = flood.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
			_, _ = flood.Write(req)
		}
	}()
	defer close(stop)
	time.Sleep(200 * time.Millisecond)
	_, a := client(t, server, "g1", "p_a")
	_, b := client(t, server, "g1", "p_b")
	aGot, bGot := exchange(a, b, 3*time.Second)
	if !aGot || !bGot {
		t.Fatalf("during the flood: a got %v, b got %v", aGot, bGot)
	}
	if got := burst(t, a, b, 50); got < 50 {
		t.Fatalf("during the flood: %d of 50 arrived", got)
	}
}
