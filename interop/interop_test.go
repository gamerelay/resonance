// Interop: pion's TURN client (github.com/pion/turn, the stack gamerelay.io's Go relay was
// built on) against the Rust node, over real UDP on loopback. Run from the repo root:
//
//	cargo build --release && (cd interop && go test ./...)
package interop

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pion/turn/v4"
)

const nodeKey = "fiahLYMg85YkiFJQ0Xp3Bl0x3pXkUhI4nMU8jj6QRio"

// The control plane's credentials (gamerelay.io apps/server/src/turn.ts).
func credentials(room, player string) (string, string) {
	user := fmt.Sprintf("%d:ins_x:%s:%s", time.Now().Add(time.Hour).Unix(), room, player)
	mac := hmac.New(sha1.New, []byte(nodeKey))
	mac.Write([]byte(user))
	return user, base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func startNode(t *testing.T) string {
	t.Helper()
	bin, _ := filepath.Abs("../target/release/resonance-node")
	if _, err := os.Stat(bin); err != nil {
		t.Skip("build it first: cargo build --release")
	}
	l, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	_ = l.Close()
	cmd := exec.Command(bin)
	cmd.Env = []string{"TURN_SECRET=" + nodeKey, "TURN_PUBLIC_IP=127.0.0.1", fmt.Sprintf("TURN_PORT=%d", port)}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	time.Sleep(200 * time.Millisecond)
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func client(t *testing.T, server, room, player string) (*turn.Client, net.PacketConn) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	user, pass := credentials(room, player)
	c, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: server, TURNServerAddr: server, Conn: conn,
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
		t.Fatalf("allocate as %s: %v", player, err)
	}
	t.Cleanup(func() { _ = relayConn.Close(); c.Close(); _ = conn.Close() })
	return c, relayConn
}

// exchange: a and b each write to the other's relay address until one packet gets through each
// way (pion creates the permission, then a channel, on the first write), or the deadline.
func exchange(a, b net.PacketConn, wait time.Duration) (aGot, bGot bool) {
	deadline := time.Now().Add(wait)
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) && !(aGot && bGot) {
		_, _ = a.WriteTo([]byte("from a"), b.LocalAddr())
		_, _ = b.WriteTo([]byte("from b"), a.LocalAddr())
		for _, side := range []struct {
			conn net.PacketConn
			want string
			got  *bool
		}{{b, "from a", &bGot}, {a, "from b", &aGot}} {
			_ = side.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			if n, _, err := side.conn.ReadFrom(buf); err == nil && bytes.Equal(buf[:n], []byte(side.want)) {
				*side.got = true
			}
		}
	}
	return
}

func TestBindingAnswersOurAddress(t *testing.T) {
	server := startNode(t)
	c, _ := client(t, server, "g1", "p_a")
	mapped, err := c.SendBindingRequest()
	if err != nil {
		t.Fatal(err)
	}
	if !mapped.(*net.UDPAddr).IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("mapped %v", mapped)
	}
}

func TestTwoPlayersOfOneRoomRelayBothWays(t *testing.T) {
	server := startNode(t)
	_, a := client(t, server, "g1", "p_a")
	_, b := client(t, server, "g1", "p_b")
	if a.LocalAddr().(*net.UDPAddr).Port == b.LocalAddr().(*net.UDPAddr).Port {
		t.Fatal("one relay port for two allocations")
	}
	aGot, bGot := exchange(a, b, 3*time.Second)
	if !aGot || !bGot {
		t.Fatalf("a got %v, b got %v", aGot, bGot)
	}
	// Past the first packets pion binds channels: a burst still arrives, now as ChannelData.
	buf := make([]byte, 1500)
	for i := range 50 {
		if _, err := a.WriteTo([]byte(fmt.Sprintf("n%d", i)), b.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	got := 0
	for {
		_ = b.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, _, err := b.ReadFrom(buf); err != nil {
			break
		}
		got++
	}
	if got < 50 {
		t.Fatalf("b got %d of 50", got)
	}
}

func TestNothingCrossesRooms(t *testing.T) {
	server := startNode(t)
	_, a := client(t, server, "g1", "p_a")
	_, b := client(t, server, "g2", "p_b")
	if aGot, bGot := exchange(a, b, time.Second); aGot || bGot {
		t.Fatalf("across rooms: a got %v, b got %v", aGot, bGot)
	}
}

func TestAWrongPasswordIsRefused(t *testing.T) {
	server := startNode(t)
	conn, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer conn.Close()
	user, _ := credentials("g1", "p_a")
	c, err := turn.NewClient(&turn.ClientConfig{STUNServerAddr: server, TURNServerAddr: server, Conn: conn, Username: user, Password: "wrong", Realm: "gamerelay"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.Listen()
	if _, err := c.Allocate(); err == nil {
		t.Fatal("allocated with a wrong password")
	}
}
