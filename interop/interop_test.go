// Interop: pion's TURN client (github.com/pion/turn, the stack gamerelay.io's Go relay was
// built on) against the Rust node, over real UDP on loopback. Run from the repo root:
//
//	cargo build --release && (cd interop && go test ./...)
package interop

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/gamerelay/resonance/interop/ticket"
	"github.com/pion/turn/v4"
)

// A ticket for a test node (docs/PROTOCOL.md, "Tickets"): from the issuer it trusts, for its
// sealing key.
func credentials(room, player string) (string, string) {
	return ticket.Mint(ticket.Issuer, time.Now().Add(time.Hour).Unix(), "ins_x", room, player, ticket.SealPublic(ticket.NodeSeed))
}

func startNode(t *testing.T) string {
	t.Helper()
	return startNodeWith(t)
}

// startNodeWith: a node with more of its settings (KEY=value); its UDP and TCP address.
func startNodeWith(t *testing.T, env ...string) string {
	t.Helper()
	bin, _ := filepath.Abs("../target/release/resonance-node")
	if _, err := os.Stat(bin); err != nil {
		// Locally a reminder; in CI a failure, so a missing build can't pass as a skip.
		if os.Getenv("CI") != "" {
			t.Fatalf("no node at %s: cargo build --release", bin)
		}
		t.Skip("build it first: cargo build --release")
	}
	l, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	_ = l.Close()
	state, err := ticket.StateDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin)
	cmd.Env = append([]string{"RESONANCE_STATE_DIR=" + state, "RESONANCE_ISSUERS=" + ticket.IssuerPublic(), "TURN_PUBLIC_IP=127.0.0.1", fmt.Sprintf("TURN_PORT=%d", port)}, env...)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	server := fmt.Sprintf("127.0.0.1:%d", port)
	waitForNode(t, server, env)
	return server
}

// waitForNode: until the node answers a Binding over UDP, and its TCP listeners (if any) take
// connections. Listeners are bound before the loop starts, so the Binding answer comes last.
func waitForNode(t *testing.T, server string, env []string) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	to, _ := net.ResolveUDPAddr("udp4", server)
	req := []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	buf := make([]byte, 1500)
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		_, _ = conn.WriteTo(req, to)
		_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		if _, _, err := conn.ReadFrom(buf); err == nil {
			return
		}
	}
	t.Fatalf("the node at %s never answered (settings %v)", server, env)
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
