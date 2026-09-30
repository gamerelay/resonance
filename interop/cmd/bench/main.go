// bench: one relay binary under load, measured from outside. Pairs of TURN clients (pion's, the
// same for every relay) allocate, bind channels, and send timestamped packets both ways at a
// game-like rate; it reports one-way latency, loss, the relay's CPU time and memory.
//
//	go run ./cmd/bench -relay ../target/release/resonance-node -pairs 200 -rate 60 -size 200
//
// Both relays read the same variables (TURN_SECRET, TURN_PUBLIC_IP, TURN_PORT, TURN_MIN_PORT,
// TURN_MAX_PORT), so any build of either can be measured the same way.
package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pion/turn/v4"
)

const nodeKey = "fiahLYMg85YkiFJQ0Xp3Bl0x3pXkUhI4nMU8jj6QRio"

func credentials(room, player string) (string, string) {
	user := fmt.Sprintf("%d:ins_bench:%s:%s", time.Now().Add(time.Hour).Unix(), room, player)
	mac := hmac.New(sha1.New, []byte(nodeKey))
	mac.Write([]byte(user))
	return user, base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

type side struct {
	client *turn.Client
	conn   net.PacketConn
	relay  net.PacketConn
}

// dial: one player from its own loopback address (Linux answers all of 127.0.0.0/8), since a relay
// allows 64 allocations per client IP.
func dial(server, from, room, player string) (*side, error) {
	conn, err := net.ListenPacket("udp4", from+":0")
	if err != nil {
		return nil, err
	}
	if u, ok := conn.(*net.UDPConn); ok {
		_ = u.SetReadBuffer(1 << 20)
	}
	user, pass := credentials(room, player)
	c, err := turn.NewClient(&turn.ClientConfig{STUNServerAddr: server, TURNServerAddr: server, Conn: conn, Username: user, Password: pass, Realm: "gamerelay"})
	if err != nil {
		return nil, err
	}
	if err := c.Listen(); err != nil {
		return nil, err
	}
	r, err := c.Allocate()
	if err != nil {
		return nil, fmt.Errorf("allocate %s/%s: %w", room, player, err)
	}
	return &side{c, conn, r}, nil
}

// psOf: the relay's CPU seconds so far and its resident memory in KB (from /proc on Linux).
func psOf(pid int) (cpu float64, rssKB int) {
	if stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		f := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+2:]))
		utime, _ := strconv.ParseFloat(f[11], 64)
		stime, _ := strconv.ParseFloat(f[12], 64)
		cpu = (utime + stime) / 100 // USER_HZ
		status, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "VmRSS:") {
				rssKB, _ = strconv.Atoi(strings.Fields(line)[1])
			}
		}
		return
	}
	out, err := exec.Command("ps", "-o", "time=,rss=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, 0
	}
	f := strings.Fields(string(out))
	if len(f) < 2 {
		return 0, 0
	}
	// [[hh:]mm:]ss.cc
	parts := strings.Split(f[0], ":")
	mult := 1.0
	for i := len(parts) - 1; i >= 0; i-- {
		v, _ := strconv.ParseFloat(parts[i], 64)
		cpu += v * mult
		mult *= 60
	}
	rssKB, _ = strconv.Atoi(f[1])
	return
}

func pct(xs []time.Duration, p float64) time.Duration {
	if len(xs) == 0 {
		return 0
	}
	return xs[min(len(xs)-1, int(float64(len(xs))*p))]
}

func main() {
	bin := flag.String("relay", "", "the relay binary")
	name := flag.String("name", "", "a label for the report")
	pairs := flag.Int("pairs", 100, "pairs of players, each pair one room")
	rate := flag.Int("rate", 60, "packets a second, per player")
	size := flag.Int("size", 200, "bytes per packet")
	dur := flag.Duration("duration", 10*time.Second, "how long to measure")
	port := flag.Int("port", 34780, "the relay's UDP port")
	spread := flag.Bool("spread", false, "each pair from its own 127.1.x.y address (Linux)")
	flag.Parse()
	if *bin == "" {
		log.Fatal("-relay is required")
	}
	if *size < 16 {
		*size = 16
	}
	var lim syscall.Rlimit
	_ = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim)
	lim.Cur = min(lim.Max, 65536)
	_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)

	cmd := exec.Command(*bin)
	cmd.Env = []string{"TURN_SECRET=" + nodeKey, "TURN_PUBLIC_IP=127.0.0.1", fmt.Sprintf("TURN_PORT=%d", *port), "TURN_MIN_PORT=40000", "TURN_MAX_PORT=59999"}
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	time.Sleep(300 * time.Millisecond)
	server := fmt.Sprintf("127.0.0.1:%d", *port)
	_, rssIdle := psOf(cmd.Process.Pid)

	sides := make([][2]*side, *pairs)
	for i := range sides {
		from := "127.0.0.1"
		if *spread {
			from = fmt.Sprintf("127.1.%d.%d", i/200, i%200+1)
		}
		for j, p := range []string{"a", "b"} {
			s, err := dial(server, from, fmt.Sprintf("r%d", i), fmt.Sprintf("p%d%s", i, p))
			if err != nil {
				log.Fatal(err)
			}
			sides[i][j] = s
		}
	}
	_, rssAllocated := psOf(cmd.Process.Pid)

	start := time.Now()
	var measuring atomic.Bool
	var sent, recv atomic.Int64
	var mu sync.Mutex
	var lat []time.Duration
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for _, pr := range sides {
		for j := range 2 {
			me, peer := pr[j], pr[1-j]
			// Receiver.
			wg.Add(1)
			go func() {
				defer wg.Done()
				buf := make([]byte, 2048)
				local := make([]time.Duration, 0, 1024)
				for {
					_ = me.relay.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
					n, _, err := me.relay.ReadFrom(buf)
					select {
					case <-stop:
						mu.Lock()
						lat = append(lat, local...)
						mu.Unlock()
						return
					default:
					}
					// Counted by the flag it was sent with, so packets still in flight when the
					// window closes land in the drain below instead of counting as lost.
					if err != nil || n < 9 || buf[8] != 1 {
						continue
					}
					d := time.Since(start) - time.Duration(binary.BigEndian.Uint64(buf))
					local = append(local, d)
					recv.Add(1)
				}
			}()
			// Sender: at rate, with a random phase so the pairs don't send in lockstep.
			wg.Add(1)
			go func() {
				defer wg.Done()
				payload := make([]byte, *size)
				interval := time.Second / time.Duration(*rate)
				time.Sleep(time.Duration(time.Now().UnixNano() % int64(interval)))
				t := time.NewTicker(interval)
				defer t.Stop()
				for {
					select {
					case <-stop:
						return
					case <-t.C:
						binary.BigEndian.PutUint64(payload, uint64(time.Since(start)))
						m := measuring.Load()
						payload[8] = 0
						if m {
							payload[8] = 1
						}
						_, _ = me.relay.WriteTo(payload, peer.relay.LocalAddr())
						if m {
							sent.Add(1)
						}
					}
				}
			}()
		}
	}
	// Warm up: permissions and channels get made, then measure.
	time.Sleep(3 * time.Second)
	cpu0, _ := psOf(cmd.Process.Pid)
	measuring.Store(true)
	time.Sleep(*dur)
	measuring.Store(false)
	cpu1, rssLoaded := psOf(cmd.Process.Pid)
	time.Sleep(300 * time.Millisecond) // the last packets land
	close(stop)
	wg.Wait()

	sort.Slice(lat, func(a, b int) bool { return lat[a] < lat[b] })
	s, r := sent.Load(), recv.Load()
	loss := 0.0
	if s > 0 {
		loss = 100 * float64(s-r) / float64(s)
	}
	pps := float64(s) / dur.Seconds()
	fmt.Printf("%-6s pairs=%-4d pps=%-7.0f p50=%-9v p99=%-9v p99.9=%-9v max=%-9v loss=%.3f%% cpu=%.1f%% rss idle=%dKB allocated=%dKB loaded=%dKB (%.1f KB/alloc)\n",
		*name, *pairs, pps, pct(lat, .5).Round(time.Microsecond), pct(lat, .99).Round(time.Microsecond), pct(lat, .999).Round(time.Microsecond),
		pct(lat, 1).Round(time.Microsecond), loss, 100*(cpu1-cpu0)/dur.Seconds(), rssIdle, rssAllocated, rssLoaded,
		float64(rssAllocated-rssIdle)/float64(2**pairs))
	_ = os.Stdout.Sync()
}
