// Real browsers' TURN clients against the node: two pages open a WebRTC data channel to each
// other, relay only (iceTransportPolicy 'relay'), through a resonance-node on this machine's own
// network address (Firefox leaves loopback out of ICE). Every pairing of Chromium, Firefox and
// WebKit, both directions of the offer. Plain RTCPeerConnection, no SDK: this is the browsers'
// own TURN clients (libwebrtc; Firefox's nICEr) and nothing else.
//
// In the Playwright image (browsers included), with the node built for Linux:
//   docker run --rm -v "$PWD":/w -w /w/interop/browsers mcr.microsoft.com/playwright:v1.63.0-noble \
//     sh -c 'npm i -s playwright@1.63.0 && NODE_BIN=/w/target/release/resonance-node node relay.mjs'
import { createHmac } from 'node:crypto';
import { spawn } from 'node:child_process';
import { networkInterfaces } from 'node:os';
import { chromium, firefox, webkit } from 'playwright';

const KEY = 'fiahLYMg85YkiFJQ0Xp3Bl0x3pXkUhI4nMU8jj6QRio';
const PORT = 34810;
const ip = Object.values(networkInterfaces()).flat().find((a) => a && a.family === 'IPv4' && !a.internal)?.address;
if (!ip) throw new Error('no non-loopback IPv4 address');

const node = spawn(process.env.NODE_BIN, [], { env: { TURN_SECRET: KEY, TURN_PUBLIC_IP: ip, TURN_PORT: String(PORT) }, stdio: ['ignore', 'inherit', 'inherit'] });
await new Promise((r) => setTimeout(r, 300));

// The control plane's credentials (gamerelay.io apps/server/src/turn.ts).
function ice(room, player) {
  const username = `${Math.floor(Date.now() / 1000) + 3600}:ins:${room}:${player}`;
  const credential = createHmac('sha1', KEY).update(username).digest('base64');
  return [{ urls: [`turn:${ip}:${PORT}`], username, credential }];
}

const launchers = {
  chromium: () => chromium.launch(),
  firefox: () => firefox.launch(),
  webkit: () => webkit.launch(),
};

async function side(browser, iceServers) {
  const page = await browser.newPage();
  await page.goto('about:blank');
  await page.evaluate((iceServers) => {
    const pc = new RTCPeerConnection({ iceServers, iceTransportPolicy: 'relay' });
    const w = window;
    w.pc = pc;
    w.got = [];
    w.cands = [];
    w.errs = [];
    pc.onicecandidate = (e) => e.candidate && w.cands.push(e.candidate.toJSON());
    pc.onicecandidateerror = (e) => w.errs.push(`${e.errorCode} ${e.errorText}`);
    pc.ondatachannel = (e) => {
      w.dc = e.channel;
      e.channel.onmessage = (m) => w.got.push(m.data);
    };
  }, iceServers);
  return page;
}

async function connect(a, b) {
  const offer = await a.evaluate(async () => {
    window.dc = window.pc.createDataChannel('game');
    window.dc.onmessage = (m) => window.got.push(m.data);
    await window.pc.setLocalDescription(await window.pc.createOffer());
    return window.pc.localDescription.toJSON();
  });
  const answer = await b.evaluate(async (offer) => {
    await window.pc.setRemoteDescription(offer);
    await window.pc.setLocalDescription(await window.pc.createAnswer());
    return window.pc.localDescription.toJSON();
  }, offer);
  await a.evaluate((answer) => window.pc.setRemoteDescription(answer), answer);
  // Trickle candidates both ways until connected.
  const deadline = Date.now() + 20_000;
  const sent = [0, 0];
  for (;;) {
    for (const [i, from, to] of [[0, a, b], [1, b, a]]) {
      const cands = await from.evaluate(() => window.cands);
      for (const c of cands.slice(sent[i])) await to.evaluate((c) => window.pc.addIceCandidate(c), c);
      sent[i] = cands.length;
    }
    const open = await Promise.all([a, b].map((p) => p.evaluate(() => window.dc?.readyState === 'open')));
    if (open.every(Boolean)) return;
    if (Date.now() > deadline) {
      const why = await Promise.all([a, b].map((p) => p.evaluate(() => ({ ice: window.pc.iceConnectionState, cands: window.cands.map((c) => c.candidate), errs: window.errs }))));
      throw new Error(`no channel: ${JSON.stringify(why)}`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
}

const results = [];
const names = Object.keys(launchers);
let n = 0;
for (const x of names) {
  for (const y of names) {
    const room = `r${n++}`;
    let ba, bb;
    try {
      [ba, bb] = [await launchers[x](), await launchers[y]()];
      const a = await side(ba, ice(room, 'a'));
      const b = await side(bb, ice(room, 'b'));
      const t0 = Date.now();
      await connect(a, b);
      const ms = Date.now() - t0;
      for (let i = 0; i < 50; i++) {
        await a.evaluate((i) => window.dc.send(`a${i}`), i);
        await b.evaluate((i) => window.dc.send(`b${i}`), i);
      }
      await new Promise((r) => setTimeout(r, 500));
      const [ga, gb] = await Promise.all([a, b].map((p) => p.evaluate(() => window.got.length)));
      const route = await a.evaluate(async () => {
        for (const s of (await window.pc.getStats()).values()) {
          if (s.type === 'candidate-pair' && s.nominated && s.state === 'succeeded') {
            const stats = await window.pc.getStats();
            return stats.get(s.localCandidateId)?.candidateType;
          }
        }
        return null;
      });
      const ok = ga === 50 && gb === 50 && route === 'relay';
      results.push({ offer: x, answer: y, ok, ms, a_got: gb, b_got: ga, route });
    } catch (e) {
      results.push({ offer: x, answer: y, ok: false, error: String(e.message ?? e).slice(0, 400) });
    } finally {
      await ba?.close();
      await bb?.close();
    }
  }
}
node.kill();
console.table(results.map(({ error, ...r }) => r));
for (const r of results.filter((r) => r.error)) console.log(`${r.offer} → ${r.answer}: ${r.error}`);
process.exit(results.every((r) => r.ok) ? 0 : 1);
