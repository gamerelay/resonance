// Real browsers' TURN clients against the node: two pages open a WebRTC data channel to each
// other, relay only (iceTransportPolicy 'relay'), through a resonance-node on this machine's own
// network address (Firefox leaves loopback out of ICE). Every pairing of Chromium, Firefox and
// WebKit, both directions of the offer. Plain RTCPeerConnection, no SDK: this is the browsers'
// own TURN clients (libwebrtc; Firefox's nICEr) and nothing else.
//
// TRANSPORT picks how the browsers reach the node: udp (the default), tcp, or tls (turns:, to a
// name on a certificate from a CA made here; the name is mapped in /etc/hosts, so run it as root
// in a container). The CA is trusted where each browser looks: the system store (WebKit), the NSS
// database (Chromium; needs certutil, libnss3-tools) and an enterprise policy (Firefox), as a real
// certificate would be. WebKit's TURN client checks against roots built into it (a test CA can't
// be added), so run TLS with BROWSERS=chromium,firefox; WebKit is checked against a real
// certificate. TLS_TRUST=none trusts nothing: every browser should refuse it.
//
// In the Playwright image (browsers included), with the node built for Linux:
//   docker run --rm -v "$PWD":/w -w /w/interop/browsers mcr.microsoft.com/playwright:v1.63.0-noble \
//     sh -c 'npm i -s playwright@1.63.0 && NODE_BIN=/w/target/release/resonance-node node relay.mjs'
import { createHmac } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { appendFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { networkInterfaces, tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium, firefox, webkit } from 'playwright';

const KEY = 'fiahLYMg85YkiFJQ0Xp3Bl0x3pXkUhI4nMU8jj6QRio';
const PORT = 34810;
const TLS_PORT = 34811;
const HOST = 'turn.test';
const TRANSPORT = process.env.TRANSPORT ?? 'udp';
const TRUST = process.env.TLS_TRUST ?? 'ca';
let firefoxProfile = null;
const ip = Object.values(networkInterfaces()).flat().find((a) => a && a.family === 'IPv4' && !a.internal)?.address;
if (!ip) throw new Error('no non-loopback IPv4 address');

const env = { TURN_SECRET: KEY, TURN_PUBLIC_IP: ip, TURN_PORT: String(PORT), TURN_TCP: '1', TURN_DEBUG_STREAMS: process.env.TURN_DEBUG_STREAMS ?? '' };
if (TRANSPORT === 'tls') {
  // A CA, and a certificate for HOST signed by it, as certbot's fullchain.pem and privkey.pem.
  const dir = mkdtempSync(join(tmpdir(), 'turn-tls-'));
  const ssl = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: 'pipe' });
  ssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', '/CN=test CA');
  ssl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'privkey.pem', '-out', 'req.csr', '-subj', `/CN=${HOST}`);
  writeFileSync(join(dir, 'ext.cnf'), `subjectAltName=DNS:${HOST}\nextendedKeyUsage=serverAuth\n`);
  ssl('x509', '-req', '-in', 'req.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'cert.pem', '-days', '1', '-extfile', 'ext.cnf');
  execFileSync('sh', ['-c', 'cat cert.pem ca.pem > fullchain.pem'], { cwd: dir });
  Object.assign(env, { TURN_TLS_CERT: join(dir, 'fullchain.pem'), TURN_TLS_KEY: join(dir, 'privkey.pem'), TURN_TLS_PORT: String(TLS_PORT), TURN_TLS_HOST: HOST });
  appendFileSync('/etc/hosts', `${ip} ${HOST}\n`);
  if (TRUST === 'ca') trust(join(dir, 'ca.pem'));
}

/** The CA, where each browser reads trust from. */
function trust(ca) {
  const sh = (cmd) => execFileSync('sh', ['-c', cmd], { stdio: 'pipe' });
  sh(`cp ${ca} /usr/local/share/ca-certificates/turn-test-ca.crt && update-ca-certificates`);
  const db = `${process.env.HOME}/.pki/nssdb`;
  sh(`mkdir -p ${db} && (certutil -d sql:${db} -L >/dev/null 2>&1 || certutil -d sql:${db} -N --empty-password) && certutil -d sql:${db} -A -t C,, -n turn-test-ca -i ${ca}`);
  // Firefox trusts what's in its profile's own database: a profile made here, with the CA in it.
  firefoxProfile = mkdtempSync(join(tmpdir(), 'ff-'));
  sh(`certutil -d sql:${firefoxProfile} -N --empty-password && certutil -d sql:${firefoxProfile} -A -t C,, -n turn-test-ca -i ${ca}`);
}
const node = spawn(process.env.NODE_BIN, [], { env, stdio: ['ignore', 'inherit', 'inherit'] });
await new Promise((r) => setTimeout(r, 300));
const URL = { udp: `turn:${ip}:${PORT}`, tcp: `turn:${ip}:${PORT}?transport=tcp`, tls: `turns:${HOST}:${TLS_PORT}?transport=tcp` }[TRANSPORT];
if (!URL) throw new Error(`TRANSPORT is udp, tcp or tls, not ${TRANSPORT}`);

// The control plane's credentials (gamerelay.io apps/server/src/turn.ts).
function ice(room, player) {
  const username = `${Math.floor(Date.now() / 1000) + 3600}:ins:${room}:${player}`;
  const credential = createHmac('sha1', KEY).update(username).digest('base64');
  return [{ urls: [URL], username, credential }];
}

const launchers = {
  chromium: () => chromium.launch(),
  // With a profile of its own (the CA in it) when there is one: one browser per profile at a time.
  firefox: () => (firefoxProfile ? firefox.launchPersistentContext(mkdtempCopy(firefoxProfile)) : firefox.launch()),
  webkit: () => webkit.launch(),
};
function mkdtempCopy(dir) {
  const copy = mkdtempSync(join(tmpdir(), 'ff-'));
  execFileSync('sh', ['-c', `cp -r ${dir}/. ${copy}/`]);
  return copy;
}

async function side(browser, iceServers) {
  // A persistent context (Firefox with its profile) is already a context.
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
// BROWSERS=firefox,webkit: only those.
const names = (process.env.BROWSERS ?? Object.keys(launchers).join(',')).split(',');
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
console.log(`${TRANSPORT} (${URL})${TRANSPORT === 'tls' ? `, trust: ${TRUST}` : ''}`);
console.table(results.map(({ error, ...r }) => r));
for (const r of results.filter((r) => r.error)) console.log(`${r.offer} → ${r.answer}: ${r.error}`);
process.exit(results.every((r) => r.ok) ? 0 : 1);
