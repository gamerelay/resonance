package ticket

import (
	"crypto/ed25519"
	"testing"
)

// The fixture shared with crates/resonance-turn/src/ticket.rs and gamerelay.io's turn.test.ts.
func TestFixtureSharedWithTheNodeAndTheControlPlane(t *testing.T) {
	issuer := ed25519.NewKeyFromSeed(bytes32(1))
	seal := SealPublic(bytes32(7))
	if got := b64.EncodeToString(seal); got != "_1XQc9Vk2S2KlA8GlnTSxeDhMe3CwYq-383J2nCL7V8" {
		t.Fatalf("seal key %s", got)
	}
	user, pass := MintWith(issuer, bytes32(3), 1790000000, "ins_x", "g1", "p1", seal)
	if user != "t1:1790000000:ins_x:g1:p1:NHUPmL1Z_Pw:Xf7dO2vUf2-ijuFdlp1bsOpTd01Ii9r53xxuASSz7yI:cXuVnphwjGWacAMAD-2Fa9CV27VN59F4ccjIghbGr1eUlbh9jpvn2EoKz728Cry6iJubi7VlAoEzbuI3A7V3AQ" {
		t.Fatalf("username %s", user)
	}
	if pass != "8dlvZZektqxUYgGG5LqPm_r5qYpR38zt1KJZ_X55msw" {
		t.Fatalf("password %s", pass)
	}
}
