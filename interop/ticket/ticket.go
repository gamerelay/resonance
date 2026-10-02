// Package ticket mints Resonance tickets for the interop tests and the benchmark: the format in
// docs/PROTOCOL.md, "Tickets" (and crates/resonance-turn/src/ticket.rs).
package ticket

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
)

var b64 = base64.RawURLEncoding

const domain = "resonance/ticket/v1\n"

// NodeSeed is the ed25519 seed test nodes run with (their `key` file), so every test knows their
// sealing key.
var NodeSeed = bytes32(7)

// Issuer is the issuer test nodes trust (RESONANCE_ISSUERS=IssuerPublic()).
var Issuer = ed25519.NewKeyFromSeed(bytes32(1))

func bytes32(b byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = b
	}
	return s
}

// IssuerPublic is Issuer's public key, base64url.
func IssuerPublic() string { return b64.EncodeToString(Issuer.Public().(ed25519.PublicKey)) }

// SealPublic is the sealing key of a node whose ed25519 seed this is.
func SealPublic(nodeSeed []byte) []byte {
	m := hmac.New(sha256.New, nodeSeed)
	m.Write([]byte("resonance/seal/v1"))
	k, err := ecdh.X25519().NewPrivateKey(m.Sum(nil))
	if err != nil {
		panic(err)
	}
	return k.PublicKey().Bytes()
}

// StateDir makes a node state directory holding NodeSeed as its key.
func StateDir(parent string) (string, error) {
	dir, err := os.MkdirTemp(parent, "resonance-state-")
	if err != nil {
		return "", err
	}
	return dir, os.WriteFile(filepath.Join(dir, "key"), NodeSeed, 0o600)
}

// Mint: a ticket from `issuer` for the node with this sealing key, its username and password.
func Mint(issuer ed25519.PrivateKey, expiry int64, instance, room, player string, sealPublic []byte) (string, string) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return MintWith(issuer, eph.Bytes(), expiry, instance, room, player, sealPublic)
}

// MintWith: Mint with a given ephemeral secret (for fixtures).
func MintWith(issuer ed25519.PrivateKey, ephSecret []byte, expiry int64, instance, room, player string, sealPublic []byte) (string, string) {
	eph, err := ecdh.X25519().NewPrivateKey(ephSecret)
	if err != nil {
		panic(err)
	}
	pub := issuer.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	signed := fmt.Sprintf("t1:%d:%s:%s:%s:%s:%s", expiry, instance, room, player, b64.EncodeToString(sum[:8]), b64.EncodeToString(eph.PublicKey().Bytes()))
	msg := []byte(domain + signed)
	user := signed + ":" + b64.EncodeToString(ed25519.Sign(issuer, msg))
	seal, err := ecdh.X25519().NewPublicKey(sealPublic)
	if err != nil {
		panic(err)
	}
	shared, err := eph.ECDH(seal)
	if err != nil {
		panic(err)
	}
	m := hmac.New(sha256.New, shared)
	m.Write(msg)
	return user, b64.EncodeToString(m.Sum(nil))
}
