// Command shsc-release-sign signs and verifies the agent release manifest (SHA256SUMS) with
// Ed25519 from the Go standard library (no new dependency, ADR-073).
//
//	shsc-release-sign keygen <private-key-file> <public-key-file>
//	shsc-release-sign sign   <private-key-file> <file>          (writes <file>.sig)
//	shsc-release-sign verify <public-key-file>  <file> [<sig>]  (default <file>.sig)
//
// Key files hold base64 text: the 32-byte seed (private, mode 0600) or the 32-byte public key.
// The signature file holds the base64 Ed25519 signature of the exact bytes of <file>.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "shsc-release-sign:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 3 {
		return errors.New("usage: keygen <priv> <pub> | sign <priv> <file> | verify <pub> <file> [<sig>]")
	}
	switch args[0] {
	case "keygen":
		return keygen(args[1], args[2])
	case "sign":
		return sign(args[1], args[2])
	case "verify":
		sig := args[2] + ".sig"
		if len(args) > 3 {
			sig = args[3]
		}
		if err := verify(args[1], args[2], sig); err != nil {
			return err
		}
		fmt.Println("signature OK:", args[2])
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func keygen(privPath, pubPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// O_EXCL: never overwrite an existing key
	f, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(priv.Seed()) + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644)
}

func sign(privPath, file string) error {
	seed, err := readKey(privPath, ed25519.SeedSize)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), data)
	return os.WriteFile(file+".sig", []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644)
}

func verify(pubPath, file, sigPath string) error {
	pub, err := readKey(pubPath, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	sig, err := readKey(sigPath, ed25519.SignatureSize)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), data, sig) {
		return errors.New("signature NOT valid: do not install these files")
	}
	return nil
}

func readKey(path string, size int) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(b) != size {
		return nil, fmt.Errorf("%s: not a valid base64 value of %d bytes", path, size)
	}
	return b, nil
}
