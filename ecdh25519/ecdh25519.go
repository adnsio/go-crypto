// Package ecdh25519 implements the curve25519 diffie-hellman protocol.
// See https://cr.yp.to/ecdh.html and https://www.ietf.org/rfc/rfc7748.html.
package ecdh25519

import (
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 32
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 32
)

var (
	ErrBadPrivateKeyLength = errors.New("ecdh25519: bad private key length")
	ErrBadPublicKeyLength  = errors.New("ecdh25519: bad public key length")
)

// PublicKey is the type of ecdh25519 public keys.
type PublicKey []byte

// PrivateKey is the type of ecdh25519 private keys.
type PrivateKey []byte

// Public returns the Public corresponding to the PrivateKey.
func (p PrivateKey) Public() (PublicKey, error) {
	return curve25519.X25519(p, curve25519.Basepoint)
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	if rand == nil {
		rand = cryptorand.Reader
	}

	privateKey := make(PrivateKey, PrivateKeySize)
	if _, err := io.ReadFull(rand, privateKey); err != nil {
		return nil, nil, err
	}

	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	publicKey, err := privateKey.Public()
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, nil
}

// GenerateShared generates a shared secret by using someone else's public key.
func GenerateShared(privateKey PrivateKey, peerPublicKey PublicKey) ([]byte, error) {
	if l := len(privateKey); l != PrivateKeySize {
		return nil, fmt.Errorf("%w: %d", ErrBadPrivateKeyLength, l)
	}

	if l := len(peerPublicKey); l != PublicKeySize {
		return nil, fmt.Errorf("%w: %d", ErrBadPublicKeyLength, l)
	}

	return curve25519.X25519(privateKey, peerPublicKey)
}
