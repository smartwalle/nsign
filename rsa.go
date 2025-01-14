package nsign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

type RSAMethod struct {
	hash       crypto.Hash
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewRSAMethod(hash crypto.Hash, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *RSAMethod {
	var m = &RSAMethod{}
	m.hash = hash
	m.privateKey = privateKey
	m.publicKey = publicKey
	return m
}

func (m *RSAMethod) Sign(data []byte) ([]byte, error) {
	var h = m.hash.New()
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	var hashed = h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, m.privateKey, m.hash, hashed)
}

func (m *RSAMethod) Verify(data []byte, signature []byte) error {
	var h = m.hash.New()
	if _, err := h.Write(data); err != nil {
		return err
	}
	var hashed = h.Sum(nil)
	return rsa.VerifyPKCS1v15(m.publicKey, m.hash, hashed, signature)
}
