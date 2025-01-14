package nsign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

type RSAMethod struct {
	h          crypto.Hash
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewRSAMethod(h crypto.Hash, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *RSAMethod {
	var nRSA = &RSAMethod{}
	nRSA.h = h
	nRSA.privateKey = privateKey
	nRSA.publicKey = publicKey
	return nRSA
}

func (m *RSAMethod) Sign(data []byte) ([]byte, error) {
	var h = m.h.New()
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	var hashed = h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, m.privateKey, m.h, hashed)
}

func (m *RSAMethod) Verify(data []byte, signature []byte) error {
	var h = m.h.New()
	if _, err := h.Write(data); err != nil {
		return err
	}
	var hashed = h.Sum(nil)
	return rsa.VerifyPKCS1v15(m.publicKey, m.h, hashed, signature)
}
