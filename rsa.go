package sign4go

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/url"
)

type RSA struct {
	h          crypto.Hash
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewRSA(h crypto.Hash, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) Signer {
	var hs = &RSA{}
	hs.h = h
	hs.privateKey = privateKey
	hs.publicKey = publicKey
	return hs
}

func (this *RSA) Sign(p url.Values, opts ...Option) ([]byte, error) {
	var src = EncodeValues(p, opts...)
	return this.SignBytes([]byte(src))
}

func (this *RSA) SignBytes(b []byte) ([]byte, error) {
	var h = this.h.New()
	if _, err := h.Write(b); err != nil {
		return nil, err
	}
	var hashed = h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, this.privateKey, this.h, hashed)
}

func (this *RSA) Verify(p url.Values, sign []byte, opts ...Option) bool {
	var src = EncodeValues(p, opts...)
	return this.VerifyBytes([]byte(src), sign)
}

func (this *RSA) VerifyBytes(b []byte, sign []byte) bool {
	var h = this.h.New()
	if _, err := h.Write(b); err != nil {
		return false
	}
	var hashed = h.Sum(nil)

	if err := rsa.VerifyPKCS1v15(this.publicKey, this.h, hashed, sign); err != nil {
		return false
	}
	return true
}
