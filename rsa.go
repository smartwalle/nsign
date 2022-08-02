package nsign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/url"
)

type RSA struct {
	*BufferPool
	h          crypto.Hash
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewRSA(h crypto.Hash, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) Signer {
	var hs = &RSA{}
	hs.BufferPool = NewBufferPool()
	hs.h = h
	hs.privateKey = privateKey
	hs.publicKey = publicKey
	return hs
}

func (this *RSA) sign(values []byte) ([]byte, error) {
	var h = this.h.New()
	if _, err := h.Write(values); err != nil {
		return nil, err
	}
	var hashed = h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, this.privateKey, this.h, hashed)
}

func (this *RSA) SignValues(values url.Values, opts ...Option) ([]byte, error) {
	var buffer = this.GetBuffer()
	defer buffer.Release()

	var src = encodeValues(buffer, values, opts...)
	return this.sign(src)
}

func (this *RSA) SignBytes(values []byte, opts ...Option) ([]byte, error) {
	var buffer = this.GetBuffer()
	defer buffer.Release()

	var src = encodeBytes(buffer, values, opts...)
	return this.sign(src)
}

func (this *RSA) verify(values []byte, sign []byte) bool {
	var h = this.h.New()
	if _, err := h.Write(values); err != nil {
		return false
	}
	var hashed = h.Sum(nil)

	if err := rsa.VerifyPKCS1v15(this.publicKey, this.h, hashed, sign); err != nil {
		return false
	}
	return true
}

func (this *RSA) VerifyValues(values url.Values, sign []byte, opts ...Option) bool {
	var buffer = this.GetBuffer()
	defer buffer.Release()

	var src = encodeValues(buffer, values, opts...)
	return this.verify(src, sign)
}

func (this *RSA) VerifyBytes(values []byte, sign []byte, opts ...Option) bool {
	var buffer = this.GetBuffer()
	defer buffer.Release()

	var src = encodeBytes(buffer, values, opts...)
	return this.verify(src, sign)
}
