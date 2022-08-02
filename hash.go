package nsign

import (
	"bytes"
	"crypto"
	"net/url"
)

type Hash struct {
	*BufferPool
	h crypto.Hash
}

func NewHash(h crypto.Hash) Signer {
	var hs = &Hash{}
	hs.BufferPool = NewBufferPool()
	hs.h = h
	return hs
}

func (this *Hash) sign(values []byte) ([]byte, error) {
	var h = this.h.New()
	if _, err := h.Write(values); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (this *Hash) SignValues(values url.Values, opts ...Option) ([]byte, error) {
	var buffer = this.GetBuffer()
	defer buffer.Release()

	var src = encodeValues(buffer, values, opts...)
	return this.sign(src)
}

func (this *Hash) SignBytes(values []byte, opts ...Option) ([]byte, error) {
	var buffer = this.GetBuffer()
	defer buffer.Release()

	var src = encodeBytes(buffer, values, opts...)
	return this.sign(src)
}

func (this *Hash) VerifyValues(values url.Values, sign []byte, opts ...Option) bool {
	nSign, err := this.SignValues(values, opts...)
	if err != nil {
		return false
	}
	if bytes.Compare(nSign, sign) == 0 {
		return true
	}
	return false
}

func (this *Hash) VerifyBytes(values []byte, sign []byte, opts ...Option) bool {
	nSign, err := this.SignBytes(values, opts...)
	if err != nil {
		return false
	}
	if bytes.Compare(nSign, sign) == 0 {
		return true
	}
	return false
}
