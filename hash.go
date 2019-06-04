package sign4go

import (
	"bytes"
	"crypto"
	"net/url"
)

type Hash struct {
	h crypto.Hash
}

func NewHash(h crypto.Hash) Signer {
	var hs = &Hash{}
	hs.h = h
	return hs
}

func (this *Hash) Sign(p url.Values, opts ...OptionFunc) ([]byte, error) {
	var src = EncodeValues(p, opts...)
	return this.SignBytes([]byte(src))
}

func (this *Hash) SignBytes(b []byte) ([]byte, error) {
	var h = this.h.New()
	if _, err := h.Write(b); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (this *Hash) Verify(p url.Values, sign []byte, opts ...OptionFunc) bool {
	nSign, err := this.Sign(p, opts...)
	if err != nil {
		return false
	}
	if bytes.Compare(nSign, sign) == 0 {
		return true
	}
	return false
}

func (this *Hash) VerifyBytes(b []byte, sign []byte) bool {
	nSign, err := this.SignBytes(b)
	if err != nil {
		return false
	}
	if bytes.Compare(nSign, sign) == 0 {
		return true
	}
	return false
}
