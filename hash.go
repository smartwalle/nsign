package sign4go

import (
	"crypto"
	"encoding/hex"
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

func (this *Hash) Sign(p url.Values, opts ...OptionFunc) (string, error) {
	var src = EncodeValues(p, opts...)
	return this.SignBytes([]byte(src), opts...)
}

func (this *Hash) SignBytes(b []byte, opts ...OptionFunc) (string, error) {
	var h = this.h.New()
	if _, err := h.Write(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (this *Hash) Verify(p url.Values, sign string, opts ...OptionFunc) bool {
	nSign, err := this.Sign(p, opts...)
	if err != nil {
		return false
	}
	if nSign == sign {
		return true
	}
	return false
}

func (this *Hash) VerifyBytes(b []byte, sign string, opts ...OptionFunc) bool {
	nSign, err := this.SignBytes(b, opts...)
	if err != nil {
		return false
	}
	if nSign == sign {
		return true
	}
	return false
}
