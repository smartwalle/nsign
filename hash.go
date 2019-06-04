package sign4go

import (
	"crypto"
	"encoding/hex"
	"net/url"
)

type HashSign struct {
	h crypto.Hash
}

func NewHashSign(h crypto.Hash) *HashSign {
	var hs = &HashSign{}
	hs.h = h
	return hs
}

func (this *HashSign) Sign(p url.Values, opts ...OptionFunc) (string, error) {
	var src = EncodeValues(p, opts...)
	return this.SignByte([]byte(src), opts...)
}

func (this *HashSign) SignByte(b []byte, opts ...OptionFunc) (string, error) {
	var h = this.h.New()
	if _, err := h.Write([]byte(b)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (this *HashSign) Verify(p url.Values, sign string, opts ...OptionFunc) bool {
	nSign, err := this.Sign(p, opts...)
	if err != nil {
		return false
	}
	if nSign == sign {
		return true
	}
	return false
}

func (this *HashSign) VerifyByte(b []byte, sign string, opts ...OptionFunc) bool {
	nSign, err := this.SignByte(b, opts...)
	if err != nil {
		return false
	}
	if nSign == sign {
		return true
	}
	return false
}
