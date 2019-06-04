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
	var h = this.h.New()
	if _, err := h.Write([]byte(src)); err != nil {
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
