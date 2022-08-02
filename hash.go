package nsign

import (
	"bytes"
	"crypto"
)

type HashSigner struct {
	h crypto.Hash
}

func NewHashSigner(h crypto.Hash) *HashSigner {
	var nHash = &HashSigner{}
	nHash.h = h
	return nHash
}

func (this *HashSigner) Sign(values []byte) ([]byte, error) {
	var h = this.h.New()
	if _, err := h.Write(values); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (this *HashSigner) Verify(values []byte, sign []byte) bool {
	var h = this.h.New()
	if _, err := h.Write(values); err != nil {
		return false
	}
	nSign := h.Sum(nil)
	if bytes.Compare(nSign, sign) == 0 {
		return true
	}
	return false
}
