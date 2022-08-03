package nsign

import (
	"bytes"
	"crypto"
)

type HashMethod struct {
	h crypto.Hash
}

func NewHashMethod(h crypto.Hash) *HashMethod {
	var nHash = &HashMethod{}
	nHash.h = h
	return nHash
}

func (this *HashMethod) Sign(values []byte) ([]byte, error) {
	var h = this.h.New()
	if _, err := h.Write(values); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (this *HashMethod) Verify(values []byte, sign []byte) bool {
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
