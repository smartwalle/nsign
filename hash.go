package nsign

import (
	"bytes"
	"crypto"
)

type HashMethod struct {
	h crypto.Hash
}

func NewHashMethod(h crypto.Hash) *HashMethod {
	var m = &HashMethod{}
	m.h = h
	return m
}

func (m *HashMethod) Sign(data []byte) ([]byte, error) {
	var h = m.h.New()
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (m *HashMethod) Verify(data []byte, signature []byte) error {
	var h = m.h.New()
	if _, err := h.Write(data); err != nil {
		return err
	}
	var hashed = h.Sum(nil)
	if bytes.Compare(hashed, signature) == 0 {
		return nil
	}
	return ErrVerification
}
