package nsign

import (
	"bytes"
	"crypto"
)

type HashMethod struct {
	hash crypto.Hash
}

func NewHashMethod(hash crypto.Hash) *HashMethod {
	var m = &HashMethod{}
	m.hash = hash
	return m
}

func (m *HashMethod) Sign(data []byte) ([]byte, error) {
	var h = m.hash.New()
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (m *HashMethod) Verify(data []byte, signature []byte) error {
	var h = m.hash.New()
	if _, err := h.Write(data); err != nil {
		return err
	}
	var hashed = h.Sum(nil)
	if bytes.Compare(hashed, signature) == 0 {
		return nil
	}
	return ErrVerification
}
