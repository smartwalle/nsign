package nsign

import (
	"bytes"
	"crypto"
	"errors"
	"net/url"
	"sync"
)

var ErrVerification = errors.New("verification error")

type Option func(signer *Signer)

func WithMethod(method Method) Option {
	return func(signer *Signer) {
		if method == nil {
			return
		}
		signer.method = method
	}
}

func WithEncoder(encoder Encoder) Option {
	return func(signer *Signer) {
		if encoder == nil {
			return
		}
		signer.encoder = encoder
	}
}

type SignOption func(opt *SignOptions)

type SignOptions struct {
	Prefix string
	Suffix string
}

func WithPrefix(s string) SignOption {
	return func(opt *SignOptions) {
		opt.Prefix = s
	}
}

func WithSuffix(s string) SignOption {
	return func(opt *SignOptions) {
		opt.Suffix = s
	}
}

type Method interface {
	Sign(data []byte) ([]byte, error)

	Verify(data []byte, signature []byte) (bool, error)
}

type Signer struct {
	pool    *sync.Pool
	method  Method
	encoder Encoder
}

func NewSigner(opts ...Option) *Signer {
	var s = &Signer{}
	s.pool = &sync.Pool{
		New: func() interface{} {
			return bytes.NewBufferString("")
		},
	}
	s.method = NewHashMethod(crypto.MD5)
	s.encoder = &DefaultEncoder{}

	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

func (this *Signer) getBuffer() *bytes.Buffer {
	var buffer = this.pool.Get().(*bytes.Buffer)
	buffer.Reset()
	return buffer
}

func (this *Signer) putBuffer(buffer *bytes.Buffer) {
	if buffer != nil {
		buffer.Reset()
		this.pool.Put(buffer)
	}
}

func (this *Signer) SignValues(values url.Values, opts ...SignOption) ([]byte, error) {
	var buffer = this.getBuffer()
	defer this.putBuffer(buffer)

	var nOptions = &SignOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(nOptions)
		}
	}

	var src, err = this.encoder.EncodeValues(buffer, values, nOptions)
	if err != nil {
		return nil, err
	}
	return this.method.Sign(src)
}

func (this *Signer) SignBytes(data []byte, opts ...SignOption) ([]byte, error) {
	var buffer = this.getBuffer()
	defer this.putBuffer(buffer)

	var nOptions = &SignOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(nOptions)
		}
	}

	var src, err = this.encoder.EncodeBytes(buffer, data, nOptions)
	if err != nil {
		return nil, err
	}
	return this.method.Sign(src)
}

func (this *Signer) VerifyValues(values url.Values, signature []byte, opts ...SignOption) (bool, error) {
	var buffer = this.getBuffer()
	defer this.putBuffer(buffer)

	var nOptions = &SignOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(nOptions)
		}
	}

	var src, err = this.encoder.EncodeValues(buffer, values, nOptions)
	if err != nil {
		return false, err
	}
	return this.method.Verify(src, signature)
}

func (this *Signer) VerifyBytes(data []byte, signature []byte, opts ...SignOption) (bool, error) {
	var buffer = this.getBuffer()
	defer this.putBuffer(buffer)

	var nOptions = &SignOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(nOptions)
		}
	}

	var src, err = this.encoder.EncodeBytes(buffer, data, nOptions)
	if err != nil {
		return false, err
	}
	return this.method.Verify(src, signature)
}
