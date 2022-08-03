package nsign

import (
	"bytes"
	"crypto"
	"net/url"
	"sync"
)

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

type SignOptionFunc func(opt *SignOption)

type SignOption struct {
	Prefix string
	Suffix string
}

func WithPrefix(s string) SignOptionFunc {
	return func(opt *SignOption) {
		opt.Prefix = s
	}
}

func WithSuffix(s string) SignOptionFunc {
	return func(opt *SignOption) {
		opt.Suffix = s
	}
}

type Method interface {
	Sign(values []byte) ([]byte, error)

	Verify(values []byte, sign []byte) bool
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

func (this *Signer) SignValues(values url.Values, opts ...SignOptionFunc) ([]byte, error) {
	var buffer = this.getBuffer()
	defer this.putBuffer(buffer)

	var nOption = &SignOption{}
	for _, opt := range opts {
		if opt != nil {
			opt(nOption)
		}
	}

	var src, err = this.encoder.EncodeValues(buffer, values, nOption)
	if err != nil {
		return nil, err
	}
	return this.method.Sign(src)
}

func (this *Signer) SignBytes(values []byte, opts ...SignOptionFunc) ([]byte, error) {
	var buffer = this.getBuffer()
	defer this.putBuffer(buffer)

	var nOption = &SignOption{}
	for _, opt := range opts {
		if opt != nil {
			opt(nOption)
		}
	}

	var src, err = this.encoder.EncodeBytes(buffer, values, nOption)
	if err != nil {
		return nil, err
	}
	return this.method.Sign(src)
}

func (this *Signer) VerifyValues(values url.Values, sign []byte, opts ...SignOptionFunc) bool {
	var buffer = this.getBuffer()
	defer this.putBuffer(buffer)

	var nOption = &SignOption{}
	for _, opt := range opts {
		if opt != nil {
			opt(nOption)
		}
	}

	var src, err = this.encoder.EncodeValues(buffer, values, nOption)
	if err != nil {
		return false
	}
	return this.method.Verify(src, sign)
}

func (this *Signer) VerifyBytes(values []byte, sign []byte, opts ...SignOptionFunc) bool {
	var buffer = this.getBuffer()
	defer this.putBuffer(buffer)

	var nOption = &SignOption{}
	for _, opt := range opts {
		if opt != nil {
			opt(nOption)
		}
	}

	var src, err = this.encoder.EncodeBytes(buffer, values, nOption)
	if err != nil {
		return false
	}
	return this.method.Verify(src, sign)
}
