package nsign

import (
	"bytes"
	"crypto"
	"net/url"
	"sync"
)

type Option func(sign *Sign)

func WithSigner(signer Signer) Option {
	return func(sign *Sign) {
		if signer == nil {
			return
		}
		sign.signer = signer
	}
}

func WithEncoder(encoder Encoder) Option {
	return func(sign *Sign) {
		if encoder == nil {
			return
		}
		sign.encoder = encoder
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

type Signer interface {
	Sign(values []byte) ([]byte, error)

	Verify(values []byte, sign []byte) bool
}

type Sign struct {
	pool    *sync.Pool
	signer  Signer
	encoder Encoder
}

func NewSign(opts ...Option) *Sign {
	var s = &Sign{}
	s.pool = &sync.Pool{
		New: func() interface{} {
			return bytes.NewBufferString("")
		},
	}
	s.signer = NewHashSigner(crypto.MD5)
	s.encoder = &DefaultEncoder{}

	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

func (this *Sign) getBuffer() *bytes.Buffer {
	var buffer = this.pool.Get().(*bytes.Buffer)
	buffer.Reset()
	return buffer
}

func (this *Sign) putBuffer(buffer *bytes.Buffer) {
	if buffer != nil {
		buffer.Reset()
		this.pool.Put(buffer)
	}
}

func (this *Sign) SignValues(values url.Values, opts ...SignOptionFunc) ([]byte, error) {
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
	return this.signer.Sign(src)
}

func (this *Sign) SignBytes(values []byte, opts ...SignOptionFunc) ([]byte, error) {
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
	return this.signer.Sign(src)
}

func (this *Sign) VerifyValues(values url.Values, sign []byte, opts ...SignOptionFunc) bool {
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
	return this.signer.Verify(src, sign)
}

func (this *Sign) VerifyBytes(values []byte, sign []byte, opts ...SignOptionFunc) bool {
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
	return this.signer.Verify(src, sign)
}
