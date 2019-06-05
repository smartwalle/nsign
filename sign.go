package sign4go

import (
	"net/url"
	"sort"
	"strings"
	"sync"
)

// --------------------------------------------------------------------------------
var bPool *sync.Pool

func init() {
	bPool = &sync.Pool{
		New: func() interface{} {
			return NewBuffer()
		},
	}
}

func GetBuffer() *Buffer {
	var b = bPool.Get().(*Buffer)
	b.Reset()
	b.p = bPool
	return b
}

type Buffer struct {
	*strings.Builder
	p      *sync.Pool
	prefix string
	suffix string
}

func NewBuffer() *Buffer {
	var b = &Buffer{}
	b.Builder = &strings.Builder{}
	return b
}

func (this *Buffer) Reset() {
	this.Builder.Reset()
	this.prefix = ""
	this.suffix = ""
}

func (this *Buffer) Release() {
	this.p.Put(this)
	this.p = nil
}

// --------------------------------------------------------------------------------

type Option interface {
	Apply(b *Buffer)
}

type optionFunc func(b *Buffer)

func (f optionFunc) Apply(b *Buffer) {
	f(b)
}

func WithPrefix(s string) Option {
	return optionFunc(func(b *Buffer) {
		b.prefix = s
	})
}

func WithSuffix(s string) Option {
	return optionFunc(func(b *Buffer) {
		b.suffix = s
	})
}

// --------------------------------------------------------------------------------
type Signer interface {
	// Sign
	// 1、将参数名进行升序排序
	// 2、将排序后的参数名及参数名使用等号进行连接，例如：a=10
	// 3、将组合之后的参数使用&号进行连接，例如：a=10&b=20&c=30&c=31
	// 4、把拼接好的字符串进行相应运算
	Sign(p url.Values, opts ...Option) ([]byte, error)

	SignBytes(b []byte) ([]byte, error)

	Verify(p url.Values, sign []byte, opts ...Option) bool

	VerifyBytes(b []byte, sign []byte) bool
}

func EncodeValues(p url.Values, opts ...Option) string {
	if p == nil {
		return ""
	}
	var b = GetBuffer()
	defer b.Release()

	for _, opt := range opts {
		opt.Apply(b)
	}

	b.WriteString(b.prefix)

	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for index, k := range keys {
		vs := p[k]
		for _, v := range vs {
			if v = strings.TrimSpace(v); v == "" {
				continue
			}
			if index != 0 {
				b.WriteByte('&')
			}
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(v)
		}
	}

	b.WriteString(b.suffix)

	return b.String()
}
