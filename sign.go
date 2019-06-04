package sign4go

import (
	"net/url"
	"sort"
	"strings"
)

type OptionFunc func(buf *strings.Builder)

type Signer interface {
	// Sign
	// 1、将参数名进行升序排序
	// 2、将排序后的参数名及参数名使用等号进行连接，例如：a=10
	// 3、将组合之后的参数使用&号进行连接，例如：a=10&b=20&c=30&c=31
	// 4、把拼接好的字符串进行相应运算
	Sign(p url.Values, opts ...OptionFunc) (string, error)

	SignBytes(b []byte, opts ...OptionFunc) (string, error)

	Verify(p url.Values, sign string, opts ...OptionFunc) bool

	VerifyBytes(b []byte, sign string, opts ...OptionFunc) bool
}

func EncodeValues(p url.Values, opts ...OptionFunc) string {
	if p == nil {
		return ""
	}
	var buf = &strings.Builder{}
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		vs := p[k]
		for _, v := range vs {
			if v = strings.TrimSpace(v); v == "" {
				continue
			}
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}
			buf.WriteString(k)
			buf.WriteByte('=')
			buf.WriteString(v)
		}
	}

	for _, opt := range opts {
		opt(buf)
	}

	return buf.String()
}
