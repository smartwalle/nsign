package nsign

import (
	"net/url"
)

type Option func(b *Buffer)

func WithPrefix(s string) Option {
	return func(b *Buffer) {
		b.prefix = s
	}
}

func WithSuffix(s string) Option {
	return func(b *Buffer) {
		b.suffix = s
	}
}

type Signer interface {
	// SignValues
	// 1、将参数名进行升序排序
	// 2、将排序后的参数名及参数名使用等号进行连接，例如：a=10
	// 3、将组合之后的参数使用&号进行连接，例如：a=10&b=20&c=30&c=31
	// 4、把拼接好的字符串进行相应运算
	SignValues(values url.Values, opts ...Option) ([]byte, error)

	SignBytes(values []byte, opts ...Option) ([]byte, error)

	VerifyValues(values url.Values, sign []byte, opts ...Option) bool

	VerifyBytes(values []byte, sign []byte, opts ...Option) bool
}
