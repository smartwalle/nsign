package nsign

import (
	"bytes"
	"net/url"
	"sort"
	"strings"
)

type Encoder interface {
	EncodeValues(buffer *bytes.Buffer, values url.Values, opt *SignOption) ([]byte, error)

	EncodeBytes(buffer *bytes.Buffer, values []byte, opt *SignOption) ([]byte, error)
}

type DefaultEncoder struct {
}

// EncodeValues
// 1、将参数名进行升序排序
// 2、将排序后的参数名及参数名使用等号进行连接，例如：a=10
// 3、将组合之后的参数使用&号进行连接，例如：a=10&b=20&c=30&c=31
// 4、把拼接好的字符串进行相应运算
func (this *DefaultEncoder) EncodeValues(buffer *bytes.Buffer, values url.Values, opt *SignOption) ([]byte, error) {
	if values == nil {
		return nil, nil
	}

	if opt.Prefix != "" {
		buffer.WriteString(opt.Prefix)
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for index, key := range keys {
		vs := values[key]
		for _, v := range vs {
			if v = strings.TrimSpace(v); v == "" {
				continue
			}
			if index != 0 {
				buffer.WriteByte('&')
			}
			buffer.WriteString(key)
			buffer.WriteByte('=')
			buffer.WriteString(v)
		}
	}

	if opt.Suffix != "" {
		buffer.WriteString(opt.Suffix)
	}

	return buffer.Bytes(), nil
}

func (this *DefaultEncoder) EncodeBytes(buffer *bytes.Buffer, values []byte, opt *SignOption) ([]byte, error) {
	if values == nil {
		return nil, nil
	}

	if opt.Prefix != "" {
		buffer.WriteString(opt.Prefix)
	}

	buffer.Write(values)

	if opt.Suffix != "" {
		buffer.WriteString(opt.Suffix)
	}

	return buffer.Bytes(), nil
}
