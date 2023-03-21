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

	var pairs = make([]string, 0, len(values))
	for key := range values {
		var nValues = values[key]
		if len(nValues) > 0 {
			for _, value := range nValues {
				var nValue = strings.TrimSpace(value)
				if len(nValue) > 0 {
					pairs = append(pairs, key+"="+nValue)
				}
			}
		}
	}
	sort.Strings(pairs)

	buffer.WriteString(strings.Join(pairs, "&"))

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
