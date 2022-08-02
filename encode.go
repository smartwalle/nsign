package nsign

import (
	"net/url"
	"sort"
	"strings"
)

func encodeValues(buffer *Buffer, values url.Values, opts ...Option) []byte {
	if values == nil {
		return nil
	}

	for _, opt := range opts {
		if opt != nil {
			opt(buffer)
		}
	}

	buffer.WriteString(buffer.prefix)

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

	buffer.WriteString(buffer.suffix)

	return buffer.Bytes()
}

func encodeBytes(buffer *Buffer, values []byte, opts ...Option) []byte {
	if values == nil {
		return nil
	}

	for _, opt := range opts {
		if opt != nil {
			opt(buffer)
		}
	}

	buffer.WriteString(buffer.prefix)

	buffer.Write(values)

	buffer.WriteString(buffer.suffix)

	return buffer.Bytes()
}
