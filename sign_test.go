package sign4go

import (
	"crypto"
	_ "crypto/md5"
	"net/url"
	"strings"
	"testing"
)

func BenchmarkSign(b *testing.B) {

	var h = NewHashSign(crypto.MD5)

	for i := 0; i < b.N; i++ {
		var form = make(url.Values, 0)
		form.Set("c", "30")
		form.Set("b", "20")
		form.Set("a", "30")

		_, _ = h.Sign(form, func(buf *strings.Builder) {
			buf.WriteString("&" + "key=this_is_key")
		})


	}
}
