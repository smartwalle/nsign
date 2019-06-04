package sign4go

import (
	"crypto"
	_ "crypto/md5"
	_ "crypto/sha1"
	"net/url"
	"strings"
	"testing"
)

func BenchmarkSign(b *testing.B) {
	var h = NewHash(crypto.MD5)
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

func TestSignBytesWithSHA1(t *testing.T) {
	var h = NewHash(crypto.SHA1)
	var src = "jsapi_ticket=sM4AOVdWfPE4DxkXGEs8VMCPGGVi4C3VM0P37wVUCFvkVAy_90u5h9nbSlYy3-Sl-HhTdfl2fzFy1AOcHKP7qg&noncestr=Wm3WZYTPz0wzccnW&timestamp=1414587457&url=http://mp.weixin.qq.com?params=value"
	var r, err = h.SignBytes([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if r != "0f9de62fce790f9a083d5c99e95740ceb90c27ed" {
		t.Fatal("sha1 签名错误")
	}
}

func TestVerifyBytesWithSHA1(t *testing.T) {
	var h = NewHash(crypto.SHA1)
	var src = "jsapi_ticket=sM4AOVdWfPE4DxkXGEs8VMCPGGVi4C3VM0P37wVUCFvkVAy_90u5h9nbSlYy3-Sl-HhTdfl2fzFy1AOcHKP7qg&noncestr=Wm3WZYTPz0wzccnW&timestamp=1414587457&url=http://mp.weixin.qq.com?params=value"

	if h.VerifyBytes([]byte(src), "0f9de62fce790f9a083d5c99e95740ceb90c27ed") == false {
		t.Fatal("sha1 验签错误")
	}
}

func TestSignWithSHA1(t *testing.T) {
	var h = NewHash(crypto.SHA1)
	var p = url.Values{}
	p.Add("jsapi_ticket", "sM4AOVdWfPE4DxkXGEs8VMCPGGVi4C3VM0P37wVUCFvkVAy_90u5h9nbSlYy3-Sl-HhTdfl2fzFy1AOcHKP7qg")
	p.Add("noncestr", "Wm3WZYTPz0wzccnW")
	p.Add("timestamp", "1414587457")
	p.Add("url", "http://mp.weixin.qq.com?params=value")

	var r, err = h.Sign(p)
	if err != nil {
		t.Fatal(err)
	}
	if r != "0f9de62fce790f9a083d5c99e95740ceb90c27ed" {
		t.Fatal("sha1 签名错误")
	}
}

func TestVerifyWithSHA1(t *testing.T) {
	var h = NewHash(crypto.SHA1)
	var p = url.Values{}
	p.Add("jsapi_ticket", "sM4AOVdWfPE4DxkXGEs8VMCPGGVi4C3VM0P37wVUCFvkVAy_90u5h9nbSlYy3-Sl-HhTdfl2fzFy1AOcHKP7qg")
	p.Add("noncestr", "Wm3WZYTPz0wzccnW")
	p.Add("timestamp", "1414587457")
	p.Add("url", "http://mp.weixin.qq.com?params=value")

	if h.Verify(p, "0f9de62fce790f9a083d5c99e95740ceb90c27ed") == false {
		t.Fatal("sha1 验签错误")
	}
}
