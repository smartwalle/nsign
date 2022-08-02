package nsign_test

import (
	"bytes"
	"crypto"
	_ "crypto/md5"
	_ "crypto/sha1"
	"encoding/hex"
	"github.com/smartwalle/nsign"
	"net/url"
	"testing"
)

func BenchmarkHash_SignValues(b *testing.B) {
	var h = nsign.NewHash(crypto.MD5)
	for i := 0; i < b.N; i++ {
		var form = make(url.Values, 0)
		form.Set("c", "30")
		form.Set("b", "20")
		form.Set("a", "30")
		_, _ = h.SignValues(form)
	}
}

func TestHash_SignBytes(t *testing.T) {
	var h = nsign.NewHash(crypto.SHA1)
	var src = "jsapi_ticket=sM4AOVdWfPE4DxkXGEs8VMCPGGVi4C3VM0P37wVUCFvkVAy_90u5h9nbSlYy3-Sl-HhTdfl2fzFy1AOcHKP7qg&noncestr=Wm3WZYTPz0wzccnW&timestamp=1414587457&url=http://mp.weixin.qq.com?params=value"
	var rb, err = h.SignBytes([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	var r = hex.EncodeToString(rb)
	if r != "0f9de62fce790f9a083d5c99e95740ceb90c27ed" {
		t.Fatal("sha1 签名错误")
	}
}

func TestHash_VerifyBytes(t *testing.T) {
	var h = nsign.NewHash(crypto.SHA1)
	var src = "jsapi_ticket=sM4AOVdWfPE4DxkXGEs8VMCPGGVi4C3VM0P37wVUCFvkVAy_90u5h9nbSlYy3-Sl-HhTdfl2fzFy1AOcHKP7qg&noncestr=Wm3WZYTPz0wzccnW&timestamp=1414587457&url=http://mp.weixin.qq.com?params=value"

	var sb, _ = hex.DecodeString("0f9de62fce790f9a083d5c99e95740ceb90c27ed")

	if h.VerifyBytes([]byte(src), sb) == false {
		t.Fatal("sha1 验签错误")
	}
}

func TestHash_SignValues(t *testing.T) {
	var h = nsign.NewHash(crypto.SHA1)
	var p = url.Values{}
	p.Add("jsapi_ticket", "sM4AOVdWfPE4DxkXGEs8VMCPGGVi4C3VM0P37wVUCFvkVAy_90u5h9nbSlYy3-Sl-HhTdfl2fzFy1AOcHKP7qg")
	p.Add("noncestr", "Wm3WZYTPz0wzccnW")
	p.Add("timestamp", "1414587457")
	p.Add("url", "http://mp.weixin.qq.com?params=value")

	var rb, err = h.SignValues(p)
	if err != nil {
		t.Fatal(err)
	}

	var sb, _ = hex.DecodeString("0f9de62fce790f9a083d5c99e95740ceb90c27ed")
	if bytes.Compare(rb, sb) != 0 {
		t.Fatal("sha1 签名错误")
	}
}

func TestHash_VerifyValues(t *testing.T) {
	var h = nsign.NewHash(crypto.SHA1)
	var p = url.Values{}
	p.Add("jsapi_ticket", "sM4AOVdWfPE4DxkXGEs8VMCPGGVi4C3VM0P37wVUCFvkVAy_90u5h9nbSlYy3-Sl-HhTdfl2fzFy1AOcHKP7qg")
	p.Add("noncestr", "Wm3WZYTPz0wzccnW")
	p.Add("timestamp", "1414587457")
	p.Add("url", "http://mp.weixin.qq.com?params=value")

	var sb, _ = hex.DecodeString("0f9de62fce790f9a083d5c99e95740ceb90c27ed")

	if h.VerifyValues(p, sb) == false {
		t.Fatal("sha1 验签错误")
	}
}
