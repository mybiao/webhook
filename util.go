package webhook

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
)

//Hmacsha1 信息加密
func hmacsha1(secert string, playbody []byte) string {
	key := []byte(secert)
	mac := hmac.New(sha1.New, key)
	mac.Write(playbody)
	buf := mac.Sum(nil)
	return fmt.Sprintf("%x", buf)
}
