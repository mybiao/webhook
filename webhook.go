package webhook

import (
	"io/ioutil"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

//Config 配置
type Config struct {
	secret string   //签名
	event  []string //事件集合
	action func()   //回调函数
}

//Hook 执行hook
func Hook(w http.ResponseWriter, r *http.Request, conf Config) {
	if !strings.EqualFold(r.Method, "POST") {
		w.Write([]byte("not support method!"))
		return
	}
	//首先验证签名是否正确
	sign := r.Header["X-Hub-Signature"]
	if len(sign) == 0 {
		log.Info("not contains signature")
		return
	}
	token := sign[0]
	log.WithFields(log.Fields{
		"X-Hub-Signature": token,
	}).Info("token = ")
	event := r.Header["X-GitHub-Event"]
	if len(event) == 0 {
		log.Info("not found event")
		return
	}
	log.Info("event = ", event)
	if !checkEvent(conf.event, event[0]) {
		log.Info("not support event")
		return
	}
	rc := r.Body
	buf, err := ioutil.ReadAll(rc)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Errorln("read request body error")
	}
	token = strings.TrimPrefix(token, "sha1=")
	log.Info("token= ", token)
	//验证签名
	str := hmacsha1("abcdefgh", buf)
	log.Info("str = ", str)
	if strings.EqualFold(str, token) {
		log.Info("签名验证成功")
		conf.action()
	} else {
		log.Errorln("签名验证失败")
	}
}

//检查值是否包含
func checkEvent(es []string, ev string) bool {
	for _, v := range es {
		if strings.EqualFold(v, ev) {
			return true
		}
	}
	return false
}
