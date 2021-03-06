package webhook

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

//Config 配置
type Config struct {
	Secret string   //签名
	Event  []string //事件集合
	Action func()   //回调函数
}

//Hook 执行hook
func Hook(w http.ResponseWriter, r *http.Request, conf Config) {
	if !strings.EqualFold(r.Method, "POST") {
		w.Write([]byte("not support method!"))
		return
	}
	header := r.Header
	//首先验证签名是否正确
	sign := header["X-Hub-Signature"]
	if len(sign) == 0 {
		log.Info("not contains signature")
		return
	}
	token := sign[0]
	log.WithFields(log.Fields{
		"X-Hub-Signature": token,
	}).Info("token = ")
	event := r.Header["X-Github-Event"]
	fmt.Println(event)
	if len(event) == 0 {
		log.Info("not found event")
		return
	}
	log.Info("event = ", event)
	if !checkEvent(conf.Event, event[0]) {
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
	str := hmacsha1(conf.Secret, buf)
	log.Info("str = ", str)
	if strings.EqualFold(str, token) {
		log.Info("签名验证成功")
		go conf.Action()
	} else {
		log.Errorln("签名验证失败")
	}

	resultMap := map[string]interface{}{"code": 200, "msg": "success", "data": nil}
	jsonRes, err := json.Marshal(resultMap)
	if err != nil {
		log.Errorln("json marsha1 error,", err.Error())
	}
	w.Write(jsonRes)
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
