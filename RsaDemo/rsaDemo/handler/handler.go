package handler

import (
	"encoding/base64"
	"net/http"

	"rsaDemo/util"

	"github.com/gin-gonic/gin"
)

type Data struct {
	Context   string `json:"context"`
	PublicKey string `json:"public_key"`
}

func RsaHandler(c *gin.Context) {
	var req Data
	if err := c.BindJSON(&req); err != nil {
		panic(err)
	}

	pk, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		panic(err)
	}
	ct, err := base64.StdEncoding.DecodeString(req.Context)
	if err != nil {
		panic(err)
	}
	aesPublicKey, err := util.RsaDecrypt([]byte(pk))
	if err != nil {
		panic(err)
	}

	context, err := util.AesDecrypt([]byte(ct), aesPublicKey)
	if err != nil {
		panic(err)
	}
	c.String(http.StatusOK, string(context))

}

func PublicKeyHandler(c *gin.Context) {
	c.String(http.StatusOK, string(util.PublicKey))
}
