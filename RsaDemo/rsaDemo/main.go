package main

import (
	"rsaDemo/handler"

	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()

	router.GET("/publicKey", handler.PublicKeyHandler)
	router.POST("/context", handler.RsaHandler)

	router.Run()
}
