package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

var PrivateKey = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAzXHy6UyKLIXw7MdnZ/E/gARU3UV9BbZJDlNNgqTUj7+9fgMp
gMntcRK6q4kG0215coTfDcY7WY/HscsAu8rxycb4oaV8mJYsRB3EIZpKWlSgFE5M
yomza3n0TFWXbzjjvG7+AaRdUNpg/qsM6bTMQvFo+qmZc+KWp4oW2L41ARu66YwK
YgBEZf4/LKK9EyW+O8mWFFOul6cESEn6kTCutuQyOrCvzsT2wjG5slxKsF8/0iQN
jnpmlpm2oRVK97M7+1agiZl6Q/z/TBY+bECqtVNjtTrbNZQ17LyTlQT6ApqDfAsW
Jiu/wpsSvTRfzxmE/73FnOdO3lJxcHd5cC8ElQIDAQABAoIBADRywbvToXbKXv5j
zb9YdIifEndG1SsPJUl19NTEdcuY/Kxd7EuHwYlbabJ/EfIKAbY9u6ANmns73JRE
KhTHM8D6feDumYdu1zAwlTCq7g5vikqEzs/qJZbrlHWkaDupv2IMx+XtazFH/vkk
++/yCy+P5+gOQjG2iBWPiFOfA3MbhvmSpjX4bzHUqlS8FuDwnnhN3KvB2/pr64gO
LEHUE9AJPPG4R158eQt/K3Lk7UTWdkR500J/2UTo7YrpYM1aw24QQ9XOOIAgYSzc
VLUGlYKCX8uZBkBa2dsiu6m63dyOiBus1CsDkW8O1k40TNpB1ng+M76AoENJN65L
7hEz2oECgYEA2nu/Y3LpDy21Qx4bQv9r3DJ/2wt4z3dgzNJ97SzgsdZZ4dqbOzX6
RgDumGzeDVNBorC2rdOAI6O+oh/tTgdkkq+LqEksMAKuVmjpYPgzUUkChY7MzGGA
C5mlH+3Xnm5NrvKA44NKWulGPR1ZzyKkFaY5SADQs0tZZ0kjIuRXwWECgYEA8LkO
IMvjfPoqWYI+Z86qVLfOMPMO7e7efgdIbcmpJuBfByVLUDroWdDCQEE/v4hMjjKj
rld1aDHgmMiY9ZFXS1nYAfd4n5VH2J9mT7ccmJ1Tmht2Pwkvz5cYY2GMwAIX+Hnb
epGAq3vakwymRAHnZoj8b1aloRGI6jZz5fmoK7UCgYEAtRDDPz7XKQ4fX31O6IpX
sEhlr3nlaEKuBXEYjXuYx6k2GjgaV8rXHDbfhZELwY1TIupCqvJSCrdEYIYHG5iC
4BH9srzZkvxV0STm7McleGMCZP9AeM0A2hw+PaTWAeW2GZu9908ySv9yh2mQqVoz
FAILDMIoM77pW/C/3sXQeGECgYAI3PdtM7SbjGZ0xzve/Jf+6ImZ+ckJ76qXf1Mm
X69vtAErtS7RtGmLrQkJ7p0XQ0B2V9z49VVoUbXQSkp/eCt7pcIzSFZTod50VmIg
+z/9SoWiffJbnc352blXJ2dURn91cZ8oIyVWqwfANE4G4P8RImgQ/WK5zHh7Dygz
Rn7vpQKBgA+OVOGZ1VSJ1URvPAtMAOfXL9ivTpgw9gAt3zgcmDNcYSLNw+uQR1Xa
VPdLy1CoxWVk2xqxskCZiYYBHRfkr+08ETbXDLRBfZY1vV2HzICSP10j1TWtOJpU
24DsGXmxm14sKM4gJoY4vJQJBHOB54bQ4JsEH9+dzh6W2/ElZUgr
-----END RSA PRIVATE KEY-----`)

func main() {
	key := []byte("12345678abcdefgh")
	resp, err := http.Get("http://192.168.54.172:8080/publicKey")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	context := "试试传说中的对称加密内容，不对称加密密钥"
	// ct pk 分别为用aes加密后的内容，rsa加密后的密钥
	ct, err := AesEncrypt([]byte(context), key)
	if err != nil {
		panic(err)
	}

	pbk := string(body)
	pk, err := RsaEncrypt(key, []byte(pbk))
	if err != nil {
		panic(err)
	}

	requestBody := map[string]interface{}{
		"context":    base64.StdEncoding.EncodeToString(ct),
		"public_key": base64.StdEncoding.EncodeToString(pk),
	}

	// fmt.Println(string(pk))
	message, err := json.Marshal(requestBody)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(message))
	req, err := http.NewRequest("POST", "http://192.168.54.172:8080/context", bytes.NewBuffer(message))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(body))
}

//@brief:填充明文
func PKCS5Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

//@brief:去除填充数据
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//@brief:AES加密
func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//AES分组长度为128位，所以blockSize=16，单位字节
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize]) //初始向量的长度必须等于块block的长度16字节
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func RsaEncrypt(origData []byte, publicKey []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}

func RsaDecrypt(ciphertext []byte) ([]byte, error) {
	block, _ := pem.Decode(PrivateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}
