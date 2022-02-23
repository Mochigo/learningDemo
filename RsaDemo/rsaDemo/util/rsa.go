package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

var PublicKey = []byte(`
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzXHy6UyKLIXw7MdnZ/E/
gARU3UV9BbZJDlNNgqTUj7+9fgMpgMntcRK6q4kG0215coTfDcY7WY/HscsAu8rx
ycb4oaV8mJYsRB3EIZpKWlSgFE5Myomza3n0TFWXbzjjvG7+AaRdUNpg/qsM6bTM
QvFo+qmZc+KWp4oW2L41ARu66YwKYgBEZf4/LKK9EyW+O8mWFFOul6cESEn6kTCu
tuQyOrCvzsT2wjG5slxKsF8/0iQNjnpmlpm2oRVK97M7+1agiZl6Q/z/TBY+bECq
tVNjtTrbNZQ17LyTlQT6ApqDfAsWJiu/wpsSvTRfzxmE/73FnOdO3lJxcHd5cC8E
lQIDAQAB
-----END PUBLIC KEY-----`)

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

func RsaEncrypt(origData []byte) ([]byte, error) {
	block, _ := pem.Decode(PublicKey)
	if block != nil {
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
