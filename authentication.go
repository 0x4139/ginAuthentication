package ginAuthentication

import (
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
	"crypto/aes"
	"encoding/base64"
	"io"
	"crypto/rand"
	"crypto/cipher"
	"bytes"
	"time"
)

type checkCredentials func(AuthenticationCredentials) (valid bool, err error)

type AuthenticationEngine struct {
	AesKey []byte
	CookieName string
	CheckCredentials checkCredentials
	CookieExpirationTime time.Time
}
type AuthenticationCredentials struct{
	Username string
	Password string
}

func New(params AuthenticationEngine) (engine *AuthenticationEngine,err error)  {
	if len(params.AesKey) != 32 {
		return nil,errors.New("aesKey must be 32bytes")
	}
	return &AuthenticationEngine{CookieName:params.CookieName, CheckCredentials:params.CheckCredentials},nil
}

func (engine *AuthenticationEngine) Validate(credentials AuthenticationCredentials) (bool,error){
	valid,err:=engine.CheckCredentials(credentials)
	return valid,err
}

func (engine *AuthenticationEngine) ValidateAndSetCookie(credentials AuthenticationCredentials,c *gin.Context) (bool,error){
	valid, err := engine.CheckCredentials(credentials)
	if err != nil || valid == false {
		return false, err
	}
	encryptedCookie,err:=encryptAES(engine.AesKey,[]byte("loggedIn=true"))
	if err!=nil {
		return false,err
	}
	cookie := http.Cookie{Name: engine.CookieName, Value:string(encryptedCookie), Expires: engine.CookieExpirationTime}
	http.SetCookie(c.Writer, &cookie)
	return valid,nil
}

func (engine *AuthenticationEngine) ValidationMiddleware(notAuthenticatedRoute string)  gin.HandlerFunc {
	return func(c *gin.Context) {
		cookieString,err:=c.Request.Cookie(engine.CookieName)
		if err!=nil || cookieString==nil{
			c.Redirect(http.StatusSeeOther, notAuthenticatedRoute)
		}else{
			value,err:=decryptAES(engine.AesKey, []byte(cookieString.Value))
			if err!=nil || !bytes.Equal(value,[]byte("loggedIn=true")){
				c.Redirect(http.StatusSeeOther, notAuthenticatedRoute)
			}else{
				c.Next()
			}
		}
	}
}

func encryptAES(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func decryptAES(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}

