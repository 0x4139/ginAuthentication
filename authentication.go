package ginAuthentication

import (
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

type checkCredentials func(AuthenticationCredentials) (valid bool, err error)

type AuthenticationEngine struct {
	AesKey               []byte
	CookieName           string
	CheckCredentials     checkCredentials
	CookieExpirationTime time.Time
}

type AuthenticationCredentials struct {
	Username string
	Password string
}

func New(params AuthenticationEngine) (engine *AuthenticationEngine, err error) {
	if len(params.AesKey) != 32 {
		return nil, errors.New("aesKey must be 32bytes")
	}
	return &params, nil
}

func (engine *AuthenticationEngine) Validate(credentials AuthenticationCredentials) (bool, error) {
	valid, err := engine.CheckCredentials(credentials)
	return valid, err
}

func (engine *AuthenticationEngine) ValidateAndSetCookie(credentials AuthenticationCredentials, c *gin.Context) (bool, error) {
	valid, err := engine.CheckCredentials(credentials)
	if err != nil || valid == false {
		return false, err
	}
	cookieVal := CookieSchema{
		Username: credentials.Username,
		LoggedIn: true,
	}
	encryptedCookie, err := cookieVal.EncryptAES(engine.AesKey)
	if err != nil {
		return false, err
	}
	cookie := http.Cookie{
		Name: engine.CookieName,
		Value: encryptedCookie,
		Expires: engine.CookieExpirationTime,
	}
	http.SetCookie(c.Writer, &cookie)
	return valid, nil
}

func (engine *AuthenticationEngine) ValidationMiddleware(notAuthenticatedRoute string) gin.HandlerFunc {
	return func(c *gin.Context) {
		cookieString, err := c.Request.Cookie(engine.CookieName)
		if err != nil || cookieString == nil {
			c.Redirect(http.StatusSeeOther, notAuthenticatedRoute)
			c.Abort()
		} else {
			cookieVal := CookieSchema{}
			err := cookieVal.DecryptAES(engine.AesKey, cookieString.Value)
			if err != nil {
				c.Redirect(http.StatusSeeOther, notAuthenticatedRoute)
				c.Abort()
			} else {
				c.Set("username", cookieVal.Username)
				c.Next()
			}
		}
	}
}
