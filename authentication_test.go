package ginAuthentication
import (
	"testing"
	"time"
)

func TestShouldCreateNewAuthEngine(t *testing.T) {
	_,err:=New(AuthenticationEngine{
		AesKey:[]byte("a very very very very secret key") /*32 bytes*/,
		CookieExpirationTime:5*time.Hour,
		CookieName:"gin-auth",
		CheckCredentials:func (credentials AuthenticationCredentials) (valid bool,err error){
			return true,nil//authenticate any user
		}})

	if err!=nil{
		t.Error("Bloom filter not working");
	}
}