package ginAuthentication
import (
	"testing"
	"time"
)

func TestShouldCreateNewAuthEngine(t *testing.T) {
	_,err:=New(AuthenticationEngine{
		aesKey:[]byte("a very very very very secret key") /*32 bytes*/,
		cookieExpirationTime:5*time.Hour,
		cookieName:"gin-auth",
		fn:func (authenticationCredentials) (valid bool,err error){
			return true,nil//authenticate any user
		}})

	if err!=nil{
		t.Error("Bloom filter not working");
	}
}