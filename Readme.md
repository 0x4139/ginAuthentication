## ginAuthentication: a cookie validation engine and middleware for gin-web-framework
===
This implements a basic authentication engine and middleware for gin-web-framework

###  Instalation

```sh
go get github.com/0x4139/ginAuthentication
```

### Tests
No tests were written :( sorry
```sh
go 
```
### Usage 
```go
package ginAuthentication

import (
"github.com/gin-gonic/gin"
"time"
)

func main() {
	r := gin.New()
	authEngine,_:=New(AuthenticationEngine{
		aesKey:[]byte("a very very very very secret key") /*32 bytes*/,
		cookieExpirationTime:5*time.Hour,
		cookieName:"gin-auth",
		fn:func (authenticationCredentials) (valid bool,err error){
			return true,nil//authenticate any user
		}})
	r.Use(authEngine.ValidationMiddleware("/not/authenticated/route"))
	r.POST("/authenticate", func(c *gin.Context) {
		authEngine.ValidateAndSetCookie(authenticationCredentials{username:c.Get("username"),password:c.Get("password")},c)
	})

	r.Run(":8080") // listen and serve on 0.0.0.0:8080
}
```

### TODO
More tests
send pull requests please, love them
