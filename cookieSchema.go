package ginAuthentication

import (
    "bytes"
    "encoding/gob"
    "crypto/aes"
    "encoding/base64"
    "io"
    "crypto/rand"
    "crypto/cipher"
    "errors"
)

type CookieSchema struct {
    Username string
    LoggedIn bool
}

func (c *CookieSchema) Serialize() ([]byte, error){
    var b bytes.Buffer
    e := gob.NewEncoder(&b)
    err := e.Encode(c)
    if err != nil {
        return nil, err
    } else {
        return b.Bytes(), nil
    }
}

func (c *CookieSchema) Deserialize(by []byte) error {
    var b bytes.Buffer
    b.Write(by)
    d := gob.NewDecoder(&b)
    err := d.Decode(&c)
    return err
}

func (c *CookieSchema) EncryptAES(key []byte) (string, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }
    text, err := c.Serialize()
    if err != nil {
        return "", err
    }
    b := base64.StdEncoding.EncodeToString(text)
    ciphertext := make([]byte, aes.BlockSize + len(b))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }
    cfb := cipher.NewCFBEncrypter(block, iv)
    cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))

    return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func (c *CookieSchema) DecryptAES(key []byte, input string) error {
    block, err := aes.NewCipher(key)
    if err != nil {
        return err
    }
    text, err := base64.URLEncoding.DecodeString(input)
    if err != nil {
        return err
    }
    if len(text) < aes.BlockSize {
        return errors.New("ciphertext too short")
    }
    iv := text[:aes.BlockSize]
    text = text[aes.BlockSize:]
    cfb := cipher.NewCFBDecrypter(block, iv)
    cfb.XORKeyStream(text, text)
    data, err := base64.StdEncoding.DecodeString(string(text))
    if err != nil {
        return err
    }

    return c.Deserialize(data)
}

