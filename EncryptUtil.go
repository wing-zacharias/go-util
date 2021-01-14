package util

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// PKCS5Padding 填充模式
func PKCS5Padding(plain []byte, blockSize int) []byte {
	if blockSize != 8 {
		panic("wrong blocksize!")
	}
	padding := blockSize - len(plain)%blockSize
	//Repeat()函数的功能是把切片[]byte{byte(padding)}复制padding个，然后合并成新的字节切片返回
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plain, padtext...)
}

// PKCS5UnPadding 填充的反向操作,删除填充字符串
func PKCS5UnPadding(plain []byte) []byte {
	//获取数据长度
	length := len(plain)
	if length == 0 {
		panic("wrong plain!")
	} else {
		//获取填充字符串长度
		unpadding := int(plain[length-1])
		//截取切片,删除填充字节,并且返回明文
		return plain[:(length - unpadding)]
	}
}

// PKCS7Padding 填充模式
func PKCS7Padding(plain []byte, blockSize int) []byte {
	if blockSize < 0 || blockSize > 255 {
		panic("wrong blocksize!")
	}
	padding := blockSize - len(plain)%blockSize
	//Repeat()函数的功能是把切片[]byte{byte(padding)}复制padding个，然后合并成新的字节切片返回
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plain, padtext...)
}

// PKCS7UnPadding 填充的反向操作,删除填充字符串
func PKCS7UnPadding(plain []byte) []byte {
	//获取数据长度
	length := len(plain)
	if length == 0 {
		panic("wrong plain!")
	} else {
		//获取填充字符串长度
		unpadding := int(plain[length-1])
		//截取切片,删除填充字节,并且返回明文
		return plain[:(length - unpadding)]
	}
}

// ZeroPadding 等效于PKCS5
func ZeroPadding(plain []byte, blockSize int) []byte {
	padding := blockSize - len(plain)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(plain, padtext...)
}

// ZeroUnPadding 等效于PKCS5
func ZeroUnPadding(plain []byte) []byte {
	return bytes.TrimFunc(plain,
		func(r rune) bool {
			return r == rune(0)
		})
}

// AesEncrypt ...
func AesEncrypt(plain string, key string) (string, error) {
	runeKey := []rune(key)
	// strings.Count(key, "") - 1
	if len(runeKey) != 16 && len(runeKey) != 24 && len(runeKey) != 32 {
		return "", nil
	}
	plainByte := []byte(plain)
	keyByte := []byte(key)
	block, err := aes.NewCipher(keyByte)
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCEncrypter(block, keyByte[:blockSize])
	plainByte = PKCS7Padding(plainByte, blockSize)
	crypted := make([]byte, len(plainByte))
	blockMode.CryptBlocks(crypted, plainByte)
	return base64.StdEncoding.EncodeToString(crypted), nil
}

// AesDecrypt ...
func AesDecrypt(crypted string, key string) (string, error) {
	runeKey := []rune(key)
	if len(runeKey) != 16 && len(runeKey) != 24 && len(runeKey) != 32 {
		return "", nil
	}
	cryptdByte, _ := base64.StdEncoding.DecodeString(crypted)
	keyByte := []byte(key)
	block, err := aes.NewCipher(keyByte)
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCEncrypter(block, keyByte[:blockSize])
	plainByte := make([]byte, len(cryptdByte))
	blockMode.CryptBlocks(plainByte, cryptdByte)
	plainByte = PKCS7UnPadding(plainByte)
	if err != nil {
		return "", err
	}
	return string(plainByte), nil
}

// Base64Encrypt ...
func Base64Encrypt(plain []byte) ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(plain)), nil
}

// Base64Decrypt ...
func Base64Decrypt(crypted []byte) ([]byte, error) {
	plainByte, err := base64.StdEncoding.DecodeString(string(crypted))
	if err != nil {
		return nil, err
	}
	return plainByte, nil
}

// DesEncrypt 采用PKCS5
func DesEncrypt(plain []byte, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	// pdplain := e.ZeroPadding(plain, blockSize)
	pdplain := PKCS5Padding(plain, blockSize)
	if len(pdplain)%blockSize != 0 {
		return nil, errors.New("Need a multiple of the blocksize")
	}
	result := make([]byte, len(pdplain))
	dst := result
	for len(pdplain) > 0 {
		block.Encrypt(dst, pdplain[:blockSize])
		pdplain = pdplain[blockSize:]
		dst = dst[blockSize:]
	}
	return []byte(hex.EncodeToString(result)), nil
}

// DesDecrypt 采用PKCS5
func DesDecrypt(crypted []byte, key []byte) ([]byte, error) {
	plain, err := hex.DecodeString(string(crypted))
	if err != nil {
		return nil, err
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	result := make([]byte, len(plain))
	dst := result
	if len(plain)%blockSize != 0 {
		return nil, errors.New("crypto/cipher: input not full blocks")
	}
	for len(plain) > 0 {
		block.Decrypt(dst, plain[:blockSize])
		plain = plain[blockSize:]
		dst = dst[blockSize:]
	}
	// result = e.ZeroUnPadding(result)
	result = PKCS5UnPadding(plain)
	return result, nil
}

// DesCBCEncrypt ...
func DesCBCEncrypt(plain []byte, key []byte, ivb []byte) ([]byte, error) {
	var iv []byte
	if ivb == nil {
		iv = key
	} else if len(key) != len(ivb) {
		return nil, errors.New("The length of iv must be the same as the Block's block!")
	} else {
		iv = ivb
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain = PKCS5Padding(plain, block.BlockSize())
	crypted := make([]byte, len(plain))
	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(crypted, plain)
	return []byte(base64.StdEncoding.EncodeToString(crypted)), nil
}

// DesCBCDecrypt ...
func DesCBCDecrypt(crypted []byte, key []byte, ivb []byte) ([]byte, error) {
	var iv []byte
	if ivb == nil {
		iv = key
	} else if len(key) != len(ivb) {
		return nil, errors.New("The length of iv must be the same as the Block's block!")
	} else {
		iv = ivb
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cryptedBase64, err := base64.StdEncoding.DecodeString(string(crypted))
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(cryptedBase64))
	blockMode := cipher.NewCBCDecrypter(block, iv)
	blockMode.CryptBlocks(plain, cryptedBase64)
	plain = PKCS5UnPadding(plain)
	return plain, nil
}

// TripleDesEncrypt ...
func TripleDesEncrypt(plain []byte, key []byte, ivb []byte) ([]byte, error) {
	var iv []byte
	if len(key) != 24 {
		return nil, errors.New("The length of key must be:24!")
	}
	if ivb == nil {
		iv = key[:8]
	} else if len(ivb) == 8 {
		iv = ivb
	} else {
		return nil, errors.New("The length of iv must be:8!")
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	plain = PKCS7Padding(plain, block.BlockSize())
	// blockMode := cipher.NewCBCEncrypter(block, key[:block.BlockSize()])
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(plain))
	blockMode.CryptBlocks(crypted, plain)
	return crypted, nil
}

// TripleDesDecrypt ...
func TripleDesDecrypt(crypted []byte, key []byte, ivb []byte) ([]byte, error) {
	var iv []byte
	if len(key) != 24 {
		return nil, errors.New("The length of key must be:24!")
	}
	if ivb == nil {
		iv = key[:8]
	} else if len(ivb) == 8 {
		iv = ivb
	} else {
		return nil, errors.New("The length of iv must be:8!")
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	// blockMode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])
	blockMode := cipher.NewCBCDecrypter(block, iv)
	plainByte := make([]byte, len(crypted))
	blockMode.CryptBlocks(plainByte, crypted)
	plainByte = PKCS7UnPadding(plainByte)
	return plainByte, nil
}

// RsaEncrypt ...
func RsaEncrypt(plain []byte, publicKey []byte) ([]byte, error) {
	//解密pem格式的公钥
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	// 解析公钥
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// 类型断言
	pub := pubInterface.(*rsa.PublicKey)
	//加密
	return rsa.EncryptPKCS1v15(rand.Reader, pub, plain)
}

// RsaDecrypt ...
func RsaDecrypt(crypted []byte, privateKey []byte) ([]byte, error) {
	//解密
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error!")
	}
	//解析PKCS1格式的私钥
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// 解密
	return rsa.DecryptPKCS1v15(rand.Reader, priv, crypted)
}

// MD5Sum ...
func MD5Encrypt(plain string) string {
	h := md5.New()
	if _, err := h.Write([]byte(plain)); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// MD5Check crypted-密文,plain-明文
func MD5Check(crypted string, plain string) bool {
	return strings.EqualFold(MD5Encrypt(plain), crypted)
}

// SHA1EncryptHex ...
func SHA1EncryptHex(plain string) string {
	h := sha1.New()
	if _, err := h.Write([]byte(plain)); err != nil {
		return ""
	}
	plainByte := h.Sum(nil)
	return fmt.Sprintf("%x", plainByte)
}
