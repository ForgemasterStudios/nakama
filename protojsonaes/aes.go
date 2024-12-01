package protojsonaes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

var (
	ErrPaddingSize = errors.New("padding size error")

	// difference with pkcs5 only block must be 8
	PKCS7 = &pkcs5{}
)

// pkcs5Padding is a pkcs5 padding struct.
type pkcs5 struct{}

// Padding implements the Padding interface Padding method.
func (p *pkcs5) Padding(src []byte, blockSize int) []byte {
	srcLen := len(src)
	padLen := blockSize - (srcLen % blockSize)
	padText := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(src, padText...)
}

// Unpadding implements the Padding interface Unpadding method.
func (p *pkcs5) Unpadding(src []byte, blockSize int) ([]byte, error) {
	srcLen := len(src)
	paddingLen := int(src[srcLen-1])
	if paddingLen >= srcLen || paddingLen > blockSize {
		return nil, ErrPaddingSize
	}
	return src[:srcLen-paddingLen], nil
}

func Encrypt(key []byte, plainText []byte) ([]byte, error) {
	if len(plainText) == 0 {
		return []byte{}, errors.New("plaintext can not be empty")
	}
	if len(key) != aes.BlockSize {
		return []byte{}, errors.New("key length must be length of block size")
	}

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2.
	plainText = PKCS7.Padding(plainText, aes.BlockSize)
	if len(plainText) < aes.BlockSize || len(plainText)%aes.BlockSize != 0 {
		return []byte{}, errors.New("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the cipherText.
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return []byte{}, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], plainText)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.
	return cipherText, nil
}

func Decrypt(key []byte, cipherText []byte) ([]byte, error) {
	if len(cipherText) == 0 {
		return []byte{}, errors.New("cipherText can not be empty")
	}
	// CBC mode always works in whole blocks.
	if len(cipherText)%aes.BlockSize != 0 {
		return []byte{}, errors.New("ciphertext is not a multiple of the block size")
	}
	if len(key) != aes.BlockSize {
		return []byte{}, errors.New("key length must be length of block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(cipherText, cipherText)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2.
	cipherText, err = PKCS7.Unpadding(cipherText, aes.BlockSize)

	// It's critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.
	return cipherText, err
}
