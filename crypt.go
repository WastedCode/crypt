package crypter

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/hex"
    "errors"
    "io"
)

type Crypt struct {
    UnencryptedData []byte
    CipherData []byte
    Key []byte
}

func NewCryptFromPlainText(plainText, key string) (*Crypt) {
    return NewCryptFromUnencryptedData([]byte(plainText), key)
}

func NewCryptFromUnencryptedData(data []byte, key string) (*Crypt) {
    ValidateCryptKey(key)
    crypt := Crypt {
        UnencryptedData: data,
        Key: []byte(key)}
    return &crypt
}

func NewCryptFromHexCipherText(cipherText, key string) (*Crypt) {
    return NewCryptFromCipherData(DecodeHexString(cipherText), key)
}

func NewCryptFromCipherData(cipherData []byte, key string) (*Crypt) {
    ValidateCryptKey(key)
    crypt := Crypt {
        CipherData: cipherData,
        Key: []byte(key)}
    return &crypt
}

func (crypt *Crypt) Encrypt() ([]byte, error) {
    block, err := aes.NewCipher(crypt.Key)
    if (err != nil) {
        return nil, err
    }

    crypt.CipherData = make([]byte, aes.BlockSize + len(crypt.UnencryptedData))

    // Generate initialization vector
    // This will generate a random vector
    iv := crypt.CipherData[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }

    // Use a stream cipher to encrypt the data
    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(crypt.CipherData[aes.BlockSize:], crypt.UnencryptedData)

    return crypt.CipherData, nil
}

func (crypt *Crypt) EncryptToString() (string, error) {
    data, err := crypt.Encrypt()
    if (err != nil) {
        return "", err
    }
    return hex.EncodeToString(data), nil
}

func (crypt *Crypt) Decrypt() ([]byte, error) {
    block, err := aes.NewCipher(crypt.Key)
    if (err != nil) {
        return nil, err
    }

    if (len(crypt.CipherData) < aes.BlockSize) {
        return nil, errors.New("Invalid cipher text")
    }

    iv := crypt.CipherData[:aes.BlockSize]
    cipherText := crypt.CipherData[aes.BlockSize:]
    crypt.UnencryptedData = make([]byte, len(cipherText))
    stream := cipher.NewCFBDecrypter(block, iv)

    stream.XORKeyStream(crypt.UnencryptedData, cipherText)
    return crypt.UnencryptedData, nil
}

func (crypt *Crypt) DecryptToString() (string, error) {
    data, err := crypt.Decrypt()
    if (err != nil) {
        return "", nil
    }
    return string(data), nil
}

// Decodes the string from hex to a byte array
// Panics if the input string is not hex encoded
func DecodeHexString(text string) ([]byte) {
    textBytes, err := hex.DecodeString(text)
    if (err != nil) {
        panic("The given string: " + text + " is not a valid hex string")
    }
    return textBytes
}

func ValidateCryptKey(key string) {
    keyLength := len(key)
    validSizes := []int {16, 24, 32}
    for _, size := range validSizes {
        if (keyLength == size) {
            return
        }
    }
    panic("The given key is of invalid size")
}
