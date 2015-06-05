package crypter

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/hex"
    "errors"
    "io"
)

// Crypt stores a collection of encrypted data
// Along with its plain text and encryption key
type Crypt struct {
    UnencryptedData []byte
    CipherData []byte
    Key []byte
}

// Error when the key provided is not valid
var ErrInvalidCryptKey = errors.New("the given key is invalid")

// NewCryptFromPlainText creates a new crypt from plain text
// To create from Bytes look at NewCryptFromUnencryptedData
func NewCryptFromPlainText(plainText, key string) (*Crypt, error) {
    return NewCryptFromUnencryptedData([]byte(plainText), key)
}

// NewCryptFromUnencryptedData creates a new crypt from an array of bytes
func NewCryptFromUnencryptedData(data []byte, key string) (*Crypt, error) {
    if (!ValidateCryptKey(key)) {
        return nil, ErrInvalidCryptKey
    }
    crypt := Crypt {
        UnencryptedData: data,
        Key: []byte(key)}
    return &crypt, nil
}

// NewCryptFromHexCipherText creates a new crypt from hex encoded encrypted text
// It returns an error on failure
func NewCryptFromHexCipherText(cipherText, key string) (*Crypt, error) {
    decodedString, err := DecodeHexString(cipherText)
    if (err != nil) {
        return nil, err
    }
    return NewCryptFromCipherData(decodedString, key)
}

// NewCryptFromCipherData creates a new crypt from an array of bytes that have encrypted data
func NewCryptFromCipherData(cipherData []byte, key string) (*Crypt, error) {
    if (!ValidateCryptKey(key)) {
        return nil, ErrInvalidCryptKey
    }
    crypt := Crypt {
        CipherData: cipherData,
        Key: []byte(key)}
    return &crypt, nil
}

// Encrypt encrypts the plain data using the given key
// Error is nil if the method successfully encrypts the data
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

// EncryptToString encrypts the data and encodes it to a hex string
// Error is nil if the method successfully encrypts the data
// It returns a hex encoded string for the encrypted data
func (crypt *Crypt) EncryptToString() (string, error) {
    data, err := crypt.Encrypt()
    if (err != nil) {
        return "", err
    }
    return hex.EncodeToString(data), nil
}

// Decrypt tries to decrypt the given encrypted data into plain data
// Error is nil if the decrypt was successful
func (crypt *Crypt) Decrypt() ([]byte, error) {
    block, err := aes.NewCipher(crypt.Key)
    if (err != nil) {
        return nil, err
    }

    if (len(crypt.CipherData) < aes.BlockSize) {
        return nil, errors.New("invalid cipher text")
    }

    // Retrieve the cipher
    iv := crypt.CipherData[:aes.BlockSize]
    cipherText := crypt.CipherData[aes.BlockSize:]
    crypt.UnencryptedData = make([]byte, len(cipherText))
    stream := cipher.NewCFBDecrypter(block, iv)

    stream.XORKeyStream(crypt.UnencryptedData, cipherText)
    return crypt.UnencryptedData, nil
}

// DecryptToString decrypts the data and converts it to a string
// Tries to convert the decrypted data into a string and returns it
func (crypt *Crypt) DecryptToString() (string, error) {
    data, err := crypt.Decrypt()
    if (err != nil) {
        return "", err
    }
    return string(data), nil
}

// DecodeHexString decodes the string from hex to a byte array
func DecodeHexString(text string) ([]byte, error) {
    textBytes, err := hex.DecodeString(text)
    if (err != nil) {
        return nil, err
    }
    return textBytes, nil
}

// ValidateCryptKey checks for the validity of the given key
// The cryptographic system requires a key size of 16, 24 or 32 only
// All other keys will be rejected
func ValidateCryptKey(key string) bool {
    keyLength := len(key)
    validSizes := []int {16, 24, 32}
    for _, size := range validSizes {
        if (keyLength == size) {
            return true
        }
    }
    return false
}
