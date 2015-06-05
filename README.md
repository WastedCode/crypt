# Crypt
A simple go package to encrypt/decrypt data. Uses AES + hex encoding.

[![Build Status](https://travis-ci.org/WastedCode/crypter.svg?branch=master)](https://travis-ci.org/WastedCode/crypter)

# Example Usage
## Encrypt
### Byte Array
```
data := []byte("somestring")
key := "1234567890123456" // Must be 16, 24 or 32 characters
crypt, err := NewCryptFromUnencryptedData(data, key)
encrypted, err := crypt.Encrypt()
encryptedStr, err := crypt.EncryptToString() // Returns a hex string instead of []byte
```
### Plain text
```
data := "somestring"
key := "1234567890123456" // Must be 16, 24 or 32 characters
crypt, err := NewCryptFromPlainText(data, key)
```

## Decrypt
### Byte Array
```
crypt, err := NewCryptFromCipherData(data, key)
decrypted, err = crypt.Decrypt()
decryptedStr, err = crypt.DecryptToString()
```
### Hex string
```
crypt, err := NewCryptFromHexString(dataHexString, key)
decryptedStr, err = crypt.DecryptToString()
```
