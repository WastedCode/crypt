# Crypt
A simple go package to encrypt/decrypt data. Uses AES + hex encoding.

# Example Usage
## Encrypt
### Byte Array
```
data := []byte("somestring")
key := "1234567890123456" // Must be 16, 24 or 32 characters
crypt := NewCryptFromUnencryptedData(data, key)
encrypted, err := crypt.Encrypt()
encryptedStr, err := crypt.EncryptToString() // Returns a hex string instead of []byte
```
### Plain text
```
data := "somestring"
key := "1234567890123456" // Must be 16, 24 or 32 characters
crypt := NewCryptFromPlainText(data, key)
```

## Decrypt
### Byte Array
```
crypt := NewCryptFromCipherData(data, key)
decrypted, err = crypt.Decrypt()
decryptedStr, err = crypt.DecryptToString()
```
### Hex string
```
crypt := NewCryptFromHexString(dataHexString, key)
decryptedStr, err = crypt.DecryptToString()
```
