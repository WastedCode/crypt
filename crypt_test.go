package crypter

import (
    "encoding/hex"
    "testing"
)

var cryptKeys = []string {
    "1234567890123456",
    "123456789012345678901234",
    "12345678901234567890123456789012",
}

func TestDecodeHexString(t *testing.T) {
    testStr := "testing string"
    hexStr := hex.EncodeToString([]byte(testStr))
    if (string(DecodeHexString(hexStr)) != testStr) {
        t.Error("Should have decoded to " + testStr)
    }

    testStr = ""
    hexStr = hex.EncodeToString([]byte(testStr))
    if (string(DecodeHexString(hexStr)) != testStr) {
        t.Error("Could not decode empty string")
    }
}

func TestDecodeHexStringInvalidInput(t *testing.T) {
    testStr := "invalid hex"
    defer func() {
        r := recover()
        if (r == nil) {
            t.Error("Failed to panic with invalid hex")
        }
    }()
    DecodeHexString(testStr)
}

func TestValidateCryptKey(t *testing.T) {
    defer func() {
        if (recover() != nil) {
            t.Error("Failed to accept a valid crypt key")
        }
    }()
    for _, key := range cryptKeys {
        ValidateCryptKey(key)
    }
}

func TestValidateCryptKeyWithInvalidKey(t *testing.T) {
    defer func() {
        if (recover() == nil) {
            t.Error("Failed to panic when an invalid key was given")
        }
    }()

    ValidateCryptKey("invalidkey")
}

func TestNewCryptFromPlainText(t *testing.T) {
    text := "plain text"
    key := cryptKeys[0]
    crypt := NewCryptFromPlainText(text, key)
    if (string(crypt.UnencryptedData) != text) {
        t.Errorf("Unable to initialize crypt with plain text '%s'", text)
    }

    if (string(crypt.Key) != key) {
        t.Errorf("Unable to initialize crypt with key '%s'", key)
    }
}

func TestNewCryptFromUnencryptedData(t *testing.T) {
    text := "plain text"
    data := []byte(text)
    key := cryptKeys[0]
    crypt := NewCryptFromUnencryptedData(data, key)
    if (string(crypt.UnencryptedData) != text) {
        t.Errorf("Unable to initialize crypt with plain text '%s'", text)
    }

    if (string(crypt.Key) != key) {
        t.Errorf("Unable to initialize crypt with key '%s'", key)
    }
}

func TestNewCryptFromHexCipherText(t *testing.T) {
    textStr := "teststring"
    hexStr := hex.EncodeToString([]byte(textStr))
    key := cryptKeys[1]
    crypt := NewCryptFromHexCipherText(hexStr, key)
    if (string(crypt.CipherData) != textStr) {
        t.Errorf("Unable to initialize crypt with hex data '%s'", hexStr)
    }

    if (string(crypt.Key) != key) {
        t.Errorf("Unable to initialize crypt with key '%s'", key)
    }
}

func TestNewCryptFromCipherData(t *testing.T) {
    textStr := "teststring"
    key := cryptKeys[1]
    crypt := NewCryptFromCipherData([]byte(textStr), key)
    if (string(crypt.CipherData) != textStr) {
        t.Errorf("Unable to initialize crypt with hex data '%s'", textStr)
    }

    if (string(crypt.Key) != key) {
        t.Errorf("Unable to initialize crypt with key '%s'", key)
    }
}

func TestEncryptDecryptString(t *testing.T) {
    stringToEncrypt := "some string"
    key := cryptKeys[0]
    crypt := NewCryptFromPlainText(stringToEncrypt, key)
    encrypted, err := crypt.Encrypt()

    if (err != nil) {
        t.Error("Unable to encrypt string")
    }

    if (hex.EncodeToString(crypt.CipherData) != hex.EncodeToString(encrypted)) {
        t.Error("Did not set the cipher data after encryption")
    }

    decrypted, err := crypt.DecryptToString()
    if (err != nil) {
        t.Error("Unable to encrypt string")
    }

    if (decrypted != stringToEncrypt) {
        t.Errorf("Unable to encrypt/decrypt string: '%s'", stringToEncrypt)
    }

    crypt = NewCryptFromCipherData(encrypted, key)
    decrypted, err = crypt.DecryptToString()
    if (err != nil) {
        t.Error("Unable to encrypt string")
    }

    if (decrypted != stringToEncrypt) {
        t.Errorf("Unable to encrypt/decrypt string: '%s'", stringToEncrypt)
    }
}

func TestEncryptDecryptThroughHex(t *testing.T) {
    stringToEncrypt := "some string"
    key := cryptKeys[0]
    crypt := NewCryptFromPlainText(stringToEncrypt, key)
    encrypted, err := crypt.EncryptToString()

    if (err != nil) {
        t.Error("Unable to encrypt string")
    }

    if (hex.EncodeToString(crypt.CipherData) != encrypted) {
        t.Error("Did not set the cipher data after encryption")
    }

    decrypted, err := crypt.DecryptToString()
    if (err != nil) {
        t.Error("Unable to encrypt string")
    }

    if (decrypted != stringToEncrypt) {
        t.Errorf("Unable to encrypt/decrypt string: '%s'", stringToEncrypt)
    }

    crypt = NewCryptFromHexCipherText(encrypted, key)
    decrypted, err = crypt.DecryptToString()
    if (err != nil) {
        t.Error("Unable to encrypt string")
    }

    if (decrypted != stringToEncrypt) {
        t.Errorf("Unable to encrypt/decrypt string: '%s'", stringToEncrypt)
    }
}

func TestDecryptWithInvalidData(t *testing.T) {
    key := cryptKeys[0]
    crypt := NewCryptFromHexCipherText(hex.EncodeToString([]byte("lesthnbsize")), key)
    _, err := crypt.Decrypt()
    if (err == nil) {
        t.Error("Did not fail with invalid text for decryption")
    }
}
