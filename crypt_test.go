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
    decodedStr, err := DecodeHexString(hexStr)
    if (string(decodedStr) != testStr) {
        t.Error("Should have decoded to " + testStr)
    }

    if (err != nil) {
        t.Error("Returned an error when decoding a valid hex string")
    }

    testStr = ""
    hexStr = hex.EncodeToString([]byte(testStr))
    decodedStr, err = DecodeHexString(hexStr)
    if (string(decodedStr) != testStr) {
        t.Error("Could not decode empty string")
    }

    if (err != nil) {
        t.Error("Returned an error when decoding a valid hex string")
    }
}

func TestDecodeHexStringInvalidInput(t *testing.T) {
    testStr := "invalid hex"
    _, err := DecodeHexString(testStr)

    if (err == nil) {
        t.Error("Did not return an error when decoding a bad string")
    }
}

func TestValidateCryptKey(t *testing.T) {
    for _, key := range cryptKeys {
        if (!ValidateCryptKey(key)) {
            t.Errorf("Rejected a valid Crypt Key: %s", key)
        }
    }
}

func TestValidateCryptKeyWithInvalidKey(t *testing.T) {
    if (ValidateCryptKey("invalidkey")) {
        t.Error("Did not reject invalid crypt key")
    }
}

func TestNewCryptFromPlainTextBadKey(t *testing.T) {
    crypt, err := NewCryptFromPlainText("abc", "abc")
    if (crypt != nil || err == nil) {
        t.Error("Didnt raise an error with invalid key")
    }
}

func TestNewCryptFromPlainText(t *testing.T) {
    text := "plain text"
    key := cryptKeys[0]
    crypt, err := NewCryptFromPlainText(text, key)
    if (err != nil) {
        t.Error("Returned an error when one was not expected")
    }

    if (string(crypt.UnencryptedData) != text) {
        t.Errorf("Unable to initialize crypt with plain text '%s'", text)
    }

    if (string(crypt.Key) != key) {
        t.Errorf("Unable to initialize crypt with key '%s'", key)
    }
}

func TestNewCryptFromUnencryptedDataBadKey(t *testing.T) {
    crypt, err := NewCryptFromUnencryptedData([]byte("abc"), "abc")
    if (crypt != nil || err == nil) {
        t.Error("Didnt raise an error with invalid key")
    }
}

func TestNewCryptFromUnencryptedData(t *testing.T) {
    text := "plain text"
    data := []byte(text)
    key := cryptKeys[0]
    crypt, err := NewCryptFromUnencryptedData(data, key)
    if (err != nil) {
        t.Error("Returned an error when one was not expected")
    }

    if (string(crypt.UnencryptedData) != text) {
        t.Errorf("Unable to initialize crypt with plain text '%s'", text)
    }

    if (string(crypt.Key) != key) {
        t.Errorf("Unable to initialize crypt with key '%s'", key)
    }
}

func TestNewCryptFromHexCipherTextBadKey(t *testing.T) {
    crypt, err := NewCryptFromHexCipherText("abc", "abc")
    if (crypt != nil || err == nil) {
        t.Error("Didnt raise an error with invalid key")
    }
}

func TestNewCryptFromHexCipherText(t *testing.T) {
    textStr := "teststring"
    hexStr := hex.EncodeToString([]byte(textStr))
    key := cryptKeys[1]
    crypt, err := NewCryptFromHexCipherText(hexStr, key)
    if (err != nil) {
        t.Error("Returned an error when one was not expected")
    }

    if (string(crypt.CipherData) != textStr) {
        t.Errorf("Unable to initialize crypt with hex data '%s'", hexStr)
    }

    if (string(crypt.Key) != key) {
        t.Errorf("Unable to initialize crypt with key '%s'", key)
    }
}

func TestNewCryptFromCipherDataBadKey(t *testing.T) {
    crypt, err := NewCryptFromCipherData([]byte("abc"), "abc")
    if (crypt != nil || err == nil) {
        t.Error("Didnt raise an error with invalid key")
    }
}

func TestNewCryptFromCipherData(t *testing.T) {
    textStr := "teststring"
    key := cryptKeys[1]
    crypt, err := NewCryptFromCipherData([]byte(textStr), key)
    if (err != nil) {
        t.Error("Returned an error when one was not expected")
    }

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
    crypt, err := NewCryptFromPlainText(stringToEncrypt, key)
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

    crypt, err = NewCryptFromCipherData(encrypted, key)
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
    crypt, err := NewCryptFromPlainText(stringToEncrypt, key)
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

    crypt, err = NewCryptFromHexCipherText(encrypted, key)
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
    crypt, err := NewCryptFromHexCipherText(hex.EncodeToString([]byte("lesthnbsize")), key)
    _, err = crypt.Decrypt()
    if (err == nil) {
        t.Error("Did not fail with invalid text for decryption")
    }
}
