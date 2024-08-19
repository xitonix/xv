package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/alecthomas/kingpin/v2"
)

const (
	binary  = "xv"
	keySize = 32
)

// Version build flags
var (
	version string
)

func main() {
	app := kingpin.New(binary, `A CLI tool to encode/decode data with standard command piping support.`)

	key := app.Flag("key", "Encryption key.").
		Envar("XV_KEY").
		Short('k').
		Required().
		String()
	dec := app.Flag("decrypt", "Decrypts input data.").Short('d').Bool()
	raw := app.Flag("raw", "Operates in raw mode. Suitable to encrypt/decrypt non-textual files.").Short('r').Bool()
	ver := app.Flag("version", "Displays the current version of the tool.").Short('v').Bool()

	text := app.Arg("text", `The text to encrypt/decrypt. You can use pipes to encrypt/decrypt files.

Examples: 

 Plain Text: xv 'plain text' OR echo "plain text" | xv
  Text File: cat file.txt | xv -r > enc.txt
        Raw: cat file.jpg | xv -r > enc.jpg && cat enc.jpg | xv -r -d > dec.jpg`).String()

	log.SetFlags(0)
	_, err := app.Parse(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}

	if *ver {
		printVersion()
		return
	}

	if len(*key) < keySize {
		log.Fatalf("Key must be at least %d bytes", keySize)
	}

	if isInputFromPipe() {
		if *dec {
			err = decrypt(os.Stdin, *key, *raw)
		} else {
			err = encrypt(os.Stdin, *key, *raw)
		}
	} else {
		input := strings.NewReader(*text)
		if *dec {
			err = decrypt(input, *key, *raw)
		} else {
			err = encrypt(input, *key, *raw)
		}
	}
	if err != nil {
		log.Fatal(err)
	}
}

func printVersion() {
	if version == "" {
		version = "[built from source]"
	}
	fmt.Printf("%s %s", binary, version)
}

func encrypt(reader io.Reader, key string, raw bool) error {
	value, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("Failed to read the input: %w", err)
	}

	if len(bytes.TrimSpace(value)) == 0 {
		return nil
	}
	c, err := aes.NewCipher([]byte(key[:keySize]))
	if err != nil {
		return fmt.Errorf("Failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return fmt.Errorf("Failed to create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("Failed to create nonce: %w", err)
	}
	encrypted := gcm.Seal(nonce, nonce, value, nil)
	if raw {
		_, err = os.Stdout.Write(encrypted)
	} else {
		_, err = os.Stdout.WriteString(hex.EncodeToString(encrypted))
	}
	return err
}

func decrypt(reader io.Reader, key string, raw bool) error {
	value, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("Failed to read the input: %w", err)
	}

	if len(bytes.TrimSpace(value)) == 0 {
		return nil
	}

	if !raw {
		value, err = hex.DecodeString(string(value))
		if err != nil {
			return fmt.Errorf("Failed to decode the input: %w", err)
		}
	}

	c, err := aes.NewCipher([]byte(key[:keySize]))
	if err != nil {
		return fmt.Errorf("Failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return fmt.Errorf("Failed to create GCM: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(value) < nonceSize {
		return fmt.Errorf("Invalid input encrypted data")
	}

	nonce, ciphertext := value[:nonceSize], value[nonceSize:]
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("Failed to decrypt input: %w", err)
	}
	if raw {
		_, err = os.Stdout.Write(decrypted)
	} else {
		_, err = os.Stdout.WriteString(string(decrypted))
	}
	return nil
}

func isInputFromPipe() bool {
	fileInfo, _ := os.Stdin.Stat()
	return fileInfo.Mode()&os.ModeCharDevice == 0
}
