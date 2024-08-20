package commands

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/alecthomas/kingpin/v2"
)

type enc struct {
	encMode string
	text    string
	key     string
	appName string
}

func setupEncrypt(app *kingpin.Application) {
	cmd := &enc{
		appName: app.Name,
	}
	kCmd := app.Command("enc", `Encrypts data using AES-256 algorithm`).Alias("e").Action(cmd.run)
	kCmd.Flag("encoder", "Specifies how the encrypted data must be encoded. Same encoder must be used for decryption").
		Short('e').
		Default(string(encoderBase64)).
		EnumVar(&cmd.encMode, string(encoderBase64), string(encoderHex), string(encoderRaw))
	kCmd.Flag("key", fmt.Sprintf("The key to be used for encryption (instead of the key file). It MUST be at least %d characters.", keySize)).
		Short('k').
		StringVar(&cmd.key)
	kCmd.Arg("text", fmt.Sprintf(`The text to encrypt (if not piped).

Examples: 

 Plain Text: %s enc "plain text" OR echo "plain text" | %[1]s enc
  Text File: cat file.txt | %[1]s enc > enc.txt
        Raw: cat file.jpg | %[1]s enc -e raw > enc.jpg`, app.Name)).StringVar(&cmd.text)
}

func (c *enc) run(_ *kingpin.ParseContext) error {
	var (
		key []byte
		err error
	)
	if strings.TrimSpace(c.key) != "" {
		if len(c.key) < keySize {
			return errKeyTooSmall
		}
		key = []byte(c.key)
	} else {
		key, err = readKey(c.appName)
		if err != nil {
			return err
		}
	}

	if isInputFromPipe() {
		return encrypt(os.Stdin, key, encoder(c.encMode))
	}
	input := strings.NewReader(c.text)
	return encrypt(input, key, encoder(c.encMode))
}

func encrypt(reader io.Reader, key []byte, encMode encoder) error {
	value, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("Failed to read the input: %w", err)
	}

	if len(bytes.TrimSpace(value)) == 0 {
		return nil
	}

	if len(key) < keySize {
		return errKeyTooSmall
	}
	c, err := aes.NewCipher(key[:keySize])
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

	switch encMode {
	case encoderBase64:
		_, err = os.Stdout.WriteString(base64.URLEncoding.EncodeToString(encrypted))
	case encoderHex:
		_, err = os.Stdout.WriteString(hex.EncodeToString(encrypted))
	case encoderRaw:
		_, err = os.Stdout.Write(encrypted)
	default:
		return fmt.Errorf("Unknown encoder %q", encMode)
	}
	return err
}
