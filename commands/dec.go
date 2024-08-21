package commands

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/alecthomas/kingpin/v2"
)

type dec struct {
	encMode string
	text    string
	key     string
	appName string
}

func setupDecrypt(app *kingpin.Application) {
	cmd := &dec{
		appName: app.Name,
	}
	const cmdName = "dec"
	kCmd := app.Command(cmdName, `Decrypts AES-256 encrypted data`).Alias("d").Action(cmd.run)
	kCmd.Flag("encoder", "Specifies how the encrypted data was encoded. It MUST be the same encoder which was used for encryption").
		Short('e').
		Default(string(encoderBase64)).
		EnumVar(&cmd.encMode, string(encoderBase64), string(encoderHex), string(encoderRaw))
	kCmd.Flag("key", fmt.Sprintf("The key to be used for decryption (instead of the key file). It MUST be at least %d characters.", keySize)).
		Short('k').
		StringVar(&cmd.key)
	kCmd.Arg("text", fmt.Sprintf(`AES-256 encrypted text to decrypt (if not piped).

Examples: 

 %s %[2]s "encrypted text" 
 echo "encrypted text" | %[1]s %[2]s
 cat encrypted.txt | %[1]s %[2]s > decrypted.txt
 cat encrypted.jpg | %[1]s %[2]s -e raw > decrypted.jpg`, app.Name, cmdName)).StringVar(&cmd.text)
}

func (c *dec) run(_ *kingpin.ParseContext) error {
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
		return decrypt(os.Stdin, key, encoder(c.encMode))
	}
	input := strings.NewReader(c.text)
	return decrypt(input, key, encoder(c.encMode))
}

func decrypt(reader io.Reader, key []byte, encMode encoder) error {
	encrypted, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("Failed to read the input: %w", err)
	}

	if len(bytes.TrimSpace(encrypted)) == 0 {
		return nil
	}

	if len(key) < keySize {
		return errKeyTooSmall
	}

	switch encMode {
	case encoderBase64:
		encrypted, err = base64.StdEncoding.DecodeString(string(encrypted))
	case encoderHex:
		encrypted, err = hex.DecodeString(string(encrypted))
	case encoderRaw:
	default:
		return fmt.Errorf("Unknown encoder %q", encMode)
	}

	if err != nil {
		return fmt.Errorf("Failed to decode data from %s: %w", encMode, err)
	}

	c, err := aes.NewCipher(key[:keySize])
	if err != nil {
		return fmt.Errorf("Failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return fmt.Errorf("Failed to create GCM: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return fmt.Errorf("Invalid input encrypted data")
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("Failed to decrypt input: %w", err)
	}
	if encMode == encoderRaw {
		_, err = os.Stdout.Write(decrypted)
	} else {
		_, err = os.Stdout.WriteString(string(decrypted))
	}
	if err != nil {
		return fmt.Errorf("Failed to write decrypted data: %w", err)
	}
	return nil
}
