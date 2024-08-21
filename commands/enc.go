package commands

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
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
	verify  bool
}

func setupEncrypt(app *kingpin.Application) {
	const cmdName = "enc"
	cmd := &enc{
		appName: app.Name,
	}
	kCmd := app.Command(cmdName, `Encrypts data using AES-256 algorithm (Default command if not specified)`).Alias("e").Default().Action(cmd.run)

	kCmd.Flag("encoder", "Specifies how the encrypted data must be encoded. Same decoder must be used for decryption").
		Short('e').
		Default(string(encoderBase64)).
		EnumVar(&cmd.encMode, string(encoderBase64), string(encoderHex), string(encoderRaw))

	kCmd.Flag("verify", "Verifies the encrypted data and prints the checksum (Enabled by default)").
		Short('v').
		Default("true").
		BoolVar(&cmd.verify)

	kCmd.Flag("key", fmt.Sprintf("The key to be used for encryption (instead of the key file). It MUST be at least %d characters", keySize)).
		Short('k').
		StringVar(&cmd.key)

	kCmd.Arg("text", fmt.Sprintf(`The text to encrypt (if not piped)

Examples: 

 %s [%s] "plain text"
 echo "plain text" | %[1]s [%[2]s]
 %[1]s [%[2]s] "plain text"
 echo "plain text" | %[1]s [%[2]s]
 cat file.txt | %[1]s [%[2]s] > enc.txt
 cat file.jpg | %[1]s [%[2]s] -e raw > enc.jpg`, app.Name, cmdName)).StringVar(&cmd.text)
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

	if isPiped(os.Stdin) {
		return encrypt(os.Stdin, key, encoder(c.encMode), c.verify)
	}
	input := strings.NewReader(c.text)
	return encrypt(input, key, encoder(c.encMode), c.verify)
}

func encrypt(reader io.Reader, key []byte, encMode encoder, verify bool) error {
	value, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("Failed to read the input. %w", err)
	}

	if len(bytes.TrimSpace(value)) == 0 {
		return nil
	}

	if len(key) < keySize {
		return errKeyTooSmall
	}
	c, err := aes.NewCipher(key[:keySize])
	if err != nil {
		return fmt.Errorf("Failed to create cipher. %w", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return fmt.Errorf("Failed to create GCM. %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("Failed to create nonce. %w", err)
	}
	encrypted := gcm.Seal(nonce, nonce, value, nil)
	var encBuffer *bytes.Buffer
	switch encMode {
	case encoderBase64:
		encoded := base64.StdEncoding.EncodeToString(encrypted)
		if _, err = os.Stdout.WriteString(encoded); err == nil && verify {
			encBuffer = bytes.NewBuffer([]byte(encoded))
		}
	case encoderHex:
		encoded := hex.EncodeToString(encrypted)
		if _, err = os.Stdout.WriteString(encoded); err == nil && verify {
			encBuffer = bytes.NewBuffer([]byte(encoded))
		}
	case encoderRaw:
		if _, err = os.Stdout.Write(encrypted); err == nil && verify {
			encBuffer = bytes.NewBuffer(encrypted)
		}
	default:
		return fmt.Errorf("Unknown encoder %q", encMode)
	}
	if err != nil {
		return fmt.Errorf("Failed to encrypt data. %w", err)
	}
	if verify {
		_, decrypted, err := decrypt(encBuffer, key, encMode)
		if err != nil {
			return fmt.Errorf("Failed to verify data. %w", err)
		} else {
			if bytes.Equal(value, decrypted) {
				printOutput(fmt.Sprintf("%s %sMD5/%X %s", emojiSuccess, green, md5.Sum(encrypted), ColourReset))
			} else {
				printOutput(fmt.Sprintf("%s %sVERIFICATION FAILED %s", EmojiFail, ColourRed, ColourReset))
			}
		}
	}
	return nil
}
