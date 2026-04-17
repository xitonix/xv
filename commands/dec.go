package commands

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
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
	verify  bool
}

func setupDecrypt(app *kingpin.Application) {
	cmd := &dec{
		appName: app.Name,
	}

	const cmdName = "dec"
	kCmd := app.Command(cmdName, "Decrypt AES-256 encrypted data").
		Alias("d").
		Action(cmd.run)

	encodings := []string{string(encoderBase64), string(encoderHex), string(encoderRaw)}

	kCmd.Flag(
		"encoding",
		fmt.Sprintf("Encoding of the input data. Must match the encoding used during encryption (%s)", strings.Join(encodings, ","))).
		Short('e').
		Default(string(encoderBase64)).
		EnumVar(&cmd.encMode, encodings...)

	kCmd.Flag(
		"verify",
		"Whether to verify and print the checksum of the input data (enabled by default)").
		Short('v').
		Default("true").
		BoolVar(&cmd.verify)

	kCmd.Flag(
		"key",
		fmt.Sprintf("Decryption key (overrides key file). Must be at least %d characters", keySize)).
		Short('k').
		StringVar(&cmd.key)

	kCmd.Arg("text", fmt.Sprintf(`AES-256 encrypted text to decrypt (if not piped)

Examples: 

 %s %[2]s "encrypted text" 
 echo "encrypted text" | %[1]s %[2]s
 cat encrypted.txt | %[1]s %[2]s > decrypted.txt
 cat encrypted.jpg | %[1]s %[2]s -d raw > decrypted.jpg`, app.Name, cmdName)).StringVar(&cmd.text)
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
	var (
		input   io.Reader = os.Stdin
		encMode           = encoder(c.encMode)
	)
	if !isPiped(os.Stdin) {
		input = strings.NewReader(c.text)
	}

	decoded, decrypted, err := decrypt(input, key, encMode)
	if err != nil {
		return fmt.Errorf("Failed to decrypt data. %w", err)
	}

	if encMode == encoderRaw {
		_, _ = os.Stdout.Write(decrypted)
	} else {
		_, _ = os.Stdout.WriteString(string(decrypted))
	}
	if c.verify {
		printOutput(fmt.Sprintf("%sMD5/%X %s", colourGreen, md5.Sum(decoded), ColourReset))
	}
	return nil
}

func decrypt(reader io.Reader, key []byte, encMode encoder) ([]byte, []byte, error) {
	encrypted, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to read the input. %w", err)
	}

	if len(bytes.TrimSpace(encrypted)) == 0 {
		return nil, nil, nil
	}

	if len(key) < keySize {
		return nil, nil, errKeyTooSmall
	}

	var decoded []byte
	switch encMode {
	case encoderBase64:
		decoded, err = base64.StdEncoding.DecodeString(string(encrypted))
	case encoderHex:
		decoded, err = hex.DecodeString(string(encrypted))
	case encoderRaw:
		decoded = encrypted
	default:
		return nil, nil, fmt.Errorf("Unknown decoder %q", encMode)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("Failed to decode data from %s. %w", encMode, err)
	}

	c, err := aes.NewCipher(key[:keySize])
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create cipher. %w", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create GCM. %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(decoded) < nonceSize {
		return nil, nil, fmt.Errorf("Invalid input encrypted data")
	}

	nonce, ciphertext := decoded[:nonceSize], decoded[nonceSize:]
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to decrypt input. %w", err)
	}

	return decoded, decrypted, nil
}
