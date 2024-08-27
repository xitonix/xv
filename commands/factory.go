package commands

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/alecthomas/kingpin/v2"
)

const (
	keySize = 32
)

const (
	EmojiFail    = "\u274C"
	emojiSuccess = "\u2705"
	emojiWarn    = "\u26a0\ufe0f"
	colourGreen  = "\u001B[32m"
	colourYellow = "\u001B[33m"
	ColourRed    = "\u001B[31m"
	ColourReset  = "\u001B[0m"
)

type encoder string

const (
	encoderBase64 encoder = "b64"
	encoderHex    encoder = "hex"
	encoderRaw    encoder = "raw"
)

var errKeyTooSmall = fmt.Errorf("The encryption key must be at least %d bytes", keySize)

func SetupAll(app *kingpin.Application) {
	setupKey(app)
	setupEncrypt(app)
	setupDecrypt(app)
}

func readKey(appName string) ([]byte, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("Failed to get home directory. %w", err)
	}
	path := filepath.Join(home, "."+appName)
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("Key file does not exist. Run `%s init <Minimum of 32 bytes encryption key>` to initialise a new key file", appName)
		}
		return nil, fmt.Errorf("Failed to open key file. %w", err)
	}
	defer func() {
		if err = file.Close(); err != nil {
			log.Printf("Failed to close key file: %v", err)
		}
	}()
	key, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("Failed to read key file. %w", err)
	}
	return key[:keySize], nil
}

func isPiped(file *os.File) bool {
	fileInfo, _ := file.Stat()
	return fileInfo.Mode()&os.ModeCharDevice == 0
}

func printOutput(msg string) {
	if !isPiped(os.Stdout) {
		msg = "\n" + msg
	}
	_, _ = os.Stderr.WriteString(msg + "\n")
}
