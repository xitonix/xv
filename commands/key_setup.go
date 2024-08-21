package commands

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kingpin/v2"
)

type initKey struct {
	key     string
	appName string
}

func setupInitKey(app *kingpin.Application) {
	cmd := &initKey{
		appName: app.Name,
	}
	kCmd := app.Command("init", fmt.Sprintf(`Initialises a new key file (eg. %s init <Encryption Key>)`, app.Name)).Action(cmd.run)
	kCmd.Arg("key", fmt.Sprintf("Encryption key (Minimum length: %d)", keySize)).
		Required().
		StringVar(&cmd.key)
}

func (c *initKey) run(_ *kingpin.ParseContext) error {
	key := strings.TrimSpace(c.key)
	if len(key) < keySize {
		return errKeyTooSmall
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("Failed to get home directory. %w", err)
	}
	path := filepath.Join(home, "."+c.appName)
	if _, err = os.Stat(path); err == nil {
		if !askForConfirmation(fmt.Sprintf("The key file '%s' already exists. Overwrite", path)) {
			return nil
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("Failed to create the key file %s. %w", path, err)
	}
	defer func() {
		if err = f.Close(); err != nil {
			log.Printf("Failed to close key file: %v", err)
		}
	}()
	if _, err = f.WriteString(key); err != nil {
		return fmt.Errorf("Failed to write key file %s. %w", path, err)
	}
	fmt.Printf("The key file %s has been created successfully", path)

	return nil
}

func askForConfirmation(question string) bool {
	scanner := bufio.NewScanner(os.Stdin)
	msg := fmt.Sprintf("%s [y/n]?: ", question)
	for fmt.Print(msg); scanner.Scan(); fmt.Print(msg) {
		r := strings.ToLower(strings.TrimSpace(scanner.Text()))
		switch r {
		case "y", "yes":
			return true
		case "n", "no", "q", "quit", "exit":
			return false
		}
	}
	return false
}
