package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/bintalk/bintalk-clone/internal/handlers"
	"github.com/bintalk/bintalk-clone/internal/services"
	"github.com/bintalk/bintalk-clone/migrations"
	"github.com/bintalk/bintalk-clone/pkg/db"
	"github.com/bintalk/bintalk-clone/pkg/mail"
	"github.com/bintalk/bintalk-clone/pkg/vault"
)

// runRotateKeys implements `api-server rotate-keys`:
//  1. rotates the Vault Transit key that wraps the data keys (Vault keeps the old version),
//  2. re-wraps every stored data key with the new Transit version,
//  3. creates a new data key version for new messages and files.
//
// Existing data stays readable: it is decrypted with the data key version it was encrypted with.
// Running API servers pick up the new active version within a minute.
func runRotateKeys() {
	cfg := loadConfig()
	vaultClient, err := vault.NewVaultClient(&vault.VaultConfig{Address: cfg.Vault.Address, Token: cfg.Vault.Token}, logger)
	if err != nil {
		logger.Fatalf("Failed to connect to Vault: %v", err)
	}
	database := db.NewPostgres(cfg.Database)
	defer database.Close()
	if _, err := migrations.Apply(database); err != nil {
		logger.Fatalf("Failed to apply database migrations: %v", err)
	}
	encryption := services.NewEncryptionService(vaultClient, database, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := vaultClient.TransitRotate(ctx, services.DataTransitKey); err != nil {
		logger.Fatalf("Failed to rotate Vault Transit key: %v", err)
	}
	transitVersion, _ := vaultClient.TransitKeyVersion(ctx, services.DataTransitKey)
	rewrapped, err := encryption.RewrapDataKeys(ctx)
	if err != nil {
		logger.Fatalf("Failed to re-wrap data keys: %v", err)
	}
	version, err := encryption.RotateDataKey(ctx)
	if err != nil {
		logger.Fatalf("Failed to create a new data key: %v", err)
	}

	fmt.Printf("Vault Transit key %q is now at version %d\n", services.DataTransitKey, transitVersion)
	fmt.Printf("Re-wrapped %d existing data key(s) with the new Transit version\n", rewrapped)
	fmt.Printf("Data key version %d is now active for new data; older versions remain available for decryption\n", version)
}

// runMakeAdmin implements `api-server make-admin <email>`: gives an existing account the admin role.
func runMakeAdmin(email string) {
	cfg := loadConfig()
	database := db.NewPostgres(cfg.Database)
	defer database.Close()
	if _, err := migrations.Apply(database); err != nil {
		logger.Fatalf("Failed to apply database migrations: %v", err)
	}
	if err := handlers.PromoteToAdmin(context.Background(), &handlers.Dependencies{DB: database, Logger: logger}, email); err != nil {
		logger.Fatalf("Failed to make %s an admin: %v", email, err)
	}
	fmt.Printf("%s is now an admin\n", email)
}

// runSendTestEmail implements `api-server send-test-email <address>`: sends one email with the
// current SMTP settings and prints the exact error if delivery fails.
func runSendTestEmail(to string) {
	cfg := loadConfig()
	mailer := mail.New(cfg.Email)
	status := mailer.Status()
	fmt.Printf("Sending a test email to %s via %s:%s (from %s)...\n", to, status.Host, status.Port, status.From)
	switch status.Kind {
	case "mailpit":
		fmt.Println("Note: this server is Mailpit, which catches email locally (http://localhost:8025); it will not reach a real inbox.")
	case "local":
		fmt.Println("Note: the local mail server queues the email and delivers it in the background.")
		fmt.Println("      See the recipient server's verdict with:  docker logs bintalk_postfix 2>&1 | grep status=")
	}
	err := mailer.Send(to, "BinTalk test email",
		"This is a test email from BinTalk.\n\nIf you can read this, password reset emails will be delivered.\n")
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		os.Exit(1)
	}
	if status.Kind == "local" {
		fmt.Println("Accepted by the local mail server. Check the inbox (and spam folder) and the log above.")
	} else {
		fmt.Println("Sent. Check the inbox (and the spam folder).")
	}
}

const commandUsage = `Usage: api-server [command]

Without a command, runs the API server.

Commands:
  rotate-keys               rotate the Vault Transit key and create a new data key version
                            (existing messages and files stay readable)
  make-admin <email>        give an existing account the admin role
  send-test-email <email>   send a test email with the current SMTP settings
`

// runCommand dispatches CLI commands. Unknown commands or extra arguments print usage and do
// nothing, so a typo can never trigger an action such as a key rotation.
func runCommand(args []string) {
	switch {
	case len(args) == 1 && args[0] == "rotate-keys":
		runRotateKeys()
	case len(args) == 2 && args[0] == "make-admin":
		runMakeAdmin(args[1])
	case len(args) == 2 && args[0] == "send-test-email":
		runSendTestEmail(args[1])
	default:
		fmt.Print(commandUsage)
		if len(args) != 1 || (args[0] != "-h" && args[0] != "--help" && args[0] != "help") {
			os.Exit(2)
		}
	}
}
