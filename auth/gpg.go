package auth

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/libp2p/go-libp2p/core/network"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type GPGHandshake struct {
	isHost            bool
	clientFingerprint string // Stores the client's GPG fingerprint after successful handshake
}

func NewGPGHandshake(isHost bool) *GPGHandshake {
	return &GPGHandshake{
		isHost:            isHost,
		clientFingerprint: "",
	}
}

func (h *GPGHandshake) GetClientFingerprint() string {
	return h.clientFingerprint
}

func getDefaultGPGKey() (string, error) {
	cmd := exec.Command("gpg", "--list-secret-keys", "--keyid-format", "LONG")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to list GPG keys: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "uid") {
			parts := strings.SplitN(line, "]", 2)
			if len(parts) == 2 {
				userID := strings.TrimSpace(parts[1])
				return userID, nil
			}
		}
	}

	return "", fmt.Errorf("no GPG key found")
}

func promptUserAcceptance(gpgUserName string) bool {
	fmt.Printf("\nIncoming connection from GPG user: %s\n", gpgUserName)
	fmt.Print("Accept connection? (y/N): ")

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Failed to read user input: %v\n", err)
		return false
	}

	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

func (h *GPGHandshake) Handshake(s network.Stream) bool {
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	if h.isHost {
		gpgUserName, err := rw.ReadString('\n')
		if err != nil {
			log.Printf("Failed to read GPG user ID from client: %v\n", err)
			return false
		}

		gpgUserName = strings.TrimSpace(gpgUserName)
		if gpgUserName == "" {
			log.Println("Client sent empty GPG user ID")
			return false
		}

		fingerprint, err := rw.ReadString('\n')
		if err != nil {
			log.Printf("Failed to read GPG fingerprint from client: %v\n", err)
			return false
		}

		fingerprint = strings.TrimSpace(fingerprint)
		if fingerprint == "" {
			log.Println("Client sent empty GPG fingerprint")
			return false
		}

		// Read the public key from client
		var publicKeyBuilder strings.Builder
		for {
			line, err := rw.ReadString('\n')
			if err != nil {
				log.Printf("Failed to read public key: %v\n", err)
				return false
			}
			if strings.Contains(line, "<<<END_PUBLIC_KEY>>>") {
				break
			}
			publicKeyBuilder.WriteString(line)
		}
		publicKey := publicKeyBuilder.String()

		// Import the client's public key
		log.Println("Importing client's GPG public key...")
		log.Printf("Public key length: %d bytes\n", len(publicKey))
		log.Printf("First 100 chars: %s\n", publicKey[:min(100, len(publicKey))])

		if err := ImportPublicKey(publicKey); err != nil {
			log.Printf("Failed to import client's public key: %v\n", err)
			return false
		}
		log.Println("Successfully imported client's public key")

		// Verify the key actually exists in the keyring
		exists, err := VerifyKeyExists(fingerprint)
		if err != nil {
			log.Printf("Error verifying key import: %v\n", err)
			return false
		}
		if !exists {
			log.Printf("Key import reported success but key %s not found in keyring!\n", fingerprint)
			return false
		}
		log.Printf("Verified key %s exists in keyring\n", fingerprint)

		h.clientFingerprint = fingerprint

		accepted := promptUserAcceptance(gpgUserName)

		var response string
		if accepted {
			response = "ACCEPTED\n"
			log.Printf("Connection accepted from: %s (fingerprint: %s)\n", gpgUserName, fingerprint)
		} else {
			response = "REJECTED\n"
			log.Printf("Connection rejected from: %s\n", gpgUserName)
		}

		_, err = rw.WriteString(response)
		if err != nil {
			log.Printf("Failed to send response to client: %v\n", err)
			return false
		}
		rw.Flush()

		return accepted
	} else {
		gpgUserID, err := getDefaultGPGKey()
		if err != nil {
			log.Printf("Failed to get default GPG key: %v\n", err)
			return false
		}

		fingerprint, err := GetGPGFingerprint()
		if err != nil {
			log.Printf("Failed to get GPG fingerprint: %v\n", err)
			return false
		}

		log.Printf("Using GPG identity: %s (fingerprint: %s)\n", gpgUserID, fingerprint)

		// Export public key for the host to import
		publicKey, err := ExportPublicKey(fingerprint)
		if err != nil {
			log.Printf("Failed to export public key: %v\n", err)
			return false
		}

		_, err = rw.WriteString(gpgUserID + "\n")
		if err != nil {
			log.Printf("Failed to send GPG user ID: %v\n", err)
			return false
		}

		_, err = rw.WriteString(fingerprint + "\n")
		if err != nil {
			log.Printf("Failed to send GPG fingerprint: %v\n", err)
			return false
		}

		// Send the public key (use a delimiter to mark the end)
		_, err = rw.WriteString(publicKey + "<<<END_PUBLIC_KEY>>>\n")
		if err != nil {
			log.Printf("Failed to send public key: %v\n", err)
			return false
		}
		rw.Flush()

		response, err := rw.ReadString('\n')
		if err != nil {
			log.Printf("Failed to read response from host: %v\n", err)
			return false
		}

		response = strings.TrimSpace(response)
		if response == "ACCEPTED" {
			log.Println("Connection accepted by host")
			return true
		} else {
			log.Printf("Connection rejected by host: %s\n", response)
			return false
		}
	}
}
