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

type GPGHandshake struct {
	isHost             bool
	clientFingerprint  string // Stores the client's GPG fingerprint after successful handshake
}

// NewGPGHandshake creates a new GPG handshaker
// - isHost: true if this peer is the host (verifier), false if client (prover)
func NewGPGHandshake(isHost bool) *GPGHandshake {
	return &GPGHandshake{
		isHost:            isHost,
		clientFingerprint: "",
	}
}

// GetClientFingerprint returns the client's GPG fingerprint (only valid on host after successful handshake)
func (h *GPGHandshake) GetClientFingerprint() string {
	return h.clientFingerprint
}

// getDefaultGPGKey retrieves the default GPG key user ID
func getDefaultGPGKey() (string, error) {
	cmd := exec.Command("gpg", "--list-secret-keys", "--keyid-format", "LONG")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to list GPG keys: %w", err)
	}

	// Parse output to get the first user ID
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "uid") {
			// Extract user ID from line like "uid [ultimate] John Doe <john@example.com>"
			parts := strings.SplitN(line, "]", 2)
			if len(parts) == 2 {
				userID := strings.TrimSpace(parts[1])
				return userID, nil
			}
		}
	}

	return "", fmt.Errorf("no GPG key found")
}

// promptUserAcceptance prompts the user to accept or reject a connection
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

// Handshake performs the GPG-based authentication handshake
func (h *GPGHandshake) Handshake(s network.Stream) bool {
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	if h.isHost {
		// Host mode: receive client's GPG user ID and fingerprint, then prompt for acceptance
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

		// Read client's GPG fingerprint
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

		// Store the client's fingerprint for later use
		h.clientFingerprint = fingerprint

		// Prompt user to accept or reject
		accepted := promptUserAcceptance(gpgUserName)

		// Send response back to client
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
		// Client mode: send GPG user ID and fingerprint to host
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

		// Send GPG user ID to host
		_, err = rw.WriteString(gpgUserID + "\n")
		if err != nil {
			log.Printf("Failed to send GPG user ID: %v\n", err)
			return false
		}

		// Send GPG fingerprint to host
		_, err = rw.WriteString(fingerprint + "\n")
		if err != nil {
			log.Printf("Failed to send GPG fingerprint: %v\n", err)
			return false
		}
		rw.Flush()

		// Wait for host's response
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
