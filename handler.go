package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"github.com/Noah-Wilderom/secretshare/auth"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/libp2p/go-libp2p/core/network"
)

// formatFileSize formats bytes into human-readable format
func formatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// promptFileAcceptance prompts the user to accept or reject a file transfer
func promptFileAcceptance(filename string, fileSize int64) bool {
	fmt.Printf("\nIncoming file: %s (%s)\n", filename, formatFileSize(fileSize))
	fmt.Print("Download this file? (y/N): ")

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Failed to read user input: %v\n", err)
		return false
	}

	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

// makeStreamHandler creates a stream handler that performs handshake and file transfer
func makeStreamHandler(handshaker *auth.GPGHandshake, filePath string) network.StreamHandler {
	return func(s network.Stream) {
		log.Println("Got a new stream!")

		// Perform handshake first
		if !handshaker.Handshake(s) {
			log.Printf("Handshake failed with peer %s, rejecting connection\n", s.Conn().RemotePeer())
			s.Reset()
			return
		}

		log.Printf("Handshake successful with peer %s, connection accepted\n", s.Conn().RemotePeer())

		// Get client's GPG fingerprint from handshaker
		clientFingerprint := handshaker.GetClientFingerprint()
		if clientFingerprint == "" {
			log.Println("Error: No client fingerprint available")
			s.Reset()
			return
		}

		// Send file to client
		if err := sendFile(s, filePath, clientFingerprint); err != nil {
			log.Printf("Error sending file: %v\n", err)
			s.Reset()
			return
		}

		log.Println("File transfer completed successfully")
		s.Close()
	}
}

// sendFile encrypts and sends a file to the client
func sendFile(s network.Stream, filePath string, recipientFingerprint string) error {
	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	fileName := filepath.Base(filePath)
	fileSize := fileInfo.Size()

	log.Printf("Preparing to send file: %s (%s)\n", fileName, formatFileSize(fileSize))

	// Encrypt the file
	log.Println("Encrypting file with client's GPG key...")
	encryptedData, err := auth.EncryptFile(filePath, recipientFingerprint)
	if err != nil {
		return fmt.Errorf("failed to encrypt file: %w", err)
	}

	encryptedSize := int64(len(encryptedData))
	log.Printf("Encrypted file size: %s\n", formatFileSize(encryptedSize))

	// Create buffered reader/writer
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	// Send file metadata: filename, original size, encrypted size
	metadata := fmt.Sprintf("%s|%d|%d\n", fileName, fileSize, encryptedSize)
	if _, err := rw.WriteString(metadata); err != nil {
		return fmt.Errorf("failed to send metadata: %w", err)
	}
	rw.Flush()

	log.Println("Sent file metadata, waiting for client response...")

	// Wait for client's acceptance
	response, err := rw.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read client response: %w", err)
	}

	response = strings.TrimSpace(response)
	if response != "ACCEPT" {
		log.Println("Client rejected the file transfer")
		return fmt.Errorf("client rejected file transfer")
	}

	log.Println("Client accepted, sending encrypted file...")

	// Send encrypted data (base64 encoded for safe transmission)
	encodedData := base64.StdEncoding.EncodeToString(encryptedData)
	if _, err := rw.WriteString(encodedData + "\n"); err != nil {
		return fmt.Errorf("failed to send encrypted file: %w", err)
	}
	rw.Flush()

	log.Println("File sent successfully")
	return nil
}

// receiveFile receives and decrypts a file from the host
func receiveFile(rw *bufio.ReadWriter) error {
	// Read file metadata
	metadata, err := rw.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	metadata = strings.TrimSpace(metadata)
	parts := strings.Split(metadata, "|")
	if len(parts) != 3 {
		return fmt.Errorf("invalid metadata format")
	}

	fileName := parts[0]
	originalSize, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid file size: %w", err)
	}

	// Prompt user to accept file
	if !promptFileAcceptance(fileName, originalSize) {
		rw.WriteString("REJECT\n")
		rw.Flush()
		log.Println("File transfer rejected by user")
		return fmt.Errorf("file transfer rejected")
	}

	// Send acceptance
	rw.WriteString("ACCEPT\n")
	rw.Flush()

	log.Println("Receiving encrypted file...")

	// Receive encrypted data
	encodedData, err := rw.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to receive encrypted file: %w", err)
	}

	encodedData = strings.TrimSpace(encodedData)
	encryptedData, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return fmt.Errorf("failed to decode encrypted file: %w", err)
	}

	log.Printf("Received %s of encrypted data, decrypting...\n", formatFileSize(int64(len(encryptedData))))

	// Decrypt and save file
	outputPath := filepath.Join(".", fileName)
	if err := auth.DecryptData(encryptedData, outputPath); err != nil {
		return fmt.Errorf("failed to decrypt file: %w", err)
	}

	log.Printf("File saved successfully to: %s\n", outputPath)
	return nil
}
