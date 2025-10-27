package auth

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// GetGPGFingerprint retrieves the fingerprint of the default GPG key
func GetGPGFingerprint() (string, error) {
	cmd := exec.Command("gpg", "--list-secret-keys", "--with-colons")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to list GPG keys: %w", err)
	}

	// Parse output to get the fingerprint
	lines := bytes.Split(output, []byte("\n"))
	for _, line := range lines {
		fields := bytes.Split(line, []byte(":"))
		if len(fields) > 0 && string(fields[0]) == "fpr" {
			// Return the first fingerprint found
			return string(fields[9]), nil
		}
	}

	return "", fmt.Errorf("no GPG fingerprint found")
}

// EncryptFile encrypts a file for a specific GPG recipient and returns the encrypted data
func EncryptFile(filePath string, recipientFingerprint string) ([]byte, error) {
	// Read the file
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Encrypt using GPG
	cmd := exec.Command("gpg", "--encrypt", "--recipient", recipientFingerprint, "--trust-model", "always", "--armor")
	cmd.Stdin = bytes.NewReader(fileData)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("GPG encryption failed: %v\nStderr: %s", err, stderr.String())
	}

	return stdout.Bytes(), nil
}

// DecryptData decrypts GPG-encrypted data and writes it to the specified output file
func DecryptData(encryptedData []byte, outputPath string) error {
	// Decrypt using GPG
	cmd := exec.Command("gpg", "--decrypt", "--batch", "--yes")
	cmd.Stdin = bytes.NewReader(encryptedData)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("GPG decryption failed: %v\nStderr: %s", err, stderr.String())
	}

	// Write decrypted data to file
	if err := os.WriteFile(outputPath, stdout.Bytes(), 0600); err != nil {
		return fmt.Errorf("failed to write decrypted file: %w", err)
	}

	return nil
}

// StreamEncryptFile encrypts a file and writes encrypted chunks to a writer
func StreamEncryptFile(filePath string, recipientFingerprint string, writer io.Writer) error {
	encryptedData, err := EncryptFile(filePath, recipientFingerprint)
	if err != nil {
		return err
	}

	_, err = writer.Write(encryptedData)
	return err
}

// StreamDecryptData reads encrypted data from a reader and decrypts it to a file
func StreamDecryptData(reader io.Reader, outputPath string) error {
	// Read all encrypted data
	encryptedData, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read encrypted data: %w", err)
	}

	return DecryptData(encryptedData, outputPath)
}
