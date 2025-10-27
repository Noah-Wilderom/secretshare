package auth

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
)

func GetGPGFingerprint() (string, error) {
	cmd := exec.Command("gpg", "--list-secret-keys", "--with-colons")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to list GPG keys: %w", err)
	}

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

// ExportPublicKey exports the public key for a given fingerprint in ASCII armor format
func ExportPublicKey(fingerprint string) (string, error) {
	cmd := exec.Command("gpg", "--armor", "--export", fingerprint)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to export public key: %w", err)
	}
	return string(output), nil
}

// ImportPublicKey imports a public key into the GPG keyring
func ImportPublicKey(publicKey string) error {
	cmd := exec.Command("gpg", "--import", "--batch")
	cmd.Stdin = bytes.NewReader([]byte(publicKey))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to import public key: %v\nStderr: %s\nStdout: %s", err, stderr.String(), stdout.String())
	}

	// Log what GPG said about the import
	fmt.Printf("GPG import output:\nStderr: %s\nStdout: %s\n", stderr.String(), stdout.String())
	return nil
}

// VerifyKeyExists checks if a key with the given fingerprint exists in the keyring
func VerifyKeyExists(fingerprint string) (bool, error) {
	cmd := exec.Command("gpg", "--list-keys", "--with-colons", fingerprint)
	output, err := cmd.Output()
	if err != nil {
		return false, nil // Key doesn't exist
	}

	// Check if the output contains the fingerprint
	lines := bytes.Split(output, []byte("\n"))
	for _, line := range lines {
		fields := bytes.Split(line, []byte(":"))
		if len(fields) > 0 && string(fields[0]) == "fpr" {
			if string(fields[9]) == fingerprint {
				return true, nil
			}
		}
	}

	return false, nil
}

func EncryptFile(filePath string, recipientFingerprint string) ([]byte, error) {
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

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

func DecryptData(encryptedData []byte, outputPath string) error {
	cmd := exec.Command("gpg", "--decrypt", "--batch", "--yes")
	cmd.Stdin = bytes.NewReader(encryptedData)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("GPG decryption failed: %v\nStderr: %s", err, stderr.String())
	}

	if err := os.WriteFile(outputPath, stdout.Bytes(), 0600); err != nil {
		return fmt.Errorf("failed to write decrypted file: %w", err)
	}

	return nil
}

func StreamEncryptFile(filePath string, recipientFingerprint string, writer io.Writer) error {
	encryptedData, err := EncryptFile(filePath, recipientFingerprint)
	if err != nil {
		return err
	}

	_, err = writer.Write(encryptedData)
	return err
}

func StreamDecryptData(reader io.Reader, outputPath string) error {
	encryptedData, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read encrypted data: %w", err)
	}

	return DecryptData(encryptedData, outputPath)
}
