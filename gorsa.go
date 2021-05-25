package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}
	return privateKey, &privateKey.PublicKey
}

func RsaPrivateKeyToPem(privateKey *rsa.PrivateKey) []byte {
	bytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: bytes,
		},
	)
	return pem
}

func RsaPrivateKeyFromPem(privPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func RsaPublicKeyToPem(pubkey *rsa.PublicKey) ([]byte, error) {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return nil, err
	}
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)

	return pubkey_pem, nil
}

func RsaPublicKeyFromPem(pubPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("key type is not RSA")
}

func RsaEncrypt(source []byte, publicKey rsa.PublicKey) ([]byte, error) {
	srcLen := len(source)
	hash := sha256.New()
	rnd := rand.Reader
	step := publicKey.Size() - 2*hash.Size() - 2

	var result []byte

	for start := 0; start < srcLen; start += step {
		finish := start + step
		if finish > srcLen {
			finish = srcLen
		}

		encryptedBlockBytes, err := rsa.EncryptOAEP(hash, rnd, &publicKey, source[start:finish], []byte("OAEP Encrypted"))
		if err != nil {
			return nil, err
		}

		result = append(result, encryptedBlockBytes...)
	}

	return result, nil
}

func RsaDecrypt(msg []byte, privateKey rsa.PrivateKey) ([]byte, error) {
	msgLen := len(msg)
	hash := sha256.New()
	rnd := rand.Reader
	step := privateKey.PublicKey.Size()

	var result []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		decryptedBlockBytes, err := rsa.DecryptOAEP(hash, rnd, &privateKey, msg[start:finish], []byte("OAEP Encrypted"))
		if err != nil {
			return nil, err
		}

		result = append(result, decryptedBlockBytes...)
	}

	return result, nil
}

func CheckFile(filePath string) bool {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	}
	return true
}

func CopyFile(source string, dest string) error {
	content, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	err = os.WriteFile(dest, content, 0644)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	homePath, _ := os.UserHomeDir()
	septPath := filepath.Join(homePath, ".september")
	publicPath := filepath.Join(septPath, "key.pbsk")
	privatePath := filepath.Join(septPath, "key.pvsk")

	if !CheckFile(septPath) {
		os.Mkdir(septPath, 0644)
	}
	args := os.Args[1:]

	if len(args) == 0 || (len(args) == 1 && args[0] == "help") {
		fmt.Println("Usage:")
		fmt.Println("genpair [filename] - Create RSA key pair")
		fmt.Println("setpbsk [filename] - Set public RSA key from file")
		fmt.Println("setpvsk [filename] - Set private RSA key from file")
		fmt.Println("encrypt [filename] - Encrypt file with temporary public RSA key")
		fmt.Println("decrypt [filename] - Decrypt file with temporary private RSA key")
		return
	}

	if args[0] == "genpair" {
		if len(args) != 2 {
			fmt.Println("Usage:")
			fmt.Println("genpair [filename] - Create RSA key pair")
			fmt.Println("* filename - .pbsk and .pvsk files name")
			return
		}

		privateKey, publicKey := GenerateRsaKeyPair()

		privatePem := RsaPrivateKeyToPem(privateKey)
		publicPem, _ := RsaPublicKeyToPem(publicKey)

		os.WriteFile(args[1]+".pvsk", privatePem, 0644)
		os.WriteFile(args[1]+".pbsk", publicPem, 0644)

		fmt.Printf("The RSA keys were written to %v.pvsk and %v.pbsk\n", args[1], args[1])
		return
	}
	if args[0] == "setpbsk" {
		if len(args) != 2 {
			fmt.Println("Usage:")
			fmt.Println("setpbsk [filename] - Set public RSA key from file")
			fmt.Println("* filename - *.pbsk file name")
			return
		}
		if !CheckFile(args[1]) {
			fmt.Printf("* File %v doesn't exist\n", args[1])
			return
		}
		err := CopyFile(args[1], filepath.Join(septPath, "key.pbsk"))
		if err != nil {
			fmt.Println("* Unable to set public RSA key")
			return
		}

		fmt.Println("The key was successfully set")
		return
	}
	if args[0] == "setpvsk" {
		if len(args) != 2 {
			fmt.Println("Usage:")
			fmt.Println("setpvsk [filename] - Set private RSA key from file")
			fmt.Println("* filename - *.pvsk file name")
			return
		}
		if !CheckFile(args[1]) {
			fmt.Printf("* File %v doesn't exist\n", args[1])
			return
		}
		err := CopyFile(args[1], filepath.Join(septPath, "key.pvsk"))
		if err != nil {
			fmt.Println("* Unable to set private RSA key")
			return
		}

		fmt.Println("The key was successfully set")
		return
	}
	if args[0] == "encrypt" {
		if len(args) != 2 {
			fmt.Println("Usage:")
			fmt.Println("encrypt [filename] - Encrypt file with temporary public RSA key")
			fmt.Println("* filename - file name to encrypt")
			return
		}
		if !CheckFile(args[1]) {
			fmt.Printf("* File %v doesn't exist\n", args[1])
			return
		}
		if !CheckFile(publicPath) {
			fmt.Printf("* Public RSA key is not set")
			return
		}

		publicBytes, err := os.ReadFile(publicPath)
		if err != nil {
			panic(err)
		}

		publicKey, err := RsaPublicKeyFromPem(publicBytes)
		if err != nil {
			fmt.Println("* Unable to read public RSA key")
			return
		}

		file, err := os.ReadFile(args[1])
		if err != nil {
			panic(err)
		}

		result, err := RsaEncrypt(file, *publicKey)
		if err != nil {
			fmt.Println("* Unable to encrypt file")
			return
		}

		err = os.WriteFile(args[1]+".sept", result, 0644)
		if err != nil {
			panic(err)
		}

		fmt.Printf("File %v was encrypted (%v.sept)\n", args[1], args[1])
		return
	}
	if args[0] == "decrypt" {
		if len(args) != 2 {
			fmt.Println("Usage:")
			fmt.Println("encrypt [filename] - Decrypt file with temporary private RSA key")
			fmt.Println("* filename - file name to decrypt")
			return
		}
		if !CheckFile(args[1]) {
			fmt.Printf("* File %v doesn't exist\n", args[1])
			return
		}
		if !CheckFile(privatePath) {
			fmt.Printf("* Private RSA key is not set")
			return
		}

		privateBytes, err := os.ReadFile(privatePath)
		if err != nil {
			panic(err)
		}

		privateKey, err := RsaPrivateKeyFromPem(privateBytes)
		if err != nil {
			fmt.Println("* Unable to read private RSA key")
			return
		}

		file, err := os.ReadFile(args[1])
		if err != nil {
			panic(err)
		}

		result, err := RsaDecrypt(file, *privateKey)
		if err != nil {
			fmt.Println("* Unable to decrypt file")
			return
		}

		parts := strings.Split(args[1], ".")
		newPath := strings.Join(parts[:len(parts)-1], ".")

		err = os.WriteFile(newPath, result, 0644)
		if err != nil {
			panic(err)
		}

		fmt.Printf("File %v was decrypted (%v)\n", args[1], newPath)
		return
	}
	fmt.Println("* Unknown command, use: gorsa help")
}
