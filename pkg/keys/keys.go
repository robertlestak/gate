package keys

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
)

func BytesToPubKey(publicKey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return pub, nil
}

func BytesToPrivateKey(privateKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// try PKCS8
		privInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		priv = privInterface.(*rsa.PrivateKey)
	}
	return priv, nil
}

func HashSumMessage(msg []byte) []byte {
	h := sha256.New()
	h.Write(msg)
	return h.Sum(nil)
}

func Verify(msg, sig, pubKey []byte) error {
	l := log.WithFields(log.Fields{
		"fn": "Verify",
	})
	l.Debug("Verifying message")
	pub, err := BytesToPubKey(pubKey)
	if err != nil {
		l.WithError(err).Error("Failed to get public key")
		return err
	}
	hs := HashSumMessage(msg)
	l.Debug("Verifying signature")
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hs, sig)
}

func Sign(msg []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hs := HashSumMessage(msg)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hs)
}

func PrivateKeyToPublicPem(key *rsa.PrivateKey) ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		fmt.Printf("error when dumping publickey: %s \n", err)
		os.Exit(1)
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicKeyPem := pem.EncodeToMemory(publicKeyBlock)
	return publicKeyPem, nil
}

func Encrypt(d []byte, k *rsa.PublicKey) ([]byte, error) {
	l := log.WithFields(log.Fields{
		"fn": "Encrypt",
	})
	l.Debug("Encrypting data")
	encrypted, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		k,
		d,
		nil)
	if err != nil {
		l.WithError(err).Error("Failed to encrypt data")
		return nil, err
	}
	return encrypted, nil
}

func Decrypt(d []byte, k *rsa.PrivateKey) ([]byte, error) {
	l := log.WithFields(log.Fields{
		"fn": "Decrypt",
	})
	l.Debug("Decrypting data")
	decrypted, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		k,
		d,
		nil)
	if err != nil {
		l.WithError(err).Error("Failed to decrypt data")
		return nil, err
	}
	return decrypted, nil
}
