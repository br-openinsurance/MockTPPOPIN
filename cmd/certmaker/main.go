package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

const (
	keysDir = "/app/keys"
)

// Custom certificate fields.
var (
	oidLDAPUID        = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
	oidX500UID        = asn1.ObjectIdentifier{2, 5, 4, 45}
	oidOrganizationID = asn1.ObjectIdentifier{2, 5, 4, 97}
)

func main() {

	orgID := flag.String("org_id", uuid.NewString(), "Organization ID")
	flag.Parse()

	caCert, caKey := generateCACert("ca", keysDir)

	_, _ = generateCert("server", *orgID, caCert, caKey, keysDir)
}

// Generates a Certificate Authority (CA) key and self-signed certificate.
func generateCACert(name, dir string) (*x509.Certificate, *rsa.PrivateKey) {
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	return generateSelfSignedCert(name, caTemplate, keysDir)
}

func generateSelfSignedCert(name string, template *x509.Certificate, dir string) (*x509.Certificate, *rsa.PrivateKey) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate CA private key: %v", err)
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&key.PublicKey,
		key,
	)
	if err != nil {
		log.Fatalf("Failed to create CA certificate: %v", err)
	}
	// This is important for when generation the claim "x5c" of the JWK
	// corresponding to this cert.
	template.Raw = certBytes

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatalf("Failed to create CA key: %v", err)
	}
	savePEMFile(filepath.Join(dir, name+".key"), "PRIVATE KEY", keyBytes)
	savePEMFile(filepath.Join(dir, name+".crt"), "CERTIFICATE", certBytes)

	fmt.Printf("Generated self signed certificate and key for %s\n", name)
	return template, key
}

// Generates a certificate signed by the CA.
func generateCert(name, orgID string, caCert *x509.Certificate, caKey *rsa.PrivateKey, dir string) (*x509.Certificate, *rsa.PrivateKey) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: name,
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  oidX500UID,
					Value: name,
				},
				{
					Type:  oidLDAPUID,
					Value: uuid.NewString(),
				},
				{
					Type:  oidOrganizationID,
					Value: orgID,
				},
			},
		},
		DNSNames: []string{
			"mocktpp.local",
			"directory.local",
		},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Create client certificate signed by the CA.
	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		cert,
		caCert,
		&key.PublicKey,
		caKey,
	)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}
	// This is important for when generation the claim "x5c" of the JWK
	// corresponding to this cert.
	cert.Raw = certBytes

	// Save private key and certificate.
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatalf("Failed to create key: %v", err)
	}
	savePEMFile(filepath.Join(dir, name+".key"), "PRIVATE KEY", keyBytes)
	savePEMFile(filepath.Join(dir, name+".crt"), "CERTIFICATE", certBytes)

	fmt.Printf("Generated key and certificate for %s\n", name)
	return cert, key
}

// Saves data to a PEM file.
func savePEMFile(filename, blockType string, data []byte) {
	file, err := os.Create(filename) //nolint:gosec
	if err != nil {
		log.Fatalf("Failed to create %s: %v", filename, err)
	}
	defer file.Close() //nolint:errcheck

	err = pem.Encode(file, &pem.Block{Type: blockType, Bytes: data})
	if err != nil {
		log.Fatalf("Failed to write PEM data to %s: %v", filename, err)
	}
}
