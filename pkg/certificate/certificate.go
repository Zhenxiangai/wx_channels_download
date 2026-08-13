package certificate

import (
	"bytes"
	"fmt"
	"os"
	"time"
)

type CertFileAndKeyFile struct {
	Name       string
	Cert       []byte
	PrivateKey []byte
}

var DefaultCertFiles = generateDefaultCertFiles()

func generateDefaultCertFiles() *CertFileAndKeyFile {
	name := fmt.Sprintf("wx_channels_download_ephemeral_%d", os.Getpid())
	cert, key, err := GenerateRootCA(name, 24*time.Hour)
	if err != nil {
		panic("generate ephemeral root certificate: " + err.Error())
	}
	return &CertFileAndKeyFile{
		Name:       name,
		Cert:       cert,
		PrivateKey: key,
	}
}

type CertificateSubject struct {
	// label
	CN string
	// cenc
	OU string
	// hpky
	O string
	// hpky
	L string
	// subj
	S string
	// cenc
	C string
}
type Certificate struct {
	Thumbprint string
	Subject    CertificateSubject
}

// Fetch all certificates
func FetchCertificates() ([]Certificate, error) {
	return fetchCertificates()
}

// Check if a certificate with the given name exists
func CheckHasCertificate(cert_name string) (bool, error) {
	certificates, err := fetchCertificates()
	if err != nil {
		return false, err
	}
	for _, cert := range certificates {
		if cert.Subject.CN == cert_name {
			return true, nil
		}
	}
	return false, nil
}

// Check if a certificate with the given name is trusted by the system
func CheckCertificateTrusted(cert_name string) (bool, error) {
	return checkCertificateTrusted(cert_name)
}

// Install a certificate
func InstallCertificate(cert_data []byte) error {
	if DefaultCertFiles != nil && bytes.Equal(cert_data, DefaultCertFiles.Cert) {
		return fmt.Errorf("refusing to trust a process-local certificate; generate a machine-specific certificate first")
	}
	return installCertificate(cert_data)
}

// Uninstall a certificate by name
func UninstallCertificate(name string) error {
	return uninstallCertificate(name)
}
