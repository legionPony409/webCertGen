package certManager

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	randM "math/rand"
	"net"
	"strings"
	"time"
)

var CurrentCaCertificate *x509.Certificate
var CurrentCaPrivKey *rsa.PrivateKey

type certificateType int

const (
	CaCert certificateType = iota
	ServerCert
	KubeServiceCert
)

type KubeInfo struct {
	ServiceName string
	EnvName     string
	Namespace   string
}

type CertificateInfo struct {
	CertOption               certificateType
	Org, Country, CommonName string
	DnsList, IpList          string
	KubeInfo                 KubeInfo
	CaPublicCert             []byte
	CaPrivateCert            []byte
}

func ParseOutput(requestText string, scanVar interface{}) {
	fmt.Println(requestText)
	for {
		_, err := fmt.Scan(scanVar)
		if err != nil {
			fmt.Println(err.Error() + " Try again!")
			continue
		}
		break
	}
}

func GetFilledCertTemplate(certInfo *CertificateInfo) *x509.Certificate {
	keyUsageList := x509.KeyUsageDigitalSignature

	var tmpDnsStingArray []string
	var tmpIpNetArray []net.IP
	var isCa bool

	switch certInfo.CertOption {
	case KubeServiceCert:
		tmpDnsStingArray = append(tmpDnsStingArray, "localhost")
		tmpDnsStingArray = append(tmpDnsStingArray, certInfo.KubeInfo.EnvName+"-"+certInfo.KubeInfo.ServiceName)
		tmpDnsStingArray = append(tmpDnsStingArray, certInfo.KubeInfo.EnvName+"-"+certInfo.KubeInfo.ServiceName+"."+certInfo.KubeInfo.Namespace)
		tmpDnsStingArray = append(tmpDnsStingArray, certInfo.KubeInfo.EnvName+"-"+certInfo.KubeInfo.ServiceName+"."+certInfo.KubeInfo.Namespace+".svc")
		tmpDnsStingArray = append(tmpDnsStingArray, certInfo.KubeInfo.EnvName+"-"+certInfo.KubeInfo.ServiceName+"."+certInfo.KubeInfo.Namespace+".svc.cluster.local")
		tmpIpNetArray = append(tmpIpNetArray, net.ParseIP("127.0.0.1"))

		fallthrough
	case ServerCert:
		// var tmpDnsSting string
		// dnsTextInfo := "Enter DNS list with comma delimiter or enter '-' to skip (example: ya.ru,google.com,msn.com):"
		// ParseOutput(dnsTextInfo, &tmpDnsSting)
		if certInfo.DnsList != "" {
			tmpDnsStingArray = append(tmpDnsStingArray, strings.Split(certInfo.DnsList, ",")...)
		}

		// var tmpIpList string
		// ipTextInfo := "Enter IP list with comma delimiter or enter '-' to skip (example: 127.0.0.1,192.168.1.1,10.10.10.1 ):"
		// ParseOutput(ipTextInfo, &tmpIpList)
		var tmpIpListArray []string
		if certInfo.IpList != "" {
			tmpIpListArray = strings.Split(certInfo.IpList, ",")
		}

		for _, ipAddr := range tmpIpListArray {
			tmpIpNetArray = append(tmpIpNetArray, net.ParseIP(ipAddr))
		}
	case CaCert:
		keyUsageList = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
		isCa = true
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(randM.Int63()),
		Subject: pkix.Name{
			Organization: []string{certInfo.Org},
			Country:      []string{certInfo.Country},
			CommonName:   certInfo.CommonName,
		},

		// regular cert fields
		IPAddresses: tmpIpNetArray,
		DNSNames:    tmpDnsStingArray,
		// SubjectKeyId: []byte{1, 2, 3, 4, 6},

		// regular fields
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  isCa,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              keyUsageList,
		BasicConstraintsValid: true,
	}

	return certTemplate
}

func ExtractRawCertificate(certReader io.Reader) (publicCert []byte, privateCert []byte) {
	certPEM := new(bytes.Buffer)
	_, err := certPEM.ReadFrom(certReader)
	if err != nil {
		log.Println("Error: ", err.Error())
		return
	}

	rawCert, restBytes := pem.Decode(certPEM.Bytes())
	if strings.Contains(rawCert.Type, "RSA PRIVATE KEY") {
		privateCert = rawCert.Bytes

	} else if strings.Contains(rawCert.Type, "CERTIFICATE") {
		publicCert = rawCert.Bytes
	}

	if len(restBytes) > 32 {
		secondRawCert, _ := pem.Decode(restBytes)
		if strings.Contains(secondRawCert.Type, "RSA PRIVATE KEY") {
			privateCert = secondRawCert.Bytes

		} else if strings.Contains(secondRawCert.Type, "CERTIFICATE") {
			publicCert = secondRawCert.Bytes
		}
	}

	return
}

func CheckCertificate(certReader io.Reader, output io.Writer) {
	publicCert, _ := ExtractRawCertificate(certReader)
	goodCert, err := x509.ParseCertificate(publicCert)
	if err != nil {
		log.Println("Error: ", err.Error())
		return
	}

	isCA := fmt.Sprintf("Is it a CA cert: %v \n", goodCert.IsCA)
	subject := fmt.Sprintf("Subject: %v \n", goodCert.Subject)
	issuer := fmt.Sprintf("Issuer: %v \n", goodCert.Issuer)
	keyAlg := fmt.Sprintf("Key algorithm: %v \n", goodCert.PublicKeyAlgorithm)
	DnsList := fmt.Sprintf("DNS names: %v \n", goodCert.DNSNames)
	ipList := fmt.Sprintf("IP addresses: %v \n", goodCert.IPAddresses)

	output.Write([]byte(isCA))
	output.Write([]byte(subject))
	output.Write([]byte(issuer))
	output.Write([]byte(keyAlg))
	output.Write([]byte(DnsList))
	output.Write([]byte(ipList))
}

func CreateCertificate(certInfo *CertificateInfo, output io.Writer) error {
	cert := GetFilledCertTemplate(certInfo)

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	if certInfo.CertOption == CaCert {
		CurrentCaCertificate = cert
		CurrentCaPrivKey = certPrivKey
	} else {
		CurrentCaCertificate, _ = x509.ParseCertificate(certInfo.CaPublicCert)
		CurrentCaPrivKey, _ = x509.ParsePKCS1PrivateKey(certInfo.CaPrivateCert)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, CurrentCaCertificate, &certPrivKey.PublicKey, CurrentCaPrivKey)
	if err != nil {
		return err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	output.Write(certPEM.Bytes())
	output.Write(certPrivKeyPEM.Bytes())

	return nil
}
