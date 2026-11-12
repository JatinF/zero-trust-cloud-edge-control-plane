// Package identity issues lab workload certificates and human bearer tokens.
// The CA is process-local. SPIRE was not started. An OIDC provider was not contacted.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"time"
)

const ServerName = "zt-lab"

type Issuer struct {
	CACert *x509.Certificate
	CAKey  ed25519.PrivateKey
	Pool   *x509.CertPool
}

func NewIssuer(now time.Time) (*Issuer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "syn-lab-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &Issuer{CACert: cert, CAKey: priv, Pool: pool}, nil
}

// Leaf mints a certificate whose URI SAN is the SPIFFE ID.
// notAfter is wall-clock lifetime, not the lab policy clock.
func (i *Issuer) Leaf(spiffeID, commonName string, notBefore, notAfter time.Time) (tls.Certificate, error) {
	uri, err := url.Parse(spiffeID)
	if err != nil {
		return tls.Certificate{}, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:         []*url.URL{uri},
		DNSNames:     []string{ServerName},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, i.CACert, pub, i.CAKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func (i *Issuer) ServerCertificate(now time.Time) (tls.Certificate, error) {
	return i.Leaf("spiffe://syn.lab/service/policy-sync", ServerName, now.Add(-time.Hour), now.Add(24*time.Hour))
}

func ClientTLS(leaf tls.Certificate, pool *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{leaf},
		RootCAs:      pool,
		ServerName:   ServerName,
		MinVersion:   tls.VersionTLS13,
	}
}

func ServerTLS(cert tls.Certificate, pool *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
}
