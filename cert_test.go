package h2tunnel

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseCertificatesPEM(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		pb, err := os.ReadFile("testdata/certs.pem")
		require.NoError(t, err)
		certs, err := parseCertificatesPEM(pb)
		require.NoError(t, err)
		t.Log(certs[0].Issuer)
		t.Log(certs[1].Issuer)
	})

	t.Run("invalid PEM data", func(t *testing.T) {
		certs, err := parseCertificatesPEM([]byte{0, 1, 2, 3})
		require.EqualError(t, err, "invalid PEM block")
		require.Nil(t, certs)
	})

	t.Run("invalid type", func(t *testing.T) {
		pb := []byte(`
-----BEGIN INVALID TYPE-----
-----END INVALID TYPE-----
`)
		certs, err := parseCertificatesPEM(pb)
		require.EqualError(t, err, "invalid PEM block type: INVALID TYPE")
		require.Nil(t, certs)
	})

	t.Run("invalid certificate data", func(t *testing.T) {
		pb := []byte(`
-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----
`)
		certs, err := parseCertificatesPEM(pb)
		require.EqualError(t, err, "x509: malformed certificate")
		require.Nil(t, certs)
	})
}
