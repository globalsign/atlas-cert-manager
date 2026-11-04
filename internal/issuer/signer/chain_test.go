package signer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testCert struct {
	cert *x509.Certificate
	key  crypto.Signer
}

var serial atomic.Int64

func newTestCert(t *testing.T, cn string, isCA bool, parent *testCert) *testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial.Add(1)),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	signerCert, signerKey := tmpl, crypto.Signer(key)
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	return createTestCert(t, tmpl, signerCert, key, signerKey)
}

func crossSign(t *testing.T, subject, issuer *testCert) *testCert {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial.Add(1)),
		RawSubject:            subject.cert.RawSubject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	return createTestCert(t, tmpl, issuer.cert, subject.key, issuer.key)
}

func createTestCert(t *testing.T, tmpl, parent *x509.Certificate, key, parentKey crypto.Signer) *testCert {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCert{cert: cert, key: key}
}

func certs(tcs ...*testCert) []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(tcs))
	for _, tc := range tcs {
		out = append(out, tc.cert)
	}
	return out
}

func subjects(certs []*x509.Certificate) []string {
	var out []string
	for _, c := range certs {
		out = append(out, c.Subject.CommonName)
	}
	return out
}

func pemSubjects(t *testing.T, data []byte) []string {
	t.Helper()
	var out []string
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		require.Equal(t, "CERTIFICATE", block.Type)
		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		out = append(out, cert.Subject.CommonName)
	}
	assert.Empty(t, strings.TrimSpace(string(data)), "unexpected trailing data")
	return out
}

type hierarchy struct {
	root, otherRoot, rootCrossSigned           *testCert
	intermediate, intermediate1, intermediate2 *testCert
	otherIntermediate, notCA                   *testCert
	leaf, leaf2, leafFromRoot, leafOfNotCA     *testCert
	selfSignedLeaf                             *testCert
}

func newHierarchy(t *testing.T) *hierarchy {
	h := &hierarchy{}
	h.root = newTestCert(t, "root", true, nil)
	h.otherRoot = newTestCert(t, "other-root", true, nil)
	h.rootCrossSigned = crossSign(t, h.root, h.otherRoot)

	h.intermediate = newTestCert(t, "intermediate", true, h.root)
	h.leaf = newTestCert(t, "leaf", false, h.intermediate)

	h.intermediate1 = newTestCert(t, "intermediate1", true, h.root)
	h.intermediate2 = newTestCert(t, "intermediate2", true, h.intermediate1)
	h.leaf2 = newTestCert(t, "leaf2", false, h.intermediate2)

	h.leafFromRoot = newTestCert(t, "leaf-from-root", false, h.root)
	h.otherIntermediate = newTestCert(t, "other-intermediate", true, h.otherRoot)
	h.notCA = newTestCert(t, "not-ca", false, h.root)
	h.leafOfNotCA = newTestCert(t, "leaf-of-not-ca", false, h.notCA)
	h.selfSignedLeaf = newTestCert(t, "self-signed-leaf", false, nil)
	return h
}

func TestBuildChain(t *testing.T) {
	h := newHierarchy(t)

	tests := map[string]struct {
		leaf          *testCert
		trustChain    []*testCert
		expectedChain []string
		expectedCA    []string
		expectedError error
	}{
		"intermediate-then-root": {
			leaf:          h.leaf,
			trustChain:    []*testCert{h.intermediate, h.root},
			expectedChain: []string{"leaf", "intermediate"},
			expectedCA:    []string{"root"},
		},
		"root-then-intermediate": {
			leaf:          h.leaf,
			trustChain:    []*testCert{h.root, h.intermediate},
			expectedChain: []string{"leaf", "intermediate"},
			expectedCA:    []string{"root"},
		},
		"multiple-intermediates-out-of-order": {
			leaf:          h.leaf2,
			trustChain:    []*testCert{h.root, h.intermediate1, h.intermediate2},
			expectedChain: []string{"leaf2", "intermediate2", "intermediate1"},
			expectedCA:    []string{"root"},
		},
		"no-root-uses-topmost-intermediate": {
			leaf:          h.leaf2,
			trustChain:    []*testCert{h.intermediate1, h.intermediate2},
			expectedChain: []string{"leaf2", "intermediate2", "intermediate1"},
			expectedCA:    []string{"intermediate1"},
		},
		"leaf-signed-directly-by-root": {
			leaf:          h.leafFromRoot,
			trustChain:    []*testCert{h.root},
			expectedChain: []string{"leaf-from-root"},
			expectedCA:    []string{"root"},
		},
		"unrelated-certificates-are-ignored": {
			leaf:          h.leaf,
			trustChain:    []*testCert{h.otherIntermediate, h.intermediate, h.otherRoot, h.root},
			expectedChain: []string{"leaf", "intermediate"},
			expectedCA:    []string{"root"},
		},
		"duplicate-certificates": {
			leaf:          h.leaf2,
			trustChain:    []*testCert{h.intermediate2, h.intermediate2, h.intermediate1, h.root, h.root},
			expectedChain: []string{"leaf2", "intermediate2", "intermediate1"},
			expectedCA:    []string{"root"},
		},
		"duplicate-certificates-without-root": {
			leaf:          h.leaf2,
			trustChain:    []*testCert{h.intermediate2, h.intermediate1, h.intermediate2},
			expectedChain: []string{"leaf2", "intermediate2", "intermediate1"},
			expectedCA:    []string{"intermediate1"},
		},
		"self-signed-root-preferred-over-cross-signed": {
			leaf:          h.leaf,
			trustChain:    []*testCert{h.rootCrossSigned, h.intermediate, h.root, h.otherRoot},
			expectedChain: []string{"leaf", "intermediate"},
			expectedCA:    []string{"root"},
		},
		"cross-signed-root-without-its-self-signed-copy": {
			leaf:          h.leaf,
			trustChain:    []*testCert{h.intermediate, h.rootCrossSigned, h.otherRoot},
			expectedChain: []string{"leaf", "intermediate", "root"},
			expectedCA:    []string{"other-root"},
		},
		"empty-trust-chain": {
			leaf:          h.leaf,
			expectedChain: []string{"leaf"},
		},
		"trust-chain-does-not-match-leaf": {
			leaf:          h.leaf,
			trustChain:    []*testCert{h.otherIntermediate, h.otherRoot},
			expectedError: errChainDoesNotMatchLeaf,
		},
		"issuer-is-not-a-ca": {
			leaf:          h.leafOfNotCA,
			trustChain:    []*testCert{h.notCA, h.root},
			expectedError: errChainDoesNotMatchLeaf,
		},
		"missing-intermediate": {
			leaf:          h.leaf2,
			trustChain:    []*testCert{h.intermediate2, h.root},
			expectedError: errIncompleteChain,
		},
		"self-signed-leaf": {
			leaf:          h.selfSignedLeaf,
			trustChain:    []*testCert{h.root},
			expectedError: errSelfSignedLeaf,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			chain, ca, err := buildChain(tc.leaf.cert, certs(tc.trustChain...))
			if tc.expectedError != nil {
				assert.ErrorIs(t, err, tc.expectedError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedChain, subjects(chain), "tls.crt")
			assert.Equal(t, tc.expectedCA, subjects(ca), "ca.crt")
		})
	}
}

func TestFallbackChain(t *testing.T) {
	h := newHierarchy(t)

	tests := map[string]struct {
		leaf          *testCert
		trustChain    []*testCert
		expectedChain []string
		expectedCA    []string
	}{
		"trust-chain-does-not-match-leaf": {
			leaf:          h.leaf,
			trustChain:    []*testCert{h.otherIntermediate, h.otherRoot},
			expectedChain: []string{"leaf", "other-intermediate"},
			expectedCA:    []string{"other-root"},
		},
		"missing-intermediate-keeps-the-rest": {
			leaf:          h.leaf2,
			trustChain:    []*testCert{h.intermediate2, h.root},
			expectedChain: []string{"leaf2", "intermediate2"},
			expectedCA:    []string{"root"},
		},
		"keeps-atlas-order-and-drops-duplicates": {
			leaf:          h.leaf2,
			trustChain:    []*testCert{h.root, h.intermediate1, h.leaf2, h.intermediate2, h.intermediate1, h.root},
			expectedChain: []string{"leaf2", "intermediate1", "intermediate2"},
			expectedCA:    []string{"root"},
		},
		"no-root-returns-trust-chain-as-ca": {
			leaf:          h.leaf2,
			trustChain:    []*testCert{h.intermediate2},
			expectedChain: []string{"leaf2", "intermediate2"},
			expectedCA:    []string{"intermediate2"},
		},
		"self-signed-leaf": {
			leaf:          h.selfSignedLeaf,
			trustChain:    []*testCert{h.root},
			expectedChain: []string{"self-signed-leaf"},
			expectedCA:    []string{"root"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			chain, ca := fallbackChain(tc.leaf.cert, certs(tc.trustChain...))
			assert.Equal(t, tc.expectedChain, subjects(chain), "tls.crt")
			assert.Equal(t, tc.expectedCA, subjects(ca), "ca.crt")
		})
	}
}

func TestBundle(t *testing.T) {
	h := newHierarchy(t)

	tests := map[string]struct {
		leaf          *testCert
		trustChain    []*testCert
		expectedCert  []string
		expectedCA    []string
		expectWarning bool
	}{
		"verified-chain": {
			leaf:         h.leaf2,
			trustChain:   []*testCert{h.root, h.intermediate1, h.intermediate2},
			expectedCert: []string{"leaf2", "intermediate2", "intermediate1"},
			expectedCA:   []string{"root"},
		},
		"empty-trust-chain": {
			leaf:         h.leaf,
			expectedCert: []string{"leaf"},
		},
		"unverifiable-chain-falls-back-and-warns": {
			leaf:          h.leaf2,
			trustChain:    []*testCert{h.intermediate2, h.root},
			expectedCert:  []string{"leaf2", "intermediate2"},
			expectedCA:    []string{"root"},
			expectWarning: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var logs []string
			logger := funcr.New(func(prefix, args string) { logs = append(logs, args) }, funcr.Options{})
			ctx := logr.NewContext(context.Background(), logger)

			certPEM, caPEM := bundle(ctx, tc.leaf.cert, certs(tc.trustChain...))
			assert.Equal(t, tc.expectedCert, pemSubjects(t, certPEM), "tls.crt")
			assert.Equal(t, tc.expectedCA, pemSubjects(t, caPEM), "ca.crt")

			if tc.expectWarning {
				require.Len(t, logs, 1)
				assert.Contains(t, logs[0], errIncompleteChain.Error())
			} else {
				assert.Empty(t, logs)
			}
		})
	}
}
