package signer

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/go-logr/logr"
)

var (
	errSelfSignedLeaf        = errors.New("issued certificate is self-signed")
	errChainDoesNotMatchLeaf = errors.New("atlas trust chain does not contain the issuer of the issued certificate")
	errIncompleteChain       = errors.New("atlas trust chain is missing an intermediate between the issued certificate and the root")
)

func bundle(ctx context.Context, leaf *x509.Certificate, trustChain []*x509.Certificate) (certPEM []byte, caPEM []byte) {
	chain, ca, err := buildChain(leaf, trustChain)
	if err != nil {
		logr.FromContextOrDiscard(ctx).Info("Could not verify the Atlas trust chain, writing it to tls.crt as returned",
			"reason", err.Error(), "trustChain", subjectNames(trustChain))
		chain, ca = fallbackChain(leaf, trustChain)
	}
	return encodePEM(chain...), encodePEM(ca...)
}

func buildChain(leaf *x509.Certificate, trustChain []*x509.Certificate) ([]*x509.Certificate, []*x509.Certificate, error) {
	chain := []*x509.Certificate{leaf}
	if len(trustChain) == 0 {
		return chain, nil, nil
	}
	if isSelfSigned(leaf) {
		return nil, nil, errSelfSignedLeaf
	}

	used := make([]bool, len(trustChain))
	current := leaf
	for {
		i := findIssuer(current, trustChain, used)
		if i < 0 {
			break
		}
		used[i] = true
		issuer := trustChain[i]
		if isSelfSigned(issuer) {
			return chain, []*x509.Certificate{issuer}, nil
		}
		chain = append(chain, issuer)
		current = issuer
	}

	if len(chain) == 1 {
		return nil, nil, errChainDoesNotMatchLeaf
	}
	for i, cert := range trustChain {
		if !used[i] && !containsCert(chain, cert) {
			return nil, nil, errIncompleteChain
		}
	}
	return chain, chain[len(chain)-1:], nil
}

func fallbackChain(leaf *x509.Certificate, trustChain []*x509.Certificate) ([]*x509.Certificate, []*x509.Certificate) {
	chain := []*x509.Certificate{leaf}
	var roots []*x509.Certificate
	for _, cert := range trustChain {
		if containsCert(chain, cert) || containsCert(roots, cert) {
			continue
		}
		if isSelfSigned(cert) {
			roots = append(roots, cert)
		} else {
			chain = append(chain, cert)
		}
	}
	if len(roots) == 0 {
		return chain, trustChain
	}
	return chain, roots
}

func findIssuer(cert *x509.Certificate, candidates []*x509.Certificate, used []bool) int {
	found := -1
	for i, c := range candidates {
		if used[i] || !bytes.Equal(cert.RawIssuer, c.RawSubject) || cert.CheckSignatureFrom(c) != nil {
			continue
		}
		if isSelfSigned(c) {
			return i
		}
		if found < 0 {
			found = i
		}
	}
	return found
}

func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject) &&
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

func containsCert(certs []*x509.Certificate, cert *x509.Certificate) bool {
	for _, c := range certs {
		if c.Equal(cert) {
			return true
		}
	}
	return false
}

func subjectNames(certs []*x509.Certificate) []string {
	names := make([]string, 0, len(certs))
	for _, cert := range certs {
		names = append(names, cert.Subject.String())
	}
	return names
}

func encodePEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, cert := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}
	return out
}
