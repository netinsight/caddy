// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddypki

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"github.com/smallstep/certificates/authority/provisioner"
	"go.uber.org/zap"
)

type failingRenewalStorage struct {
	certmagic.Storage
	err error
}

func (s failingRenewalStorage) Store(context.Context, string, []byte) error { return s.err }

func TestRenewExpiredIntermediate(t *testing.T) {
	for _, scenario := range []string{"managed", "manual", "expired root", "storage failure", "missing root key"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()
			ca := &CA{storage: &certmagic.FileStorage{Path: t.TempDir()}}
			if err := ca.Provision(ctx, "test", zap.NewNop()); err != nil {
				t.Fatal(err)
			}
			root := ca.RootCertificate()
			expired := *ca.interChain[0]
			expired.NotBefore = time.Now().Add(-2 * time.Hour)
			expired.NotAfter = time.Now().Add(-time.Hour)
			ca.interChain = []*x509.Certificate{&expired}
			switch scenario {
			case "manual":
				ca.Intermediate = &KeyPair{}
			case "expired root":
				expiredRoot := *root
				expiredRoot.NotAfter = time.Now().Add(-time.Hour)
				key, err := ca.RootKey()
				if err != nil {
					t.Fatal(err)
				}
				rawDER, err := x509.CreateCertificate(rand.Reader, &expiredRoot, &expiredRoot, key.Public(), key)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := pemEncodeCert(rawDER)
				if err != nil {
					t.Fatal(err)
				}
				if err := ca.storage.Store(ctx, ca.storageKeyRootCert(), raw); err != nil {
					t.Fatal(err)
				}
			case "storage failure":
				ca.storage = failingRenewalStorage{Storage: ca.storage, err: errors.New("storage unavailable")}
			case "missing root key":
				if err := ca.storage.Delete(ctx, ca.storageKeyRootKey()); err != nil {
					t.Fatal(err)
				}
			}
			err := ca.renewExpiredIntermediate()
			wantError := scenario != "managed" && scenario != "manual"
			if (err != nil) != wantError {
				t.Fatalf("renewExpiredIntermediate() = %v, want error: %v", err, wantError)
			}
			if !bytes.Equal(root.Raw, ca.RootCertificate().Raw) {
				t.Error("replaced root")
			}
			if scenario == "managed" {
				if ca.interChain[0] == &expired {
					t.Error("did not renew intermediate")
				}
				if err := ca.interChain[0].CheckSignatureFrom(root); err != nil {
					t.Fatal(err)
				}
				renewed := ca.interChain[0]
				if err := ca.renewExpiredIntermediate(); err != nil {
					t.Fatal(err)
				}
				if ca.interChain[0] != renewed {
					t.Error("renewed a healthy intermediate")
				}
			} else if ca.interChain[0] != &expired {
				t.Error("replaced intermediate on failure or manual configuration")
			}
		})
	}
}

func TestNewAuthorityUsesValidIntermediateWhenRenewalFails(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	ca := &CA{storage: &certmagic.FileStorage{Path: t.TempDir()}}
	if err := ca.Provision(ctx, "test", zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	// Move the renewal window over the current time without expiring the signer.
	ca.RenewalWindowRatio = 1
	if !ca.needsRenewal(ca.interChain[0]) {
		t.Fatal("intermediate is not in its renewal window")
	}
	original := ca.interChain[0]
	ca.storage = failingRenewalStorage{Storage: ca.storage, err: errors.New("storage unavailable")}
	auth, err := ca.NewAuthority(AuthorityConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.GetX509Signer(); err != nil {
		t.Fatalf("valid signer should remain usable: %v", err)
	}
	if ca.interChain[0] != original {
		t.Fatal("replaced a valid intermediate")
	}
}

func TestAuthorityRenewsExpiredIntermediateBeforeSigning(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	ca := &CA{storage: &certmagic.FileStorage{Path: t.TempDir()}, IntermediateLifetime: caddy.Duration(3 * time.Second)}
	if err := ca.Provision(ctx, "test", zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	auth, err := ca.NewAuthority(AuthorityConfig{})
	if err != nil {
		t.Fatal(err)
	}
	oldIntermediate := ca.IntermediateCertificateChain()[0]
	ca.IntermediateLifetime = caddy.Duration(7 * 24 * time.Hour)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rawCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"clock.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(rawCSR)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the authority alive across expiry, as the ACME server does.
	time.Sleep(time.Until(oldIntermediate.NotAfter) + 100*time.Millisecond)
	chain, err := auth.SignWithContext(ctx, csr, provisioner.SignOptions{}, provisioner.CertificateModifierFunc(func(cert *x509.Certificate, _ provisioner.SignOptions) error {
		cert.NotBefore = time.Now()
		cert.NotAfter = cert.NotBefore.Add(time.Hour)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.RootCertificate())
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{DNSName: "clock.test", Roots: roots, Intermediates: intermediates}); err != nil {
		t.Fatal(err)
	}
}
