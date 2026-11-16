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

package caddytls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"go.uber.org/zap"
)

func TestInternalIssuerRenewsExpiredIntermediate(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	storage, err := json.Marshal(map[string]string{"module": "file_system", "root": t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ca := &caddypki.CA{StorageRaw: storage, IntermediateLifetime: caddy.Duration(3 * time.Second)}
	if err := ca.Provision(ctx, "test", zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	root := ca.RootCertificate()
	oldIntermediate := ca.IntermediateCertificateChain()[0]
	ca.IntermediateLifetime = caddy.Duration(time.Hour)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rawCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"clock.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer := InternalIssuer{ca: ca, Lifetime: caddy.Duration(5 * time.Minute), logger: zap.NewNop()}
	// Let the originally valid intermediate expire without running PKI maintenance.
	time.Sleep(time.Until(oldIntermediate.NotAfter) + 100*time.Millisecond)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			csr, err := x509.ParseCertificateRequest(rawCSR)
			if err != nil {
				t.Error(err)
				return
			}
			issued, err := issuer.Issue(ctx, csr)
			if err != nil {
				t.Error(err)
				return
			}
			block, rest := pem.Decode(issued.Certificate)
			if block == nil {
				t.Error("missing leaf certificate")
				return
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Error(err)
				return
			}
			intermediates := x509.NewCertPool()
			if !intermediates.AppendCertsFromPEM(rest) {
				t.Error("missing intermediate")
				return
			}
			if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "clock.test", Roots: roots, Intermediates: intermediates}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if !bytes.Equal(root.Raw, ca.RootCertificate().Raw) {
		t.Error("renewal replaced the trusted root")
	}
	if bytes.Equal(oldIntermediate.Raw, ca.IntermediateCertificateChain()[0].Raw) {
		t.Error("expired intermediate was not renewed")
	}
}
