/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"

	"github.com/grafeas/kritis/pkg/kritis/admission"
)

var (
	tlsCertFile string
	tlsKeyFile  string
)

const (
	Addr = ":443"
)

func main() {
	flag.Set("logtostderr", "true")
	flag.StringVar(&tlsCertFile, "tls-cert-file", "/var/tls/tls.crt", "TLS certificate file.")
	flag.StringVar(&tlsKeyFile, "tls-key-file", "/var/tls/tls.key", "TLS key file.")
	flag.Parse()
	http.HandleFunc("/", admission.AdmissionReviewHandler)
	httpsServer := NewServer(Addr)
	log.Fatal(httpsServer.ListenAndServeTLS(tlsCertFile, tlsKeyFile))
}

func NewServer(addr string) *http.Server {
	return &http.Server{
		Addr: addr,
		TLSConfig: &tls.Config{
			// TODO: Change this to tls.RequireAndVerifyClientCert
			ClientAuth: tls.NoClientCert,
		},
	}
}
