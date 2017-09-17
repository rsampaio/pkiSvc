#ifndef CERT_H
#define CERT_H

#include <cstdio>
#include <iostream>
#include <memory>
#include <string>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

// unique_ptr aliases to delete when out of scope
// use decltype to declare the type of free functions
// to receive as parameter.
// Alias                   unique_ptr<TYPE,      DELETER>
using BN_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using RSA_ptr = std::unique_ptr<RSA, decltype(&RSA_free)>;
using X509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using X509_REQ_ptr = std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)>;
using X509_NAME_ptr = std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>;
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

namespace cert {
struct CertificateOptions {
  std::string hostname;
  std::string country;
  std::string state;
  std::string org;
};

class CertificateGenerator {
public:
  // LoadCA loads certificate that will sign identity certs
  // args are CA pubkey and CA private key
  int LoadCA(const std::string &, const std::string &);

  // GenKey generates an RSA key from an specified size
  int GenKey(const int size);

  // GenCSR generates the X509 CSR
  int GenCSR(const CertificateOptions &opts);

  // GenCert generates signed cert based on CSR
  int GenCert(const CertificateOptions &opts);

  // accessors
  std::string get_server_pubkey();
  std::string get_server_privkey();
  std::string get_server_cert();
  std::string get_ca_cert();
  std::string get_ca_key();

private:
  std::string server_cert_; // X509 cert
  EVP_PKEY *server_key;     // RSA keypair
  EVP_PKEY *ca_cert;        // CA cert (pub)
  EVP_PKEY *ca_key;         // CA key (priv)
};
}
#endif
