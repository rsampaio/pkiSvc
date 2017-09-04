#ifndef CERT_H
#define CERT_H

#include <cstdio>
#include <iostream>
#include <string>

#include <openssl/err.h>

#include <openssl/pem.h>
#include <openssl/x509.h>

namespace cert {
struct CertificateOptions {
  std::string hostname;
  std::string subject;
  std::string issuer;
};
class CertificateGenerator {
public:
  int LoadCA(const std::string &, const std::string &);
  int GenKey(int size);
  int GenCert(CertificateOptions *opts);

  // accessors
  std::string get_server_key();
  std::string get_server_cert();
  std::string get_ca_cert();
  std::string get_ca_key();

private:
  EVP_PKEY *server_key;
  EVP_PKEY *server_cert;
  EVP_PKEY *ca_cert;
  EVP_PKEY *ca_key;
};
}

#endif
