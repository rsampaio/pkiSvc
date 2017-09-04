#include "cert.h"

namespace cert {
int CertificateGenerator::LoadCA(const std::string &ca,
                                 const std::string &key) {
  BIO *bio = BIO_new_mem_buf(ca.c_str(), -1);
  X509 *x = PEM_read_bio_X509(bio, NULL, 0, NULL);
  this->ca_cert = X509_get_pubkey(x);
  if (this->ca_cert == nullptr) {
    ERR_print_errors_fp(stderr);
    EVP_PKEY_free(this->ca_cert);
    return 0;
  }

  BIO *kbio = BIO_new_mem_buf(key.c_str(), -1);
  this->ca_key = PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL);
  if (this->ca_key == nullptr) {
    ERR_print_errors_fp(stderr);
    EVP_PKEY_free(this->ca_key);
    return 0;
  }

  return 1;
}

int CertificateGenerator::GenKey(int size) {
  this->server_key = EVP_PKEY_new();
  if (!server_key) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  RSA *rsa = RSA_generate_key(size, RSA_F4, NULL, NULL);
  if (!rsa) {
    ERR_print_errors_fp(stderr);
    EVP_PKEY_free(server_key);
    return 0;
  }

  return 1;
}

int CertificateGenerator::GenCert(CertificateOptions *opts) {
  X509 *x509 = X509_new();
  X509_NAME *name = X509_get_subject_name(x509);

  if (!x509) {
    std::cerr << "failed to allocate x509\n";
    return 0;
  }

  // Serial number
  ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

  // Expire in 1 year
  X509_gmtime_adj(X509_get_notBefore(x509), 0);
  X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

  // Set pubkey
  X509_set_pubkey(x509, ca_cert);

  X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"CA", -1,
                             -1, 0);
  X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                             (unsigned char *)"RSampaio", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                             (unsigned char *)opts->hostname.c_str(), -1, -1,
                             0);

  // Sign with ca_key

  if (!X509_sign(x509, ca_key, EVP_sha256())) {
    std::cerr << "failed to sign certificate\n";
    ERR_print_errors_fp(stderr);
    X509_free(x509);
    return 0;
  }

  // Set issuer (CA)
  // ASN1_STRING_set(X509_get_issuer_name(x509), ca_issuer, strlen(ca_issuer));

  return 1;
}

std::string CertificateGenerator::get_ca_cert() {
  // FIX: calculate cert size
  char *cert = new char[4096];
  BIO *bio = BIO_new(BIO_s_mem());
  if (PEM_write_bio_PUBKEY(bio, this->ca_cert)) {
    int size = BIO_read(bio, cert, 4096);
    cert[size] = '\0';
  }

  return std::string(cert);
}
std::string CertificateGenerator::get_ca_key() {
  // FIX: calculate key size
  char *key = new char[4096];
  BIO *bio = BIO_new(BIO_s_mem());
  if (PEM_write_bio_RSAPrivateKey(bio, EVP_PKEY_get1_RSA(this->ca_key), NULL,
                                  NULL, 0, 0, NULL)) {
    int size = BIO_read(bio, key, 4096);
    key[size] = '\0';
  }

  return std::string(key);
}

std::string CertificateGenerator::get_server_cert() {
  return std::string("server_cert");
}

std::string CertificateGenerator::get_server_key() {
  return std::string("server_key");
}
} // namespace cert
