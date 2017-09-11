#include "cert.h"

namespace cert {
int CertificateGenerator::LoadCA(const std::string &ca,
                                 const std::string &key) {
  BIO_ptr bio(BIO_new_mem_buf(ca.c_str(), -1), BIO_free);
  this->ca_cert = PEM_read_bio_PUBKEY(bio.get(), NULL, 0, NULL);
  if (!this->ca_cert) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  BIO_ptr kbio(BIO_new_mem_buf(key.c_str(), -1), BIO_free);
  this->ca_key = PEM_read_bio_PrivateKey(kbio.get(), NULL, NULL, NULL);
  if (!this->ca_key) {
    ERR_print_errors_fp(stderr);
    return 0;
  }
  return 1;
}

int CertificateGenerator::GenKey(const int size) {
  this->server_key = EVP_PKEY_new();
  if (!this->server_key) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  // BIGNUM
  BN_ptr bn(BN_new(), BN_free);
  if (!BN_set_word(bn.get(), RSA_F4)) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  // RSA_generate_key is deprecated use _ex
  RSA_ptr rsa(RSA_new(), RSA_free);
  if (!RSA_generate_key_ex(rsa.get(), size, bn.get(), NULL)) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  if (!EVP_PKEY_assign_RSA(this->server_key, rsa.get())) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  return 1;
}

int CertificateGenerator::GenCSR(CertificateOptions *opts) {
  X509_REQ *req = X509_REQ_new();
  X509_NAME *name = X509_NAME_new();

  if (!X509_REQ_set_pubkey(req, this->server_key)) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  if (!X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                                  (unsigned char *)opts->country.c_str(), -1,
                                  -1, 0)) {
    return 0;
  }

  if (!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                  (unsigned char *)opts->org.c_str(), -1, -1,
                                  0)) {
    return 0;
  }

  if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                  (unsigned char *)opts->hostname.c_str(), -1,
                                  -1, 0)) {
    return 0;
  }

  if (!X509_REQ_set_subject_name(req, name)) {
    return 0;
  }

  return 1;
}

int CertificateGenerator::GenCert(void) {
  X509_ptr x509(X509_new(), X509_free);
  if (x509 == nullptr) {
    std::cerr << "failed to allocate x509" << std::endl;
    return 0;
  }

  // Serial number
  ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 1);

  // Expire in 1 year
  X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
  X509_gmtime_adj(X509_get_notAfter(x509.get()), 31536000L);

  // Set pubkey
  X509_set_pubkey(x509.get(), this->server_key);

  // Sign with ca_key
  if (!X509_sign(x509.get(), this->ca_key, EVP_sha256())) {
    std::cerr << "failed to sign certificate" << std::endl;
    ERR_print_errors_fp(stderr);
    return 0;
  }

  BIO_ptr bio(BIO_new(BIO_s_mem()), BIO_free);
  auto server_c = std::make_unique<char[]>(4096);

  if (PEM_write_bio_X509(bio.get(), x509.get())) {
    int sz = BIO_read(bio.get(), &server_c, 4096);
    server_c[sz] = '\0';
  }

  return 1;
}

std::string CertificateGenerator::get_ca_cert() {
  // FIX: calculate cert size
  auto cert = std::make_unique<char[]>(4096);
  BIO_ptr bio(BIO_new(BIO_s_mem()), BIO_free);

  if (PEM_write_bio_PUBKEY(bio.get(), this->ca_cert)) {
    int size = BIO_read(bio.get(), cert.get(), 4096);
    cert[size] = '\0';
  }
  std::string cert_str(cert.get());
  return cert_str;
}
std::string CertificateGenerator::get_ca_key() {
  // FIX: calculate key size
  auto key = std::make_unique<char[]>(4096);
  BIO_ptr bio(BIO_new(BIO_s_mem()), BIO_free);

  if (PEM_write_bio_RSAPrivateKey(bio.get(), EVP_PKEY_get1_RSA(this->ca_key),
                                  NULL, NULL, 0, 0, NULL)) {
    int size = BIO_read(bio.get(), key.get(), 4096);
    key[size] = '\0';
  }

  std::string key_str(key.get());
  return key_str;
}

std::string CertificateGenerator::get_server_cert() {
  return std::string("server_cert");
}

std::string CertificateGenerator::get_server_key() {
  return std::string("server_key");
}
} // namespace cert
