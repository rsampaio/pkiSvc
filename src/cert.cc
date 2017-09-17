#include "cert.h"

namespace cert {
int CertificateGenerator::LoadCA(const std::string &ca,
                                 const std::string &key) {
  BIO_ptr bio(BIO_new_mem_buf(ca.c_str(), -1), BIO_free);
  this->ca_cert_ = PEM_read_bio_PUBKEY(bio.get(), NULL, 0, NULL);
  if (!this->ca_cert_) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  BIO_ptr kbio(BIO_new_mem_buf(key.c_str(), -1), BIO_free);
  this->ca_key_ = PEM_read_bio_PrivateKey(kbio.get(), NULL, NULL, NULL);
  if (!this->ca_key_) {
    ERR_print_errors_fp(stderr);
    return 0;
  }
  return 1;
}

int CertificateGenerator::GenKey(const int size) {
  this->server_key_ = EVP_PKEY_new();
  if (!this->server_key_) {
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

  if (!EVP_PKEY_set1_RSA(this->server_key_, rsa.get())) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  return 1;
}

int CertificateGenerator::GenCSR(const CertificateOptions &opts) {
  X509_REQ_ptr req(X509_REQ_new(), X509_REQ_free);
  X509_NAME_ptr name(X509_NAME_new(), X509_NAME_free);

  if (!X509_REQ_set_pubkey(req.get(), this->server_key_)) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  if (!X509_NAME_add_entry_by_txt(name.get(), "C", MBSTRING_ASC,
                                  (unsigned char *)opts.country.c_str(), -1, -1,
                                  0)) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  if (!X509_NAME_add_entry_by_txt(name.get(), "ST", MBSTRING_ASC,
                                  (unsigned char *)opts.state.c_str(), -1, -1,
                                  0)) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  if (!X509_NAME_add_entry_by_txt(name.get(), "O", MBSTRING_ASC,
                                  (unsigned char *)opts.org.c_str(), -1, -1,
                                  0)) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  if (!X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC,
                                  (unsigned char *)opts.hostname.c_str(), -1,
                                  -1, 0)) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  if (!X509_REQ_set_subject_name(req.get(), name.get())) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  return 1;
}

int CertificateGenerator::GenCert(const CertificateOptions &opts) {
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

  // Set pubkey to the server_key
  if (!X509_set_pubkey(x509.get(), this->server_key_)) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  // Sign with ca_key
  if (!X509_sign(x509.get(), this->ca_key_, EVP_sha256())) {
    std::cerr << "failed to sign certificate" << std::endl;
    ERR_print_errors_fp(stderr);
    return 0;
  }

  // Write to BIO to convert to string
  BIO_ptr bio(BIO_new(BIO_s_mem()), BIO_free);
  auto server_c = std::make_unique<char[]>(4096);

  if (PEM_write_bio_X509(bio.get(), x509.get())) {
    int sz = BIO_read(bio.get(), server_c.get(), 4096);
    server_c.get()[sz] = '\0';
  }

  this->server_cert_ = std::string(server_c.get());
  return 1;
}

std::string CertificateGenerator::ca_cert() {
  // FIX: calculate cert size
  auto cert = std::make_unique<char[]>(4096);
  BIO_ptr bio(BIO_new(BIO_s_mem()), BIO_free);

  if (PEM_write_bio_PUBKEY(bio.get(), this->ca_cert_)) {
    int size = BIO_read(bio.get(), cert.get(), 4096);
    cert[size] = '\0';
  }
  std::string cert_str(cert.get());
  return cert_str;
}

std::string CertificateGenerator::ca_key() {
  // FIX: calculate key size
  auto key = std::make_unique<char[]>(4096);
  BIO_ptr bio(BIO_new(BIO_s_mem()), BIO_free);

  if (PEM_write_bio_RSAPrivateKey(bio.get(), EVP_PKEY_get1_RSA(this->ca_key_),
                                  NULL, NULL, 0, 0, NULL)) {
    int size = BIO_read(bio.get(), key.get(), 4096);
    key[size] = '\0';
  }

  std::string key_str(key.get());
  return key_str;
}

std::string CertificateGenerator::server_cert() { return this->server_cert_; }

std::string CertificateGenerator::server_privkey() {
  BIO_ptr bio(BIO_new(BIO_s_mem()), BIO_free);
  auto server_c = std::make_unique<char[]>(4096);
  RSA_ptr rsa(EVP_PKEY_get1_RSA(this->server_key_), RSA_free);
  if (PEM_write_bio_RSAPrivateKey(bio.get(), rsa.get(), NULL, NULL, 0, NULL,
                                  NULL)) {
    int sz = BIO_read(bio.get(), server_c.get(), 4096);
    server_c.get()[sz] = '\0';
  }

  return std::string(server_c.get());
}

std::string CertificateGenerator::server_pubkey() {
  BIO_ptr bio(BIO_new(BIO_s_mem()), BIO_free);
  auto server_pub_c = std::make_unique<char[]>(4096);
  if (PEM_write_bio_PUBKEY(bio.get(), this->server_key_)) {
    int sz = BIO_read(bio.get(), server_pub_c.get(), 4096);
    server_pub_c.get()[sz] = '\0';
  }

  return std::string(server_pub_c.get());
}
} // namespace cert
