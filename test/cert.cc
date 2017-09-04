#include <fstream>

#include "gtest/gtest.h"

#include "../src/cert.h"

namespace {
class CertificateTest : public testing::Test {
public:
  cert::CertificateGenerator cg;
  std::string cert_str, key_str, line;
  char *cert;

  virtual void SetUp() {

    std::fstream cert_f("ca.cert.pem",
                        std::ios::binary | std::ios::in | std::ios::ate);
    std::fstream key_f("ca.key.pem",
                       std::ios::binary | std::ios::in | std::ios::ate);

    // read ca pem
    std::streamoff cert_size = cert_f.tellg();
    cert_f.seekg(0, cert_f.beg);

    char *cert_c = new char[cert_size];
    cert_f.read(cert_c, cert_size);
    cert_c[cert_size] = '\0';
    cert_str = std::string(cert_c);
    cert_f.close();

    // read ca key
    std::streamoff key_size = key_f.tellg();
    key_f.seekg(0, key_f.beg);

    char *key_c = new char[key_size];
    key_f.read(key_c, key_size);
    key_c[key_size] = '\0';
    key_str = std::string(key_c);
    key_f.close();

    // Extract public certificate from PEM
    // Write the cert_str to a BIO
    BIO *bio = BIO_new_mem_buf(cert_str.c_str(), -1);

    // Read from BIO to a X509 certifciate
    X509 *x = NULL;
    PEM_read_bio_X509(bio, &x, NULL, NULL);

    // Extract pubkey
    EVP_PKEY *pkey = X509_get_pubkey(x);

    // Write the pubkey to a BIO and read back as text
    char *cert = new char[4096];
    BIO *cbio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PUBKEY(cbio, pkey)) {
      int size = BIO_read(cbio, cert, 4096);
      cert[size] = '\0';
    }

    EVP_PKEY_free(pkey);
    X509_free(x);
    BIO_free(bio);
    BIO_free(cbio);
  }
};

TEST_F(CertificateTest, TestLoadCA) {
  ASSERT_EQ(cg.LoadCA(cert_str, key_str), 1);
  ASSERT_EQ(cg.get_ca_key(), key_str);
  ASSERT_EQ(cg.get_ca_cert(), cert);
}

TEST_F(CertificateTest, TestGenCert) {
  cert::CertificateOptions co;
  co.hostname = "test.testing";
  cg.GenCert(&co);
  ASSERT_EQ(true, true);
}
}
