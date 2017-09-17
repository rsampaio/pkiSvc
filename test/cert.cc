#include <fstream>

#include "gtest/gtest.h"

#include "../src/cert.h"

namespace {
class CertificateTest : public testing::Test {
public:
  cert::CertificateOptions co;
  cert::CertificateGenerator cg;
  std::string pub_str, key_str, line;
  std::unique_ptr<char[]> pub;

  virtual void SetUp() {
    std::fstream pub_f("ca.key.pub",
                       std::ios::binary | std::ios::in | std::ios::ate);
    std::fstream key_f("ca.key.pem",
                       std::ios::binary | std::ios::in | std::ios::ate);

    if (!pub_f.is_open() || !key_f.is_open()) {
      std::cerr << "CA pub or key file not find\n"
                << "use: openssl genrsa -out ca.key.pem && openssl rsa -pubout "
                << "-in ca.key.pem -out ca.key.pub\n"
                << std::endl;
      exit(-1);
    }

    // read ca pem
    std::streamoff pub_size = pub_f.tellg();
    pub_f.seekg(0, pub_f.beg);

    auto pub_c = std::make_unique<char[]>(pub_size + 1);
    pub_f.read(pub_c.get(), pub_size);
    pub_c[pub_size] = '\0';
    pub_str = std::string(pub_c.get());
    pub_f.close();

    // read ca key
    std::streamoff key_size = key_f.tellg();
    key_f.seekg(0, key_f.beg);

    auto key_c = std::make_unique<char[]>(key_size + 1);
    key_f.read(key_c.get(), key_size);
    key_c[key_size] = '\0';
    key_str = std::string(key_c.get());
    key_f.close();

    // CertificateOptions
    co.hostname = "test.testing";
    co.org = "personal inc";
    co.state = "CA";
    co.country = "US";
  }
};

TEST_F(CertificateTest, TestLoadCA) {
  ASSERT_EQ(cg.LoadCA(pub_str, key_str), 1);
  ASSERT_EQ(cg.ca_key(), key_str);
  ASSERT_EQ(cg.ca_cert(), pub_str);
}

TEST_F(CertificateTest, TestGenCSR) {
  ASSERT_EQ(cg.LoadCA(pub_str, key_str), 1);
  ASSERT_EQ(cg.GenKey(2048), 1);
  ASSERT_EQ(cg.GenCSR(co), 1);

  // CSR expects all certification options
  co.country = "";
  ASSERT_EQ(cg.GenCSR(co), 0);
}

TEST_F(CertificateTest, TestGenCert) {
  ASSERT_EQ(cg.LoadCA(pub_str, key_str), 1);
  ASSERT_EQ(cg.GenKey(2048), 1);
  ASSERT_EQ(cg.GenCert(co), 1);
}

TEST_F(CertificateTest, TestGenKey) {
  ASSERT_EQ(cg.GenKey(2048), 1);
  ASSERT_EQ(cg.GenKey(1024), 1);
}
}
