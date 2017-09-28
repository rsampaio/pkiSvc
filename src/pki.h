#ifndef PKI_H
#define PKI_H
#include "cert.h"
#include "pki.grpc.pb.h"

const int kServerCertSize = 2048;

using grpc::Status;
using grpc::ServerContext;
using pki::Certificate;
using pki::CertificateOptions;
using pki::CSR;
using pki::KeyPair;
using pki::Register;
using cert::CertificateGenerator;

class RegisterImpl final : public Register::Service {
  // Method signature is important
  // make sure to override the correct method signature
  Status CreateIdentity(ServerContext *sc, const CertificateOptions *co,
                        Certificate *cert);
  Status CreateCSR(ServerContext *sc, const CertificateOptions *co, CSR *csr);

private:
  CertificateGenerator cg;

public:
  int LoadCA(const std::string& pub, const std::string& key);
};

#endif
