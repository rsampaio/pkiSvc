#ifndef PKI_H
#define PKI_H
#include "cert.h"
#include "pki.grpc.pb.h"

const int kServerCertSize = 2048;

using grpc::Status;
using grpc::ServerContext;
using pki::Register;
using pki::Identity;
using pki::Certificate;
using cert::CertificateGenerator;

class RegisterImpl final : public Register::Service {
  Status CreateIdentity(ServerContext *sc, const Identity *id,
                        Certificate *cert);

private:
  CertificateGenerator cg;

public:
  int LoadCA(const char *cert, const char *key);
};

#endif
