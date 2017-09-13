
#include "pki.h"
#include "cert.h"

using grpc::ServerContext;
using grpc::Status;

int RegisterImpl::LoadCA(const char *ca_cert, const char *ca_key) {
  return cg.LoadCA(std::string(ca_cert), std::string(ca_key));
}

Status RegisterImpl::CreateIdentity(ServerContext *context, const Identity id,
                                    Certificate cert) {

  cert::CertificateOptions co = {id.hostname(), id.country(), id.state(),
                                 id.org()};

  if (!cg.GenCert(co)) {
    std::cerr << "at=gen-certificate error\n" << std::endl;
  }

  cert.set_server_cert(cg.get_server_cert());
  cert.set_server_privkey(cg.get_server_privkey());
  cert.set_server_pubkey(cg.get_server_pubkey());

  return Status::OK;
}
