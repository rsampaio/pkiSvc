#include "pki.h"
#include "cert.h"

using grpc::ServerContext;
using grpc::Status;

int RegisterImpl::LoadCA(const char *ca_cert, const char *ca_key) {
  return cg.LoadCA(std::string(ca_cert), std::string(ca_key));
}

Status RegisterImpl::CreateIdentity(ServerContext *context, const Identity id,
                                    Certificate cert) {

  cert::CertificateOptions co = {id.hostname(), id.subject()};

  cg.GenCert(&co);

  cert.set_server_certificate(cg.get_server_cert());
  cert.set_server_key(cg.get_server_key());

  return Status::OK;
}
