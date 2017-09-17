
#include "pki.h"
#include "cert.h"

using grpc::ServerContext;
using grpc::StatusCode;
using grpc::Status;

int RegisterImpl::LoadCA(const char *ca_cert, const char *ca_key) {
  return cg.LoadCA(std::string(ca_cert), std::string(ca_key));
}

Status RegisterImpl::CreateIdentity(ServerContext *context, const Identity *id,
                                    Certificate *cert) {
  cert::CertificateOptions co;
  co.hostname = id->hostname();
  co.country = id->country();
  co.state = id->state();
  co.org = id->org();

  if (!cg.GenKey(2048)) {
    std::cerr << "at=gen-key error\n";
    return Status(StatusCode::ABORTED, "gen-key failed");
  }
  if (!cg.GenCert(co)) {
    std::cerr << "at=gen-certificate error\n" << std::endl;
    return Status(StatusCode::ABORTED, "gen-cert failed");
  }

  cert->set_server_cert(cg.server_cert());
  cert->set_server_privkey(cg.server_privkey());
  cert->set_server_pubkey(cg.server_pubkey());

  return Status::OK;
}
