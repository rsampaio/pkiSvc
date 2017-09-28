
#include "pki.h"
#include "cert.h"

using grpc::ServerContext;
using grpc::StatusCode;
using grpc::Status;

int RegisterImpl::LoadCA(const std::string &ca_pub, const std::string &ca_key) {
  return cg.LoadCA(ca_pub, ca_key);
}

Status RegisterImpl::CreateIdentity(ServerContext *context,
                                    const CertificateOptions *co,
                                    Certificate *cert) {
  cert::CertificateOptions cert_co;
  cert_co.hostname = co->hostname();
  cert_co.country = co->country();
  cert_co.state = co->state();
  cert_co.org = co->org();

  if (!cg.GenKey(2048)) {
    std::cerr << "at=gen-key error\n";
    return Status(StatusCode::ABORTED, "gen-key failed");
  }

  if (!cg.GenCert(cert_co)) {
    std::cerr << "at=gen-certificate error\n" << std::endl;
    return Status(StatusCode::ABORTED, "gen-cert failed");
  }

  KeyPair *kp = cert->mutable_key_pair();
  kp->set_privkey(cg.server_privkey());
  kp->set_pubkey(cg.server_pubkey());
  cert->set_signed_cert(cg.server_cert());
  return Status::OK;
}

Status RegisterImpl::CreateCSR(ServerContext *context,
                               const CertificateOptions *co, CSR *csr) {
  cert::CertificateOptions cert_co;
  cert_co.hostname = co->hostname();
  cert_co.country = co->country();
  cert_co.state = co->state();
  cert_co.org = co->org();

  if (!cg.GenKey(2048)) {
    std::cerr << "at=gen-key error\n";
    return Status(StatusCode::ABORTED, "gen-key failed");
  }

  if (!cg.GenCSR(cert_co)) {
    std::cerr << "at=gen-certificate error\n" << std::endl;
    return Status(StatusCode::ABORTED, "gen-cert failed");
  }

  KeyPair *kp = csr->mutable_key_pair();
  kp->set_privkey(cg.server_privkey());
  kp->set_pubkey(cg.server_pubkey());
  csr->set_sign_request(cg.server_csr());
  return Status::OK;
}
