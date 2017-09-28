#include "client.h"

namespace client {
void PkiClient::CreateIdentity(const CertificateOptions &co) {
  Certificate cert;
  ClientContext ctx;

  Status status = stub_->CreateIdentity(&ctx, co, &cert);
  if (status.ok()) {
    json out_json;
    out_json["server_certificate"] = cert.signed_cert();
    out_json["server_privkey"] = cert.key_pair().privkey();
    out_json["server_pubkey"] = cert.key_pair().pubkey();

    std::cout << out_json << std::endl;
  } else {
    std::cerr << "grpc_error=" << status.error_code() << ":"
              << status.error_message() << std::endl;
  }
}

void PkiClient::CreateCSR(const CertificateOptions &co) {
  ClientContext ctx;
  CSR csr;
  Status status = stub_->CreateCSR(&ctx, co, &csr);
  if (status.ok()) {
    json out_json;
    out_json["server_csr"] = csr.sign_request();
    out_json["server_privkey"] = csr.key_pair().privkey();
    out_json["server_pubkey"] = csr.key_pair().pubkey();
    std::cout << out_json << std::endl;
  } else {
    std::cerr << "at=create_csr grpc_error=" << status.error_code() << ":"
              << status.error_message() << std::endl;
  }
}
}
