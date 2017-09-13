#include "client.h"

using grpc::ClientContext;
using grpc::Status;
using pki::Certificate;
using pki::Identity;

namespace client {
void PkiClient::CreateIdentity(const std::string &hostname) {
  Certificate cert;
  ClientContext ctx;

  Identity id;
  id.set_hostname(hostname);

  Status status = stub_->CreateIdentity(&ctx, id, &cert);
  if (status.ok()) {
    std::cout << "server certificate: " << cert.server_cert() << "\n";
    std::cout << "server key: " << cert.server_pubkey() << "\n";

  } else {
    std::cerr << "grpc_error=" << status.error_code() << ":"
              << status.error_message() << std::endl;
  }
}
}
