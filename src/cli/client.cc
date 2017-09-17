#include "client.h"

namespace client {
void PkiClient::CreateIdentity(const std::string &hostname) {
  Certificate cert;
  ClientContext ctx;

  std::cout << "creating identity" << std::endl;

  Identity id;
  id.set_hostname(hostname);
  id.set_country("US");
  id.set_state("CA");
  id.set_org("personal inc");

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
