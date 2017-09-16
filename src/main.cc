#include <grpc++/grpc++.h>

#include "pki.h"

using grpc::ServerBuilder;
using grpc::Server;

void RunServer() {
  std::string listen("0.0.0.0:5050");

  char *ca_pubkey = std::getenv("CA_PUBKEY");
  char *ca_privkey = std::getenv("CA_PRIVKEY");

  if (!ca_pubkey || !ca_privkey) {
    std::cout << "CA_PUBKEY or CA_PRIVKEY env vars not set" << std::endl;
  }

  RegisterImpl service;
  if (!service.LoadCA(ca_pubkey, ca_privkey)) {
    std::cout << "failed to load CA" << std::endl;
    return;
  }

  ServerBuilder builder;

  builder.AddListeningPort(listen, grpc::InsecureServerCredentials());
  builder.RegisterService(&service);

  std::unique_ptr<Server> server(builder.BuildAndStart());
  std::cout << "at=start service=grpc listen=" << listen << "\n";

  server->Wait();
}

int main(int argc, char *argv[]) {
  RunServer();
  return 0;
}
