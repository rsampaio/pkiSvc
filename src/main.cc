#include <grpc++/grpc++.h>

#include "pki.h"

using grpc::ServerBuilder;
using grpc::Server;

void RunServer() {
  std::string listen("0.0.0.0:5050");

  char *ca_cert = std::getenv("CA_CERT");
  char *ca_key = std::getenv("CA_KEY");

  if (!ca_cert || !ca_key) {
    std::cout << "CA_CERT or CA_KEY env vars not set" << std::endl;
  }

  RegisterImpl service;
  if (!service.LoadCA(ca_cert, ca_key)) {
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
