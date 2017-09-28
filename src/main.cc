#include <grpc++/grpc++.h>

#include "pki.h"

#include "docopt.h"

using grpc::ServerBuilder;
using grpc::Server;

static const char USAGE[] = R"(pkiSvc
    Usage:
      pkiSvc server --ca-pub=<pub-file> --ca-priv=<priv-file> [-l <address>]

    Options:
      --ca-pub=<pub-file>              CA public key
      --ca-priv=<priv-file>            CA private key
      -l <address>,--listen <address>  Listen in this address [default: 0.0.0.0:5050]
)";

int main(int argc, char *argv[]) {
  auto args = docopt::docopt(USAGE, {argv + 1, argv + argc}, true, "pkiSvc");

  std::string listen(args["--listen"].asString());

  RegisterImpl service;
  if (!service.LoadCA(args["--ca-pub"].asString(),
                      args["--ca-priv"].asString())) {
    std::cout << "failed to load CA" << std::endl;
    return 1;
  }

  ServerBuilder builder;

  builder.AddListeningPort(listen, grpc::InsecureServerCredentials());
  builder.RegisterService(&service);

  std::unique_ptr<Server> server(builder.BuildAndStart());
  std::cout << "at=start service=grpc listen=" << listen << "\n";

  server->Wait();
  return 0;
}
