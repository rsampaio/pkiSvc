#include <iostream>

#include "client.h"

int main(int argc, char *argv[]) {
  // gRPC clients take a channel which takes the address of
  // the server and credentials for this service.
  client::PkiClient cli(grpc::CreateChannel(
      "localhost:5050", grpc::InsecureChannelCredentials()));

  cli.CreateIdentity("cooldomain.io");
  return 0;
}
