#include <iostream>

#include "client.h"

static const char USAGE[] = R"(pkiCli.
   Usage:
     pkiCli gencert -H <hostname> [-c <country>] [-s <state>] [-o <org>]
     pkiCli gencsr -H <hostname> [-c <country>] [-s <state>] [-o <org>]

   Options:
     -H <hostname>, --hostname=<hostname>  Host name to issue certificate or CSR.
     -c <country>, --country=<country>     Country name [default: US].
     -s <state>, --state=<state>           State or City [default: San Francisco].
     -o <org>, --org=<org>                 Organization Name [default: YOrg].
)";

int main(int argc, char *argv[]) {
  // gRPC clients take a channel which takes the address of
  // the server and credentials for this service.
  client::PkiClient cli(grpc::CreateChannel(
      "localhost:5050", grpc::InsecureChannelCredentials()));

  // std::vector<std::string, docopt::value> args = ...
  auto args = docopt::docopt(USAGE, {argv + 1, argv + argc}, true, "pkiCli");

  if (args["gencert"].asBool() || args["gencsr"].asBool()) {
    // Required options
    std::string hostname(args["--hostname"].asString());
    std::string country(args["--country"].asString());
    std::string state(args["--state"].asString());
    std::string org(args["--org"].asString());

    CertificateOptions co;
    co.set_hostname(hostname);
    co.set_country(country);
    co.set_state(state);
    co.set_org(org);

    if (args["gencert"].asBool()) {
      cli.CreateIdentity(co);
    }

    if (args["gencsr"].asBool()) {
      cli.CreateCSR(co);
    }
  }
  return 1;
}
