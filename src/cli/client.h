#ifndef CLIENT_H
#define CLIENT_H

#include <memory>
#include <string>

#include <grpc++/grpc++.h>

#include "docopt.h"

#include "json.hpp"

#include "pki.grpc.pb.h"

using grpc::ClientContext;
using grpc::Status;
using grpc::ChannelInterface;

using pki::Certificate;
using pki::CertificateOptions;
using pki::CSR;
using pki::Register;

using json = nlohmann::json;

namespace client {
class PkiClient {
public:
  PkiClient(std::shared_ptr<ChannelInterface> channel)
      : stub_(Register::NewStub(channel)){};
  void CreateIdentity(const CertificateOptions &co);
  void CreateCSR(const CertificateOptions &co);

private:
  std::unique_ptr<Register::Stub> stub_;
};
}

#endif
