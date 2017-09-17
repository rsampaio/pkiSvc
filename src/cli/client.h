#ifndef CLIENT_H
#define CLIENT_H

#include <memory>
#include <string>

#include <grpc++/grpc++.h>

#include "pki.grpc.pb.h"

using grpc::ClientContext;
using grpc::Status;
using grpc::ChannelInterface;

using pki::Certificate;
using pki::Identity;
using pki::Register;

namespace client {
class PkiClient {
public:
  PkiClient(std::shared_ptr<ChannelInterface> channel)
      : stub_(Register::NewStub(channel)){};
  void CreateIdentity(const std::string &hostname);

private:
  std::unique_ptr<Register::Stub> stub_;
};
}

#endif
