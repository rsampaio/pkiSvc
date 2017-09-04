set(protobuf_MODULE_COMPATIBLE ON CACHE BOOL "")
find_package(Protobuf CONFIG REQUIRED)

message(STATUS "using protobuf ${protobuf_VERSION}")

find_package(gRPC REQUIRED)
message(STATUS "using grpc ${gRPC_VERSION}")

# gRPC C++ plugin
get_target_property(gRPC_CPP_PLUGIN_EXECUTABLE gRPC::grpc_cpp_plugin
  IMPORTED_LOCATION_RELEASE)

get_filename_component(pki_proto "../proto/pki.proto" ABSOLUTE)
get_filename_component(pki_proto_path "${pki_proto}" PATH)

# Generate .pb.h and .pb.cc files
protobuf_generate_cpp(pki_proto_srcs pki_proto_hdrs "${pki_proto}")

# Generate .grpc.pb.h and .grpc.pb.cc
set(pki_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/pki.grpc.pb.cc")
set(pki_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/pki.grpc.pb.h")
add_custom_command(
  OUTPUT "${pki_grpc_srcs}" "${pki_grpc_hdrs}"
  COMMAND protobuf::protoc
  ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}" -I "${pki_proto_path}"
  --plugin=protoc-gen-grpc="${gRPC_CPP_PLUGIN_EXECUTABLE}"
  "${pki_proto}"
  DEPENDS "${pki_proto}")

# Generated include directory
include_directories("${CMAKE_CURRENT_BINARY_DIR}")
aux_source_directory("${CMAKE_CURRENT_SOURCE_DIR}" pki_srcs)
add_executable(pkiSvc
  "${pki_srcs}"
  "${pki_proto_srcs}" "${pki_grpc_srcs}")

target_link_libraries(pkiSvc protobuf::libprotobuf gRPC::grpc++ )

# Generated include directory
include_directories("${CMAKE_CURRENT_BINARY_DIR}/cli")
aux_source_directory("${CMAKE_CURRENT_SOURCE_DIR}/cli" pki_cli_srcs)
add_executable(pkiCli
  "${pki_cli_srcs}"
  "${pki_proto_srcs}" "${pki_grpc_srcs}")

target_link_libraries(pkiCli protobuf::libprotobuf gRPC::grpc++ )
