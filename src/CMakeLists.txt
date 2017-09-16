include(ExternalProject)

ExternalProject_Add(grpc_project
  GIT_REPOSITORY "https://github.com/grpc/grpc.git"
  GIT_TAG "v1.6.0"
  GIT_SUBMODULES ""
  INSTALL_COMMAND ""
  UPDATE_COMMAND ""
  BUILD_COMMAND
    ${CMAKE_COMMAND} --build . --config ${CMAKE_BUILD_TYPE} --target grpc++_unsecure &&
    ${CMAKE_COMMAND} --build . --config ${CMAKE_BUILD_TYPE} --target protoc &&
    ${CMAKE_COMMAND} --build . --config ${CMAKE_BUILD_TYPE} --target grpc_cpp_plugin
  CMAKE_CACHE_ARGS
    -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
    -DCMAKE_VERBOSE_MAKEFILE:BOOL=OFF)

ExternalProject_Get_Property(grpc_project binary_dir)
ExternalProject_Get_Property(grpc_project source_dir)

set(gRPC_BINARY ${binary_dir})
set(gRPC_SOURCE ${source_dir})

include_directories("${gRPC_SOURCE}/include")
include_directories("${gRPC_SOURCE}/third_party/protobuf/src")

if(MSVC)
  set(PROTOC_COMMAND "${gRPC_BINARY}/third_party/protobuf/Release/protoc.exe")
  get_filename_component(gRPC_CPP_PLUGIN_EXECUTABLE "${gRPC_BINARY}/Release/grpc_cpp_plugin.exe" ABSOLUTE)
  set(gRPC_LIBS
    ${gRPC_BINARY}/Release/grpc++_unsecure.lib
    ${gRPC_BINARY}/Release/grpc_unsecure.lib
    ${gRPC_BINARY}/Release/gpr.lib
    ${gRPC_BINARY}/third_party/protobuf/Release/libprotobuf.lib
    ${gRPC_BINARY}/third_party/cares/Release/cares.lib
    ${gRPC_BINARY}/third_party/zlib/Release/zlibstatic.lib
    ws2_32.lib #seriously?
    )
else()
  set(PROTOC_COMMAND "${gRPC_BINARY}/third_party/protobuf/protoc")
  get_filename_component(gRPC_CPP_PLUGIN_EXECUTABLE "${gRPC_BINARY}/grpc_cpp_plugin" ABSOLUTE)
  set(gRPC_LIBS
    ${gRPC_BINARY}/libgrpc++_unsecure.a
    ${gRPC_BINARY}/libgrpc_unsecure.a
    ${gRPC_BINARY}/libgpr.a
    ${gRPC_BINARY}/third_party/protobuf/libprotobuf.a
    ${gRPC_BINARY}/third_party/cares/libcares.a
    pthread z
    )
endif()

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

get_filename_component(pki_proto "../proto/pki.proto" ABSOLUTE)
get_filename_component(pki_proto_path "${pki_proto}" PATH)

message(STATUS "proto file: ${pki_proto}")

# Generate .pb.h and .pb.cc files
#protobuf_generate_cpp(pki_proto_srcs pki_proto_hdrs "${pki_proto}")
set(pki_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/pki.pb.cc")
set(pki_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/pki.pb.h")
add_custom_command(
  OUTPUT "${pki_proto_srcs}" "${pki_proto_hdrs}"
  COMMAND "${PROTOC_COMMAND}"
  ARGS --cpp_out "${CMAKE_CURRENT_BINARY_DIR}" -I "${pki_proto_path}" -I "${gRPC_SOURCE}/third_party/protobuf/src"
  "${pki_proto}"
  DEPENDS "${pki_proto}")


# Generate .grpc.pb.h and .grpc.pb.cc
set(pki_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/pki.grpc.pb.cc")
set(pki_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/pki.grpc.pb.h")
add_custom_command(
  OUTPUT "${pki_grpc_srcs}" "${pki_grpc_hdrs}"
  COMMAND "${PROTOC_COMMAND}"
  ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}" -I "${pki_proto_path}" -I "${gRPC_SOURCE}/third_party/protobuf/src"
  --plugin=protoc-gen-grpc="${gRPC_CPP_PLUGIN_EXECUTABLE}"
  "${pki_proto}"
  DEPENDS "${pki_proto}")

# Generated include directory
include_directories("${CMAKE_CURRENT_BINARY_DIR}")
aux_source_directory("${CMAKE_CURRENT_SOURCE_DIR}" pki_srcs)
add_executable(pkiSvc
  "${pki_srcs}"
  "${pki_proto_srcs}" "${pki_grpc_srcs}")

target_link_libraries(pkiSvc "${gRPC_LIBS}" OpenSSL::SSL)

# Generated include directory
include_directories("${CMAKE_CURRENT_BINARY_DIR}/cli")
aux_source_directory("${CMAKE_CURRENT_SOURCE_DIR}/cli" pki_cli_srcs)
add_executable(pkiCli
  "${pki_cli_srcs}"
  "${pki_proto_srcs}" "${pki_grpc_srcs}")

target_link_libraries(pkiCli ${gRPC_LIBS} OpenSSL::SSL)
