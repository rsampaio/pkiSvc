find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

find_package(gtest REQUIRED)
include_directories(${gtest_INCLUDE_DIRS})

enable_testing()

add_executable(pkiTest main.cc cert.cc ../src/cert.cc)
target_link_libraries(pkiTest ${GTEST_BOTH_LIBRARIES} OpenSSL::SSL)
add_test(
  NAME    pkiTest
  COMMAND pkiTest)
