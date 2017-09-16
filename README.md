The goal of this project is to practice C++14 and learn how to use OpenSSL APIs to generate RSA keypairs, X509 certificates and CSR.

# pkiSvc

*pkiSvc* is a mini CA/Certificate manager grpc service that generates RSA keypair and use them to sign CSR (Certificate Sign Request) or used as public key of X509 certificate signed by a the CA

# Build

## Linux

Install dependencies: `cmake build-essential clang libssl-dev`
```shell
mkdir build && cd build && cmake ..
cmake --build .
```

## Windows

Use `vcpkg` to install dependencies:

```shell
vcpkg install openssl:x64-windows-static
```

Build using vcpkg:

```shell
mkdir build
cd build
cmake .. -G "Visual Studio 15 2017 Win64" -DCMAKE_TOOLCHAIN_FILE=YOUR_VCPKG_INSTALL\scripts\buildsystems\vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build .
```


# Things I've learned in this project

## C++14

- Modern C++ has some interesting features that makes the development very pleasant.
- `std::unique_ptr` is really neat, saved me a few `delete` and `free` calls.
  `std::unique_ptr` is a smart pointer and is automatically freed when the object gets out of scope reducing the boilerplate of free and delete after use, `std::make_unique` in combination with `auto` can also be very handy on char pointers as well.
  Smart pointers are tricky to use with OpenSSL functions that re-use the reference and manages memory by itself like `EVP_PKEY_assign_rsa` instead of `EVP_PKEY_set1_RSA` functions, the former uses the reference internally and free when the object is freed, the later will copy the parameter to an internel reference.
- If you're not using or your prefered language doesn't have a formatter, I'm sorry for you, `clang-fmt` works beautifuly and gives me the exact same experience as `gofmt`.

# OpenSSL

- `BIO` is memory area for binary I/O similar to file, in OpenSSL API the output is usualy a file or `BIO` pointer, they should be freed after used (or they will be freed if you use `unique_ptr` :))
- PEM format is very well supported, you can read and write PEM format to files or memory pretty easily.
- `RSA_generate_key` is deprecated.
- Keys (both private and public) are usually mapped to `EVP_PKEY` structs.

# TODO

- [ ] Add more stuff to the readme
- [ ] Figure out a way to connect to k8s API with modern C++
- [ ] Integrate somehow with k8s custom resources.
