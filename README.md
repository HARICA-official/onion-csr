# onion-csr.rb

A tool that generates CSRs that are appropriate for use with method 2.b of appendix B of the [CA/B forum's Baseline Requirements version 1.7.4](https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.7.4.pdf)

## Requirements
* Ruby
* [Ruby-FFI](https://github.com/ffi/ffi)
* GCC

## Installation
1. Clone this repository  
`git clone --recurse-submodules https://github.com/HARICA-official/onion-csr.git && cd onion-csr`
2. Install the FFI gem  
`gem install ffi`
3. Build the Ed25519 shared library  
`gcc -shared -o libed25519.so -fPIC ed25519/src/*.c`

## Usage
```
./onion-csr.rb -h
Usage:  ./onion-csr.rb -n 4841524943413C336F6E696F6E73 [other options]
    -d, --hs-dir HS-directory        Path to the hidden service directory
    -f, --dns-names FQDNs            Comma-separated list of FQDNs to include as DNSNames
    -n, --ca-nonce NONCE             CA provided signing nonce in HEX e.g 4841524943413C336F6E696F6E73
    -p, --priv-key privkey.pem       File to read an existing private key or to write a new one
    -h, --help                       Prints this help
```
