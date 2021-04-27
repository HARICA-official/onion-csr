# onion-csr.rb

A tool that generates CSRs that are appropriate for use with method 2.b of appendix B of the [CA/B forum's Baseline Requirements version 1.7.4](https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.7.4.pdf)

## Requirements
* Ruby (Ubuntu: ruby, ruby-dev)
* [Ruby-FFI](https://github.com/ffi/ffi)
* GCC (Ubuntu: build-essential)

## Installation
1. Clone this repository  
`git clone --recurse-submodules https://github.com/HARICA-official/onion-csr.git && cd onion-csr`
2. Install the FFI gem  
`sudo gem install ffi`
3. Build the Ed25519 shared library  
`gcc -shared -o libed25519.so -fPIC ed25519/src/*.c`

## Usage
```
./onion-csr.rb -h
Usage:  ./onion-csr.rb -n 4841524943413C336F6E696F6E73 [other options]
    -d, --hs-dir HS-directory        Path to the hidden service directory
    -n, --ca-nonce NONCE             CA provided signing nonce in HEX e.g 4841524943413C336F6E696F6E73
    -h, --help                       Prints this help
```
e.g. for Ubuntu users: `sudo -u debian-tor ./onion-csr.rb -n 736F6D65206361207369676E696E67206E6F6E6365 -d /var/lib/tor/other_hidden_service`
