FROM ruby:3-bullseye

RUN apt-get install gcc

WORKDIR /opt
RUN git clone --recurse-submodules https://github.com/HARICA-official/onion-csr.git

WORKDIR /opt/onion-csr
RUN gem install ffi && \
    gcc -shared -o libed25519.so -fPIC ed25519/src/*.c

CMD ["ruby", "onion-csr.rb"]
