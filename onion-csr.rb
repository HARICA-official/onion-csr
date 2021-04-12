#!/usr/bin/ruby

# SPDX-FileCopyrightText: 2021 Antonios Eleftheriadis <antoniose@harica.gr>
# SPDX-FileCopyrightText: 2021 HARICA <ca@harica.gr>
# SPDX-License-Identifier: GPL-3.0-or-later

# frozen_string_literal: true

require 'optparse'
require 'openssl'
require 'securerandom'
require './ed25519'

params = {
  'hs-dir': '/var/lib/tor/hidden_service'
}
OptionParser.new do |opts|
  opts.banner = "Usage:  #{$PROGRAM_NAME} -n 4841524943413C336F6E696F6E73 [other options]"

  opts.on('-d', '--hs-dir HS-directory', 'Path to the hidden service directory')

  opts.on('-n', '--ca-nonce NONCE', 'CA provided signing nonce in HEX e.g 4841524943413C336F6E696F6E73')

  opts.on('-h', '--help', 'Prints this help') do
    puts opts
    exit
  end
end.parse! into: params

# Check that a CA signing nonce has been provided
abort 'You need to at least provide a CA signing nonce' unless params[:'ca-nonce']

# Read the HS hostname if no FQDN list was provided
hostname = File.read("#{params[:'hs-dir']}/hostname").strip

# Load Hidden Service identity key
hs_private_key = File.read("#{params[:'hs-dir']}/hs_ed25519_secret_key")[32..-1]
hs_public_key = File.read("#{params[:'hs-dir']}/hs_ed25519_public_key")[32..-1]

# Create CSR
req = OpenSSL::X509::Request.new

# Add nonce attributes
req.add_attribute OpenSSL::X509::Attribute.new '2.23.140.41',
                                               OpenSSL::ASN1::Set(
                                                 [
                                                   OpenSSL::ASN1::OctetString([params[:'ca-nonce']].pack('H*'))
                                                 ]
                                               )
applicant_signing_nonce = SecureRandom.bytes 10 # The BRs require at least 64bits of entropy, so we generate 80
req.add_attribute OpenSSL::X509::Attribute.new '2.23.140.42',
                                               OpenSSL::ASN1::Set([OpenSSL::ASN1::OctetString(applicant_signing_nonce)])

# Add SAN extension
req.add_attribute OpenSSL::X509::Attribute.new 'extReq', OpenSSL::ASN1::Set(
  [
    OpenSSL::ASN1::Sequence([OpenSSL::X509::ExtensionFactory.new.create_extension('subjectAltName', "DNS:#{hostname}")])
  ]
)

# Decode the CSR and get the certificationRequestInfo
certificate_request = OpenSSL::ASN1.decode req
# ASN.1 definition of CertificationRequest from RFC 2986
# CertificationRequest ::= SEQUENCE {
#      certificationRequestInfo CertificationRequestInfo,
#      signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
#      signature          BIT STRING
# }
certification_request_info = certificate_request.value[0]

# Add the public key
# ASN.1 definitions of CertificationRequestInfo, SubjectPublicKeyInfo and AlgorithmIdentifier from RFC 2986
# CertificationRequestInfo ::= SEQUENCE {
#      version       INTEGER { v1(0) } (v1,...),
#      subject       Name,
#      subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
#      attributes    [0] Attributes{{ CRIAttributes }}
# }
# SubjectPublicKeyInfo {ALGORITHM: IOSet} ::= SEQUENCE {
#      algorithm        AlgorithmIdentifier {{IOSet}},
#      subjectPublicKey BIT STRING
# }
# AlgorithmIdentifier {ALGORITHM:IOSet } ::= SEQUENCE {
#      algorithm  ALGORITHM.&id({IOSet}),
#      parameters ALGORITHM.&Type({IOSet}{@algorithm}) OPTIONAL
# }
certification_request_info.value[2].value[0].value << OpenSSL::ASN1::ObjectId('ED25519')
certification_request_info.value[2].value[1].value = hs_public_key

# Sign DER certificationRequestInfo with Ed25519
der_cri = certification_request_info.to_der
sig = FFI::Buffer.new 64
Ed25519.ed25519_sign sig, der_cri, der_cri.bytesize, hs_public_key, hs_private_key

# Add CSR signature
certificate_request.value[1].value << OpenSSL::ASN1::ObjectId('ED25519')
certificate_request.value[2].value = sig.read_bytes 64

req = OpenSSL::X509::Request.new certificate_request
puts req
