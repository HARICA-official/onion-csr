#!/usr/bin/ruby

# SPDX-FileCopyrightText: 2021-2024 Antonios Eleftheriadis <antonisel@harica.gr>
# SPDX-FileCopyrightText: 2021-2024 HARICA <ca@harica.gr>
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
  opts.banner = "Usage:  #{$PROGRAM_NAME} -n NONCE [other options]"

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

# Create AlgorithmIdentifier for Ed25519 public keys and signatures
# ASN.1 definition of AlgorithmIdentifier from RFC 2986
# AlgorithmIdentifier {ALGORITHM:IOSet } ::= SEQUENCE {
#      algorithm  ALGORITHM.&id({IOSet}),
#      parameters ALGORITHM.&Type({IOSet}{@algorithm}) OPTIONAL
# }
alg_id = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId('ED25519')])

# Create SubjectPublicKeyInfo
# ASN.1 definition of SubjectPublicKeyInfo from RFC 2986
# SubjectPublicKeyInfo {ALGORITHM: IOSet} ::= SEQUENCE {
#      algorithm        AlgorithmIdentifier {{IOSet}},
#      subjectPublicKey BIT STRING
# }
spki = OpenSSL::ASN1::Sequence([alg_id, OpenSSL::ASN1::BitString(hs_public_key)])

# Create nonce attributes
ca_nonce = OpenSSL::X509::Attribute.new '2.23.140.41',
                                        OpenSSL::ASN1::Set(
                                          [
                                            OpenSSL::ASN1::OctetString([params[:'ca-nonce']].pack('H*'))
                                          ]
                                        )
applicant_signing_nonce = SecureRandom.bytes 10 # The BRs require at least 64bits of entropy, so we generate 80
applicant_signing_nonce = OpenSSL::X509::Attribute.new '2.23.140.42',
                                                       OpenSSL::ASN1::Set(
                                                         [
                                                           OpenSSL::ASN1::OctetString(applicant_signing_nonce)
                                                         ]
                                                       )

# Create SAN extension
san = OpenSSL::X509::Attribute.new 'extReq', OpenSSL::ASN1::Set(
  [
    OpenSSL::ASN1::Sequence([OpenSSL::X509::ExtensionFactory.new.create_extension('subjectAltName', "DNS:#{hostname}")])
  ]
)

# Create certificationRequestInfo
# ASN.1 definitions of CertificationRequestInfo and Attributes from RFC 2986
# CertificationRequestInfo ::= SEQUENCE {
#      version       INTEGER { v1(0) } (v1,...),
#      subject       Name,
#      subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
#      attributes    [0] Attributes{{ CRIAttributes }}
# }
# Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
certification_request_info = OpenSSL::ASN1::Sequence(
  [
    OpenSSL::ASN1::Integer(0), OpenSSL::X509::Name.new, spki,
    OpenSSL::ASN1::Set([applicant_signing_nonce, ca_nonce, san], 0, :IMPLICIT)
  ]
)

# Sign DER certificationRequestInfo with Ed25519
der_cri = certification_request_info.to_der
sig = FFI::Buffer.new 64
Ed25519.ed25519_sign sig, der_cri, der_cri.bytesize, hs_public_key, hs_private_key

# Create CSR
# ASN.1 definition of CertificationRequest from RFC 2986
# CertificationRequest ::= SEQUENCE {
#      certificationRequestInfo CertificationRequestInfo,
#      signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
#      signature          BIT STRING
# }
certificate_request = OpenSSL::ASN1::Sequence(
  [
    certification_request_info, alg_id, OpenSSL::ASN1::BitString(sig.read_bytes(64))
  ]
)

req = OpenSSL::X509::Request.new certificate_request
puts req
