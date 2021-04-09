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
  'hs-dir': '/var/lib/tor/hidden_service',
  'priv-key': 'privkey.pem'
}
OptionParser.new do |opts|
  opts.banner = "Usage:  #{$PROGRAM_NAME} -n 4841524943414752 [other options]"

  opts.on('-d', '--hs-dir HS-directory', 'Path to the hidden service directory')

  opts.on('-f', '--dns-names FQDNs', 'Comma-separated list of FQDNs to include as DNSNames')

  opts.on('-n', '--ca-nonce NONCE', 'CA provided signing nonce in HEX e.g 4841524943414752')

  opts.on('-p', '--priv-key privkey.pem', 'File to read an existing private key or to write a new one')

  opts.on('-h', '--help', 'Prints this help') do
    puts opts
    exit
  end
end.parse! into: params

# Check that a CA signing nonce has been provided
abort 'You need to at least provide a CA signing nonce' unless params[:'ca-nonce']

# Read the HS hostname if no FQDN list was provided
params[:'dns-names'] = File.read("#{params[:'hs-dir']}/hostname").strip unless params[:'dns-names']

# Load Hidden Service identity key
hs_private_key = File.read("#{params[:'hs-dir']}/hs_ed25519_secret_key")[32..-1]
hs_public_key = File.read("#{params[:'hs-dir']}/hs_ed25519_public_key")[32..-1]

begin
  # Try to load existing private key
  priv_key = OpenSSL::PKey.read File.open params[:'priv-key']
rescue Errno::ENOENT
  # Generate new P-256 key
  priv_key = OpenSSL::PKey::EC.generate 'prime256v1'

  # Write the new private key to the specified file
  File.write params[:'priv-key'], priv_key.to_pem
end

# Create CSR
req = OpenSSL::X509::Request.new
req.public_key = priv_key

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
    OpenSSL::ASN1::Sequence(
      [
        OpenSSL::X509::ExtensionFactory.new.create_extension(
          'subjectAltName', params[:'dns-names'].split(',').map { |d| "DNS:#{d}" }.join(',')
        )
      ]
    )
  ]
)

# Sign the CSR
req.sign priv_key, OpenSSL::Digest.new('SHA256')
puts "Normal CSR:\n#{req}"

# Decode the CSR and get the DER encoded certificationRequestInfo
certificate_request = OpenSSL::ASN1.decode req
# ASN.1 definition of CertificationRequest from RFC 2986
# CertificationRequest ::= SEQUENCE {
#      certificationRequestInfo CertificationRequestInfo,
#      signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
#      signature          BIT STRING
# }
certification_request_info = certificate_request.value[0].to_der

# Sign DER certificationRequestInfo with Ed25519
sig = FFI::Buffer.new 64
Ed25519.ed25519_sign sig, certification_request_info, certification_request_info.bytesize, hs_public_key, hs_private_key

# Replace CSR signature
certificate_request.value[1].value[0].value = 'ED25519'
certificate_request.value[1].value.delete_at 1 # Remove NULL parameters in case of RSA keys
certificate_request.value[2].value = sig.read_bytes 64

req = OpenSSL::X509::Request.new certificate_request
puts "CSR signed with HS private key:\n#{req}"
