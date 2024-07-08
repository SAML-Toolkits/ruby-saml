require 'openssl'

module CertificateHelper
  extend self

  def generate_pair(not_before: nil, not_after: nil)
    key = generate_key
    cert = generate_cert(key, not_before: not_before, not_after: not_after)
    [cert, key]
  end

  def generate_pair_hash(not_before: nil, not_after: nil)
    cert, key = generate_pair(not_before: not_before, not_after: not_after)
    { certificate: cert.to_pem, private_key: key.to_pem }
  end

  def generate_key
    OpenSSL::PKey::RSA.new(1024)
  end

  def generate_cert(key = generate_key, not_before: nil, not_after: nil)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 0
    cert.not_before = not_before || Time.now - one_year
    cert.not_after  = not_after  || Time.now + one_year
    cert.public_key = key.public_key
    cert.subject = OpenSSL::X509::Name.parse "/DC=org/DC=ruby-saml/CN=Ruby SAML CA"
    cert.issuer = cert.subject # self-signed
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = cert
    cert.add_extension factory.create_extension("basicConstraints","CA:TRUE", true)
    cert.add_extension factory.create_extension("keyUsage","keyCertSign, cRLSign", true)
    cert.sign(key, OpenSSL::Digest::SHA1.new)
    cert
  end

  private

  def one_year
    3600 * 24 * 365
  end
end
