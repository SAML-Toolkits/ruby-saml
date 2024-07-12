require 'openssl'

module CertificateHelper
  extend self

  def generate_pair(algorithm = :rsa, digest: nil, not_before: nil, not_after: nil)
    key = generate_private_key(algorithm)
    cert = generate_cert(key, digest: digest, not_before: not_before, not_after: not_after)
    [cert, key]
  end

  def generate_pem_array(algorithm = :rsa, not_before: nil, not_after: nil)
    generate_pair(algorithm, not_before: not_before, not_after: not_after).map(&:to_pem)
  end

  def generate_pem_hash(algorithm = :rsa, not_before: nil, not_after: nil)
    cert, key = generate_pem_array(algorithm, not_before: not_before, not_after: not_after)
    { certificate: cert, private_key: key }
  end

  def generate_cert(private_key = :rsa, digest: nil, not_before: nil, not_after: nil)
    key = generate_private_key(private_key)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 0
    cert.not_before = not_before || Time.now - one_year
    cert.not_after  = not_after  || Time.now + one_year
    cert.public_key = generate_public_key(key)
    cert.subject = OpenSSL::X509::Name.parse "/DC=org/DC=ruby-saml/CN=Ruby SAML CA"
    cert.issuer = cert.subject # self-signed
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = cert
    cert.add_extension factory.create_extension("basicConstraints","CA:TRUE", true)
    cert.add_extension factory.create_extension("keyUsage","keyCertSign, cRLSign", true)
    cert.sign(key, generate_digest(digest))
    cert
  end

  def generate_private_key(algorithm = :rsa)
    case algorithm
    when OpenSSL::PKey::PKey
      algorithm
    when :dsa
      OpenSSL::PKey::DSA.new(2048)
    when :ec, :ecdsa
      OpenSSL::PKey::EC.generate('prime256v1')
    else
      OpenSSL::PKey::RSA.new(2048)
    end
  end

  def generate_public_key(private_key)
    private_key.is_a?(OpenSSL::PKey::EC) ? private_key : private_key.public_key
  end

  def generate_digest(digest)
    case digest
    when OpenSSL::Digest then digest
    when NilClass then OpenSSL::Digest.new('SHA256')
    else OpenSSL::Digest.new(digest.to_s.upcase)
    end
  end

  private

  def one_year
    3600 * 24 * 365
  end
end
