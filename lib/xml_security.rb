# The contents of this file are subject to the terms
# of the Common Development and Distribution License
# (the License). You may not use this file except in
# compliance with the License.
#
# You can obtain a copy of the License at
# https://opensso.dev.java.net/public/CDDLv1.0.html or
# opensso/legal/CDDLv1.0.txt
# See the License for the specific language governing
# permission and limitations under the License.
#
# When distributing Covered Code, include this CDDL
# Header Notice in each file and include the License file
# at opensso/legal/CDDLv1.0.txt.
# If applicable, add the following below the CDDL Header,
# with the fields enclosed by brackets [] replaced by
# your own identifying information:
# "Portions Copyrighted [year] [name of copyright owner]"
#
# $Id: xml_sec.rb,v 1.6 2007/10/24 00:28:41 todddd Exp $
#
# Copyright 2007 Sun Microsystems Inc. All Rights Reserved
# Portions Copyrighted 2007 Todd W Saxton.

require 'rubygems'
require "rexml/document"
require "rexml/xpath"
require "openssl"
require "xmlcanonicalizer"
require "digest/sha1"
require "digest/sha2"
require "onelogin/ruby-saml/validation_error"

module XMLSecurity

  class SignedDocument < REXML::Document
    DSIG = "http://www.w3.org/2000/09/xmldsig#"

    attr_accessor :signed_element_id

    def initialize(response)
      super(response)
      extract_signed_element_id
    end

    def validate(idp_cert_fingerprint, soft = true)
      # get cert from response
      base64_cert = REXML::XPath.first(self, "//ds:X509Certificate").text
      cert_text   = Base64.decode64(base64_cert)
      cert        = OpenSSL::X509::Certificate.new(cert_text)

      # check cert matches registered idp cert
      fingerprint = Digest::SHA1.hexdigest(cert.to_der)

      if fingerprint != idp_cert_fingerprint.gsub(/[^a-zA-Z0-9]/,"").downcase
        return soft ? false : (raise Onelogin::Saml::ValidationError.new("Fingerprint mismatch"))
      end

      validate_doc(base64_cert, soft)
    end

    def validate_doc(base64_cert, soft = true)
      # validate references

      # check for inclusive namespaces

      inclusive_namespaces            = []
      inclusive_namespace_element     = REXML::XPath.first(self, "//ec:InclusiveNamespaces")

      if inclusive_namespace_element
        prefix_list                   = inclusive_namespace_element.attributes.get_attribute('PrefixList').value
        inclusive_namespaces          = prefix_list.split(" ")
      end

      # remove signature node
      sig_element = REXML::XPath.first(self, "//ds:Signature", {"ds"=>DSIG})
      sig_element.remove

      # check digests
      REXML::XPath.each(sig_element, "//ds:Reference", {"ds"=>DSIG}) do |ref|
        uri                           = ref.attributes.get_attribute("URI").value
        hashed_element                = REXML::XPath.first(self, "//[@ID='#{uri[1..-1]}']")
        canoner                       = XML::Util::XmlCanonicalizer.new(false, true)
        canoner.inclusive_namespaces  = inclusive_namespaces if canoner.respond_to?(:inclusive_namespaces) && !inclusive_namespaces.empty?
        canon_hashed_element          = canoner.canonicalize(hashed_element).gsub('&','&amp;')
        digest_algorithm              = algorithm(REXML::XPath.first(ref, "//ds:DigestMethod"))
        hash                          = digest_algorithm.digest(canon_hashed_element)
        digest_value                  = Base64.decode64(REXML::XPath.first(ref, "//ds:DigestValue", {"ds"=>DSIG}).text)

        unless digests_match?(hash, digest_value)
          return soft ? false : (raise Onelogin::Saml::ValidationError.new("Digest mismatch"))
        end
      end

      # verify signature
      canoner                 = XML::Util::XmlCanonicalizer.new(false, true)
      signed_info_element     = REXML::XPath.first(sig_element, "//ds:SignedInfo", {"ds"=>DSIG})
      canon_string            = canoner.canonicalize(signed_info_element)

      base64_signature        = REXML::XPath.first(sig_element, "//ds:SignatureValue", {"ds"=>DSIG}).text
      signature               = Base64.decode64(base64_signature)

      # get certificate object
      cert_text               = Base64.decode64(base64_cert)
      cert                    = OpenSSL::X509::Certificate.new(cert_text)

      # signature method
      signature_algorithm     = algorithm(REXML::XPath.first(signed_info_element, "//ds:SignatureMethod"))

      unless cert.public_key.verify(signature_algorithm.new, signature, canon_string)
        return soft ? false : (raise Onelogin::Saml::ValidationError.new("Key validation error"))
      end

      return true
    end

    private

    def digests_match?(hash, digest_value)
      hash == digest_value
    end

    def extract_signed_element_id
      reference_element       = REXML::XPath.first(self, "//ds:Signature/ds:SignedInfo/ds:Reference", {"ds"=>DSIG})
      self.signed_element_id  = reference_element.attribute("URI").value[1..-1] unless reference_element.nil?
    end

    def algorithm(element)
      algorithm = element.attribute("Algorithm").value if element
      algorithm = algorithm && algorithm =~ /sha(.*?)$/i && $1.to_i
      case algorithm
      when 256 then OpenSSL::Digest::SHA256
      when 384 then OpenSSL::Digest::SHA384
      when 512 then OpenSSL::Digest::SHA512
      else
        OpenSSL::Digest::SHA1
      end
    end

  end
end
