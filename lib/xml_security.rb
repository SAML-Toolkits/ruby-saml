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
require 'nokogiri'
require "digest/sha1"
require "digest/sha2"
require "onelogin/ruby-saml/validation_error"

module XMLSecurity

  class SignedDocument < REXML::Document
    C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
    DSIG = "http://www.w3.org/2000/09/xmldsig#"

    attr_accessor :signed_element_id

    def initialize(response)
      super(response)
      extract_signed_element_id
    end

    def validate(idp_cert_fingerprint, soft = true)
      # get cert from response
      cert_element = REXML::XPath.first(self, "//ds:X509Certificate", { "ds"=>DSIG })
      raise Onelogin::Saml::ValidationError.new("Certificate element missing in response (ds:X509Certificate)") unless cert_element
      base64_cert  = cert_element.text
      cert_text    = Base64.decode64(base64_cert)
      cert         = OpenSSL::X509::Certificate.new(cert_text)

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
      inclusive_namespaces = extract_inclusive_namespaces

      document = Nokogiri.parse(self.to_s)

      # create a working copy so we don't modify the original
      @working_copy ||= REXML::Document.new(self.to_s).root

      # store and remove signature node
      @sig_element ||= begin
        element = REXML::XPath.first(@working_copy, "//ds:Signature", {"ds"=>DSIG})
        element.remove
      end


      # verify signature
      signed_info_element     = REXML::XPath.first(@sig_element, "//ds:SignedInfo", {"ds"=>DSIG})
      noko_sig_element = document.at_xpath('//ds:Signature', 'ds' => DSIG)
      noko_signed_info_element = noko_sig_element.at_xpath('./ds:SignedInfo', 'ds' => DSIG)
      canon_algorithm = canon_algorithm REXML::XPath.first(@sig_element, '//ds:CanonicalizationMethod', 'ds' => DSIG)
      canon_string = noko_signed_info_element.canonicalize(canon_algorithm)
      noko_sig_element.remove

      # check digests
      REXML::XPath.each(@sig_element, "//ds:Reference", {"ds"=>DSIG}) do |ref|
        uri                           = ref.attributes.get_attribute("URI").value

        hashed_element                = document.at_xpath("//*[@ID='#{uri[1..-1]}']")
        canon_algorithm               = canon_algorithm REXML::XPath.first(ref, '//ds:CanonicalizationMethod', 'ds' => DSIG)
        canon_hashed_element          = hashed_element.canonicalize(canon_algorithm, inclusive_namespaces)

        digest_algorithm              = algorithm(REXML::XPath.first(ref, "//ds:DigestMethod"))

        hash                          = digest_algorithm.digest(canon_hashed_element)
        digest_value                  = Base64.decode64(REXML::XPath.first(ref, "//ds:DigestValue", {"ds"=>DSIG}).text)

        unless digests_match?(hash, digest_value)
          return soft ? false : (raise Onelogin::Saml::ValidationError.new("Digest mismatch"))
        end
      end

      base64_signature        = REXML::XPath.first(@sig_element, "//ds:SignatureValue", {"ds"=>DSIG}).text
      signature               = Base64.decode64(base64_signature)

      # get certificate object
      cert_text               = Base64.decode64(base64_cert)
      cert                    = OpenSSL::X509::Certificate.new(cert_text)

      # signature method
      signature_algorithm     = algorithm(REXML::XPath.first(signed_info_element, "//ds:SignatureMethod", {"ds"=>DSIG}))

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

    def canon_algorithm(element)
      algorithm = element.attribute('Algorithm').value if element
      case algorithm
        when "http://www.w3.org/2001/10/xml-exc-c14n#"         then Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
        when "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" then Nokogiri::XML::XML_C14N_1_0
        when "http://www.w3.org/2006/12/xml-c14n11"            then Nokogiri::XML::XML_C14N_1_1
        else                                                        Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
      end
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

    def extract_inclusive_namespaces
      if element = REXML::XPath.first(self, "//ec:InclusiveNamespaces", { "ec" => C14N })
        prefix_list = element.attributes.get_attribute("PrefixList").value
        prefix_list.split(" ")
      else
        []
      end
    end

  end
end
