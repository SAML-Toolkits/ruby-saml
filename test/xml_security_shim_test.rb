# frozen_string_literal: true

require_relative 'test_helper'
require 'xml_security'

class XMLSecurityTest < Minitest::Test
  def test_base_document_inherits_from_rexml_document
    assert_kind_of REXML::Document, XMLSecurity::BaseDocument.new
  end

  def test_base_document_constants
    assert_equal RubySaml::XML::C14N, XMLSecurity::BaseDocument::C14N
    assert_equal RubySaml::XML::DSIG, XMLSecurity::BaseDocument::DSIG
    assert_equal RubySaml::XML::NOKOGIRI_OPTIONS, XMLSecurity::BaseDocument::NOKOGIRI_OPTIONS
  end

  def test_base_document_canon_algorithm_delegates_to_ruby_saml_xml
    algorithm = 'http://example.org/algorithm'
    RubySaml::XML.expects(:canon_algorithm).with(algorithm).returns('canon_result')

    doc = XMLSecurity::BaseDocument.new
    result = doc.canon_algorithm(algorithm)

    assert_equal 'canon_result', result
  end

  def test_base_document_algorithm_delegates_to_ruby_saml_xml
    algorithm = 'http://example.org/algorithm'
    RubySaml::XML.expects(:hash_algorithm).with(algorithm).returns('hash_result')

    doc = XMLSecurity::BaseDocument.new
    result = doc.algorithm(algorithm)

    assert_equal 'hash_result', result
  end

  def test_document_inherits_from_base_document
    assert_kind_of XMLSecurity::BaseDocument, XMLSecurity::Document.new('<root/>')
  end

  def test_document_constants
    assert_equal RubySaml::XML::DocumentSigner::INC_PREFIX_LIST, XMLSecurity::Document::INC_PREFIX_LIST
    assert_equal RubySaml::XML::RSA_SHA1, XMLSecurity::Document::RSA_SHA1
    assert_equal RubySaml::XML::RSA_SHA224, XMLSecurity::Document::RSA_SHA224
    assert_equal RubySaml::XML::RSA_SHA256, XMLSecurity::Document::RSA_SHA256
    assert_equal RubySaml::XML::RSA_SHA384, XMLSecurity::Document::RSA_SHA384
    assert_equal RubySaml::XML::RSA_SHA512, XMLSecurity::Document::RSA_SHA512
    assert_equal RubySaml::XML::DSA_SHA1, XMLSecurity::Document::DSA_SHA1
    assert_equal RubySaml::XML::DSA_SHA256, XMLSecurity::Document::DSA_SHA256
    assert_equal RubySaml::XML::ECDSA_SHA1, XMLSecurity::Document::ECDSA_SHA1
    assert_equal RubySaml::XML::ECDSA_SHA224, XMLSecurity::Document::ECDSA_SHA224
    assert_equal RubySaml::XML::ECDSA_SHA256, XMLSecurity::Document::ECDSA_SHA256
    assert_equal RubySaml::XML::ECDSA_SHA384, XMLSecurity::Document::ECDSA_SHA384
    assert_equal RubySaml::XML::ECDSA_SHA512, XMLSecurity::Document::ECDSA_SHA512
    assert_equal RubySaml::XML::SHA1, XMLSecurity::Document::SHA1
    assert_equal RubySaml::XML::SHA224, XMLSecurity::Document::SHA224
    assert_equal RubySaml::XML::SHA256, XMLSecurity::Document::SHA256
    assert_equal RubySaml::XML::SHA384, XMLSecurity::Document::SHA384
    assert_equal RubySaml::XML::SHA512, XMLSecurity::Document::SHA512
    assert_equal RubySaml::XML::ENVELOPED_SIG, XMLSecurity::Document::ENVELOPED_SIG
  end

  def test_document_sign_document_raises_no_method_error
    doc = XMLSecurity::Document.new("<root/>")
    assert_raises(::NoMethodError) { doc.sign_document }
  end

  def test_signed_document_inherits_from_base_document
    assert_kind_of XMLSecurity::BaseDocument, XMLSecurity::SignedDocument.new("<root/>")
  end

  def test_signed_document_validate_document_raises_no_method_error
    doc = XMLSecurity::SignedDocument.new("<root/>")
    assert_raises(::NoMethodError) { doc.validate_document }
  end

  def test_signed_document_extract_inclusive_namespaces_raises_no_method_error
    doc = XMLSecurity::SignedDocument.new("<root/>")
    assert_raises(::NoMethodError) { doc.extract_inclusive_namespaces }
  end
end
