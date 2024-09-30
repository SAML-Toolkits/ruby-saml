# frozen_string_literal: true

require_relative 'test_helper'

class PemFormatterTest < Minitest::Test
  BASE64_RAW = "\t \n\n\rR290 IGEgbG9uZyBsaX  N0IG9mIG\rV4LWx/dmVycwpUaGV  5J2xsIHR" \
               "l\n bGwgeW91  IqE+bSBpbn\t NhbmUKQnV0IE\r\nkndmUgZ  2/0IGEgYmxhbmsgc" \
               "3BhY+UsIGJhY nkKQW5kIEkn/Gwgd3\npdG UgeW91ciBuYW1l \n\r\n"
  BASE64_OUT = <<~BASE64.strip
                 R290IGEgbG9uZyBsaXN0IG9mIGV4LWx/dmVycwpUaGV5J2xsIHRlbGwgeW91IqE+
                 bSBpbnNhbmUKQnV0IEkndmUgZ2/0IGEgYmxhbmsgc3BhY+UsIGJhYnkKQW5kIEkn
                 /Gwgd3pdGUgeW91ciBuYW1l
               BASE64

  describe RubySaml::PemFormatter do
    def build_pem(label, body)
      "-----BEGIN #{label}-----\n#{body}\n-----END #{label}-----"
    end

    def build_cert(body)
      build_pem('CERTIFICATE', body)
    end

    def build_pkey(body)
      build_pem('PRIVATE KEY', body)
    end

    describe '.format_cert_array and .format_cert' do
      it 'returns nil for nil input' do
        input = nil

        assert_empty RubySaml::PemFormatter.format_cert_array(input)
        assert_nil RubySaml::PemFormatter.format_cert(input)
      end

      it 'returns nil for whitespace inputs without modifying the input' do
        ['', '    ', "\n\n", "\n \t\r"].each do |whitespace|
          input = whitespace.dup

          assert_empty RubySaml::PemFormatter.format_cert_array(input)
          assert_nil RubySaml::PemFormatter.format_cert(input)
          assert_equal input, whitespace
        end
      end

      it 'returns nil for empty array input' do
        input = []

        assert_empty RubySaml::PemFormatter.format_cert_array(input)
        assert_nil RubySaml::PemFormatter.format_cert(input)
      end

      it 'returns nil for array of whitespace strings input without modifying the input' do
        array = ['', '    ', "\n\n", "\n \t\r"]
        input = array.map(&:dup)

        assert_empty RubySaml::PemFormatter.format_cert_array(input)
        assert_nil RubySaml::PemFormatter.format_cert(input)
        assert_equal input, array
      end

      it 'returns nil for missing PEM body' do
        input = build_cert('')

        assert_empty RubySaml::PemFormatter.format_cert_array(input)
        assert_nil RubySaml::PemFormatter.format_cert(input)
      end

      it 'returns nil for blank PEM body' do
        input = build_cert("\n \t\r")

        assert_empty RubySaml::PemFormatter.format_cert_array(input)
        assert_nil RubySaml::PemFormatter.format_cert(input)
      end

      it 'formats a single valid PEM without modifying the input' do
        raw_pem = build_pem(" \n TRUSTED \tX509 \n\r CERTIFICATE  \n", BASE64_RAW)
        input = raw_pem.dup
        expected = build_cert(BASE64_OUT)

        assert_equal [expected], RubySaml::PemFormatter.format_cert_array(input)
        assert_equal expected, RubySaml::PemFormatter.format_cert(input)
        assert_equal expected, RubySaml::PemFormatter.format_cert(input, multi: true)
        assert_equal input, raw_pem
      end

      it 'formats multiple PEMs without modifying the input' do
        multi = "\n#{build_cert(BASE64_RAW)}\n #{build_pem("\t \nXXX \t\n\r CERTIFICATE \n ", 'F00==')}  \n"
        input = multi.dup
        expected_ary = [build_cert(BASE64_OUT), build_cert('F00==')]
        expected_one = expected_ary.first
        expected_mul = expected_ary.join("\n")

        assert_equal expected_ary, RubySaml::PemFormatter.format_cert_array(input)
        assert_equal expected_one, RubySaml::PemFormatter.format_cert(input)
        assert_equal expected_mul, RubySaml::PemFormatter.format_cert(input, multi: true)
        assert_equal input, multi
      end

      it 'formats array of PEMs without modifying the input' do
        array = ["\n#{build_cert(BASE64_RAW)}\n  ", "\t#{build_pem("\t \nXXX \t\n\r CERTIFICATE \n ", 'F00==')}  \n"]
        input = array.map(&:dup)
        expected_ary = [build_cert(BASE64_OUT), build_cert('F00==')]
        expected_one = expected_ary.first
        expected_mul = expected_ary.join("\n")

        assert_equal expected_ary, RubySaml::PemFormatter.format_cert_array(input)
        assert_equal expected_one, RubySaml::PemFormatter.format_cert(input)
        assert_equal expected_mul, RubySaml::PemFormatter.format_cert(input, multi: true)
        assert_equal input, array
      end

      it 'ignores non-cert PEMs when multiple PEMs are given' do
        multi = "#{build_pkey('BAR=')}\n#{build_cert(BASE64_RAW)}\n #{build_cert("\n")} #{build_pkey('BAZ')} " \
                     "#{build_pem("\t \nXXX \t\n\r CERTIFICATE \n ", 'F00==')}  #{build_pkey('QUX==')}\n"
        input = multi.dup
        expected_ary = [build_cert(BASE64_OUT), build_cert('F00==')]
        expected_one = expected_ary.first
        expected_mul = expected_ary.join("\n")

        assert_equal expected_ary, RubySaml::PemFormatter.format_cert_array(input)
        assert_equal expected_one, RubySaml::PemFormatter.format_cert(input)
        assert_equal expected_mul, RubySaml::PemFormatter.format_cert(input, multi: true)
        assert_equal input, multi
      end

      it 'ignores non-cert PEMs array of PEMs is given' do
        array = [build_pkey('BAR='),
                 "#{build_cert("\n")} \n#{build_cert(BASE64_RAW)}\n #{build_pkey('BAZ')} ",
                 build_pkey('BAZ'),
                 "\t#{build_pem("\t \nXXX \t\n\r CERTIFICATE \n ", 'F00==')}  \n",
                 build_pkey('QUX==')]
        input = array.map(&:dup)
        expected_ary = [build_cert(BASE64_OUT), build_cert('F00==')]
        expected_one = expected_ary.first
        expected_mul = expected_ary.join("\n")

        assert_equal expected_ary, RubySaml::PemFormatter.format_cert_array(input)
        assert_equal expected_one, RubySaml::PemFormatter.format_cert(input)
        assert_equal expected_mul, RubySaml::PemFormatter.format_cert(input, multi: true)
        assert_equal input, array
      end

      it 'formats multiple PEMs with non-ASCII chars outside' do
        multi = "おはよう#{build_cert(BASE64_RAW)}こんにちは#{build_cert('F00==')}おやすみ"
        input = multi.dup
        expected_ary = [build_cert(BASE64_OUT), build_cert('F00==')]
        expected_one = expected_ary.first
        expected_mul = expected_ary.join("\n")

        assert_equal expected_ary, RubySaml::PemFormatter.format_cert_array(input)
        assert_equal expected_one, RubySaml::PemFormatter.format_cert(input)
        assert_equal expected_mul, RubySaml::PemFormatter.format_cert(input, multi: true)
        assert_equal input, multi
      end

      it 'formats PEM without headers' do
        input = BASE64_RAW
        expected = build_cert(BASE64_OUT)

        assert_equal [expected], RubySaml::PemFormatter.format_cert_array(input)
        assert_equal expected, RubySaml::PemFormatter.format_cert(input)
      end

      it 'returns nil for non-ASCII input without headers' do
        input = "非ASCII証明書#{BASE64_RAW}"

        assert_empty RubySaml::PemFormatter.format_cert_array(input)
        assert_nil RubySaml::PemFormatter.format_cert(input)
      end

      it 'returns nil for non-ASCII inside PEM body' do
        input = build_cert("非ASCII証明書#{BASE64_RAW}")

        assert_empty RubySaml::PemFormatter.format_cert_array(input)
        assert_nil RubySaml::PemFormatter.format_cert(input)
      end

      it 'formats PEM with begin but no end' do
        input = "-----BEGIN CERTIFICATE-----\n#{BASE64_RAW}"
        expected = build_cert(BASE64_OUT)

        assert_equal [expected], RubySaml::PemFormatter.format_cert_array(input)
        assert_equal expected, RubySaml::PemFormatter.format_cert(input)
      end

      it 'formats PEM with end but no begin' do
        input = "#{BASE64_RAW}\n-----END CERTIFICATE-----"
        expected = build_cert(BASE64_OUT)

        assert_equal [expected], RubySaml::PemFormatter.format_cert_array(input)
        assert_equal expected, RubySaml::PemFormatter.format_cert(input)
      end

      it 'allows extra whitespace inside headers' do
        input = "----- \r  BEGIN  \n\n\n \tCERTIFICATE \r -----\n#{BASE64_RAW}\n-----END   CERTIFICATE -----"
        expected = build_cert(BASE64_OUT)

        assert_equal [expected], RubySaml::PemFormatter.format_cert_array(input)
        assert_equal expected, RubySaml::PemFormatter.format_cert(input)
      end

      it 'does not allow non-standard header labels' do
        [build_pem('CERT', BASE64_OUT),
         build_pem('CERT XXX', BASE64_OUT)].each do |input|
          assert_empty RubySaml::PemFormatter.format_private_key_array(input)
          assert_nil RubySaml::PemFormatter.format_private_key(input)
        end
      end

      it 'does not allow spaces inside header words' do
        input = build_pem('CERT IFICATE', BASE64_OUT)

        assert_empty RubySaml::PemFormatter.format_private_key_array(input)
        assert_nil RubySaml::PemFormatter.format_private_key(input)
      end

      it 'requires spaces between header words' do
        [build_cert(BASE64_OUT).gsub('BEGIN CERTIFICATE', 'BEGINCERTIFICATE'),
         build_cert(BASE64_OUT).gsub('END CERTIFICATE', 'ENDCERTIFICATE'),
         build_pem('XXX CERTIFICATE', BASE64_OUT).gsub('BEGIN XXX', 'BEGINXXX'),
         build_pem('XXX CERTIFICATE', BASE64_OUT).gsub('END XXX', 'ENDXXX')].each do |input|
          assert_empty RubySaml::PemFormatter.format_private_key_array(input)
          assert_nil RubySaml::PemFormatter.format_private_key(input)
        end
      end

      it 'normalizes labels' do
        input = "-----BEGIN \nTRUSTED \tX509 \n\r CERTIFICATE  \n-----\n#{BASE64_RAW}\n----- \tEND\t X509 CERTIFICATE -----"
        expected = build_cert(BASE64_OUT)

        assert_equal [expected], RubySaml::PemFormatter.format_cert_array(input)
        assert_equal expected, RubySaml::PemFormatter.format_cert(input)
      end

      it 'returns nil if BEGIN is missing' do
        input = "-----CERTIFICATE-----\n#{BASE64_OUT}\n-----END CERTIFICATE-----"

        assert_empty RubySaml::PemFormatter.format_cert_array(input)
        assert_nil RubySaml::PemFormatter.format_cert(input)
      end

      it 'returns nil if END is missing' do
        input = "-----BEGIN CERTIFICATE-----\n#{BASE64_OUT}\n-----CERTIFICATE-----"

        assert_empty RubySaml::PemFormatter.format_cert_array(input)
        assert_nil RubySaml::PemFormatter.format_cert(input)
      end

      it 'returns nil if wrong hyphens' do
        cert = build_cert(BASE64_OUT)
        ['----', '------', '-- ---', "---\n--"].each do |dashes|
          input = cert.gsub(/-{5}/, dashes)

          assert_empty RubySaml::PemFormatter.format_cert_array(input)
          assert_nil RubySaml::PemFormatter.format_cert(input)
        end
      end

      it 'ignores comments' do
        input = "# This is a comment\n#{build_cert(BASE64_RAW)}\n# Another comment"
        expected = build_cert(BASE64_OUT)

        assert_equal [expected], RubySaml::PemFormatter.format_cert_array(input)
        assert_equal expected, RubySaml::PemFormatter.format_cert(input)
      end

      it 'ignores private keys' do
        input = build_pkey(BASE64_OUT)

        assert_empty RubySaml::PemFormatter.format_cert_array(input)
        assert_nil RubySaml::PemFormatter.format_cert(input)
      end

      it 'returns nil when PEM body contains equal sign not at end' do
        ['=ABCDEF', 'ABC=DEF', 'ABC+=DEF', " AB C\n=\nDEF ", "=\nABCDEF"].each do |input|
          assert_empty RubySaml::PemFormatter.format_cert_array(input)
          assert_empty RubySaml::PemFormatter.format_cert_array(build_cert(input))
          assert_nil RubySaml::PemFormatter.format_cert(input)
          assert_nil RubySaml::PemFormatter.format_cert(build_cert(input))
        end
      end

      it 'allows PEM body to contain one equal sign at end' do
        expected = build_cert('AbC+DEf=')
        ['AbC+DEf=', 'AbC+DEf =', "\t A\nbC\t+DEf \t= \n"].each do |input|
          assert_equal [expected], RubySaml::PemFormatter.format_cert_array(input)
          assert_equal [expected], RubySaml::PemFormatter.format_cert_array(build_cert(input))
          assert_equal expected, RubySaml::PemFormatter.format_cert(input)
          assert_equal expected, RubySaml::PemFormatter.format_cert(build_cert(input))
        end
      end

      it 'allows PEM body to contain two equal signs at end' do
        expected = build_cert('aBC+DEf==')
        ['aBC+DEf==', 'aBC+DEf= =', 'aBC+DEf = =', "\t a\nBC+\tDEf \t=\t= \n"].each do |input|
          assert_equal [expected], RubySaml::PemFormatter.format_cert_array(input)
          assert_equal [expected], RubySaml::PemFormatter.format_cert_array(build_cert(input))
          assert_equal expected, RubySaml::PemFormatter.format_cert(input)
          assert_equal expected, RubySaml::PemFormatter.format_cert(build_cert(input))
        end
      end

      it 'does not format when PEM body contains three equal signs at end' do
        ['ABCDEF===', 'ABCDEF = = ='].each do |input|
          assert_empty RubySaml::PemFormatter.format_cert_array(input)
          assert_empty RubySaml::PemFormatter.format_cert_array(build_cert(input))
          assert_nil RubySaml::PemFormatter.format_cert(input)
          assert_nil RubySaml::PemFormatter.format_cert(build_cert(input))
        end
      end

      it 'formats PEM to exactly 64 characters per line' do
        input = 'A' * 130
        expected = build_cert("#{('A' * 64)}\n#{('A' * 64)}\nAA")

        assert_equal [expected], RubySaml::PemFormatter.format_cert_array(input)
        assert_equal [expected], RubySaml::PemFormatter.format_cert_array(build_cert(input))
        assert_equal expected, RubySaml::PemFormatter.format_cert(input)
        assert_equal expected, RubySaml::PemFormatter.format_cert(build_cert(input))
      end
    end

    describe '.format_private_key_array and .format_private_key' do
      it 'returns nil for nil input' do
        input = nil

        assert_empty RubySaml::PemFormatter.format_private_key_array(input)
        assert_nil RubySaml::PemFormatter.format_private_key(input)
      end

      it 'returns nil for whitespace inputs without modifying the input' do
        ['', '    ', "\n\n", "\n \t\r"].each do |whitespace|
          input = whitespace.dup

          assert_empty RubySaml::PemFormatter.format_private_key_array(input)
          assert_nil RubySaml::PemFormatter.format_private_key(input)
          assert_equal input, whitespace
        end
      end

      it 'returns nil for empty array input' do
        input = []

        assert_empty RubySaml::PemFormatter.format_private_key_array(input)
        assert_nil RubySaml::PemFormatter.format_private_key(input)
      end

      it 'returns nil for array of whitespace strings input without modifying the input' do
        array = ['', '    ', "\n\n", "\n \t\r"]
        input = array.map(&:dup)

        assert_empty RubySaml::PemFormatter.format_private_key_array(input)
        assert_nil RubySaml::PemFormatter.format_private_key(input)
        assert_equal input, array
      end

      it 'returns nil for missing PEM body' do
        input = build_pkey('')

        assert_empty RubySaml::PemFormatter.format_private_key_array(input)
        assert_nil RubySaml::PemFormatter.format_private_key(input)
      end

      it 'returns nil for blank PEM body' do
        input = build_pkey("\n \t\r")

        assert_empty RubySaml::PemFormatter.format_private_key_array(input)
        assert_nil RubySaml::PemFormatter.format_private_key(input)
      end

      it 'formats a single valid PEM without modifying the input' do
        raw_pem = build_pem(" \n TRUSTED \tX509 \n\r PRIVATE \t\r KEY  \n", BASE64_RAW)
        input = raw_pem.dup
        expected = build_pkey(BASE64_OUT)

        assert_equal [expected], RubySaml::PemFormatter.format_private_key_array(input)
        assert_equal expected, RubySaml::PemFormatter.format_private_key(input)
        assert_equal expected, RubySaml::PemFormatter.format_private_key(input, multi: true)
        assert_equal input, raw_pem
      end

      it 'formats multiple PEMs without modifying the input' do
        multi = "\n#{build_pkey(BASE64_RAW)}\n #{build_pem("\t \nXXX\t\n\rPRIVATE\n\nKEY \n ", 'F00==')}  \n"
        input = multi.dup
        expected_ary = [build_pkey(BASE64_OUT), build_pkey('F00==')]
        expected_one = expected_ary.first
        expected_mul = expected_ary.join("\n")

        assert_equal expected_ary, RubySaml::PemFormatter.format_private_key_array(input)
        assert_equal expected_one, RubySaml::PemFormatter.format_private_key(input)
        assert_equal expected_mul, RubySaml::PemFormatter.format_private_key(input, multi: true)
        assert_equal input, multi
      end

      it 'formats array of PEMs without modifying the input' do
        array = ["\n#{build_pkey(BASE64_RAW)}\n  ", "\t#{build_pem("\t \nXXX \t\n\r PRIVATE KEY \n ", 'F00==')}  \n"]
        input = array.map(&:dup)
        expected_ary = [build_pkey(BASE64_OUT), build_pkey('F00==')]
        expected_one = expected_ary.first
        expected_mul = expected_ary.join("\n")

        assert_equal expected_ary, RubySaml::PemFormatter.format_private_key_array(input)
        assert_equal expected_one, RubySaml::PemFormatter.format_private_key(input)
        assert_equal expected_mul, RubySaml::PemFormatter.format_private_key(input, multi: true)
        assert_equal input, array
      end

      it 'ignores non-private key PEMs when multiple PEMs are given' do
        multi = "#{build_cert('BAR=')}\n#{build_pkey(BASE64_RAW)}\n #{build_pkey("\n")} #{build_cert('BAZ')} " \
                "#{build_pem("\t \nXXX \t\n\r PRIVATE KEY \n ", 'F00==')}  #{build_cert('QUX==')}\n"
        input = multi.dup
        expected_ary = [build_pkey(BASE64_OUT), build_pkey('F00==')]
        expected_one = expected_ary.first
        expected_mul = expected_ary.join("\n")

        assert_equal expected_ary, RubySaml::PemFormatter.format_private_key_array(input)
        assert_equal expected_one, RubySaml::PemFormatter.format_private_key(input)
        assert_equal expected_mul, RubySaml::PemFormatter.format_private_key(input, multi: true)
        assert_equal input, multi
      end

      it 'ignores non-cert PEMs array of PEMs is given' do
        array = [build_cert('BAR='),
                 "#{build_pkey("\n")} \n#{build_pkey(BASE64_RAW)}\n #{build_cert('BAZ')} ",
                 build_cert('BAZ'),
                 "\t#{build_pem("\t \nXXX \t\n\r PRIVATE KEY \n ", 'F00==')}  \n",
                 build_cert('QUX==')]
        input = array.map(&:dup)
        expected_ary = [build_pkey(BASE64_OUT), build_pkey('F00==')]
        expected_one = expected_ary.first
        expected_mul = expected_ary.join("\n")

        assert_equal expected_ary, RubySaml::PemFormatter.format_private_key_array(input)
        assert_equal expected_one, RubySaml::PemFormatter.format_private_key(input)
        assert_equal expected_mul, RubySaml::PemFormatter.format_private_key(input, multi: true)
        assert_equal input, array
      end

      it 'formats multiple PEMs with non-ASCII chars outside' do
        multi = "おはよう#{build_pkey(BASE64_RAW)}こんにちは#{build_pkey('F00==')}おやすみ"
        input = multi.dup
        expected_ary = [build_pkey(BASE64_OUT), build_pkey('F00==')]
        expected_one = expected_ary.first
        expected_mul = expected_ary.join("\n")

        assert_equal expected_ary, RubySaml::PemFormatter.format_private_key_array(input)
        assert_equal expected_one, RubySaml::PemFormatter.format_private_key(input)
        assert_equal expected_mul, RubySaml::PemFormatter.format_private_key(input, multi: true)
        assert_equal input, multi
      end

      it 'formats PEM without headers' do
        input = BASE64_RAW
        expected = build_pkey(BASE64_OUT)

        assert_equal [expected], RubySaml::PemFormatter.format_private_key_array(input)
        assert_equal expected, RubySaml::PemFormatter.format_private_key(input)
      end

      it 'returns nil for non-ASCII input without headers' do
        input = "非ASCII証明書#{BASE64_RAW}"

        assert_empty RubySaml::PemFormatter.format_private_key_array(input)
        assert_nil RubySaml::PemFormatter.format_private_key(input)
      end

      it 'returns nil for non-ASCII inside PEM body' do
        input = build_pkey("非ASCII証明書#{BASE64_RAW}")

        assert_empty RubySaml::PemFormatter.format_private_key_array(input)
        assert_nil RubySaml::PemFormatter.format_private_key(input)
      end

      it 'formats PEM with begin but no end' do
        input = "-----BEGIN PRIVATE KEY-----\n#{BASE64_RAW}"
        expected = build_pkey(BASE64_OUT)

        assert_equal [expected], RubySaml::PemFormatter.format_private_key_array(input)
        assert_equal expected, RubySaml::PemFormatter.format_private_key(input)
      end

      it 'formats PEM with end but no begin' do
        input = "#{BASE64_RAW}\n-----END PRIVATE KEY-----"
        expected = build_pkey(BASE64_OUT)

        assert_equal [expected], RubySaml::PemFormatter.format_private_key_array(input)
        assert_equal expected, RubySaml::PemFormatter.format_private_key(input)
      end

      it 'returns nil if wrong hyphens' do
        pkey = build_pkey(BASE64_OUT)
        ['----', '------', '-- ---', "---\n--"].each do |dashes|
          input = pkey.gsub(/-{5}/, dashes)

          assert_empty RubySaml::PemFormatter.format_private_key_array(input)
          assert_nil RubySaml::PemFormatter.format_private_key(input)
        end
      end

      it 'allows extra whitespace inside headers' do
        input = "----- \r  BEGIN  \n\n\n \tPRIVATE\n\nKEY \r -----\n#{BASE64_RAW}\n-----END   PRIVATE\n KEY -----"
        expected = build_pkey(BASE64_OUT)

        assert_equal [expected], RubySaml::PemFormatter.format_private_key_array(input)
        assert_equal expected, RubySaml::PemFormatter.format_private_key(input)
      end

      it 'does not allow non-standard header labels' do
        [build_pem('PKEY', BASE64_OUT),
         build_pem('PRIVATE KEY XXX', BASE64_OUT)].each do |input|
          assert_empty RubySaml::PemFormatter.format_private_key_array(input)
          assert_nil RubySaml::PemFormatter.format_private_key(input)
        end
      end

      it 'does not allow spaces inside header words' do
        [build_pem('PRI VATE KEY', BASE64_OUT),
         build_pem('RSA PRIVATE KE Y', BASE64_OUT)].each do |input|
          assert_empty RubySaml::PemFormatter.format_private_key_array(input)
          assert_nil RubySaml::PemFormatter.format_private_key(input)
        end
      end

      it 'requires spaces between header words' do
        [build_pkey(BASE64_OUT).gsub('BEGIN PRIVATE', 'BEGINPRIVATE'),
         build_pkey(BASE64_OUT).gsub('END PRIVATE', 'ENDPRIVATE'),
         build_pem('PRIVATEKEY', BASE64_OUT),
         build_pem('RSAPRIVATE KEY', BASE64_OUT),
         build_pem('RSA PRIVATE KEY', BASE64_OUT).gsub('BEGIN RSA', 'BEGINRSA'),
         build_pem('RSA PRIVATE KEY', BASE64_OUT).gsub('END RSA', 'ENDRSA')].each do |input|
          assert_empty RubySaml::PemFormatter.format_private_key_array(input)
          assert_nil RubySaml::PemFormatter.format_private_key(input)
        end
      end

      it 'normalizes labels' do
        input = "-----BEGIN \nXXX \n\r PRIVATE KEY  \n-----\n#{BASE64_RAW}\n----- \tEND\t XXX PRIVATE KEY -----"
        expected = build_pkey(BASE64_OUT)

        assert_equal [expected], RubySaml::PemFormatter.format_private_key_array(input)
        assert_equal expected, RubySaml::PemFormatter.format_private_key(input)
      end

      it 'returns nil if BEGIN is missing' do
        input = "-----PRIVATE KEY-----\n#{BASE64_OUT}\n-----END PRIVATE KEY-----"

        assert_empty RubySaml::PemFormatter.format_private_key_array(input)
        assert_nil RubySaml::PemFormatter.format_private_key(input)
      end

      it 'returns nil if END is missing' do
        input = "-----BEGIN PRIVATE KEY-----\n#{BASE64_OUT}\n-----PRIVATE KEY-----"

        assert_empty RubySaml::PemFormatter.format_private_key_array(input)
        assert_nil RubySaml::PemFormatter.format_private_key(input)
      end

      it 'ignores comments' do
        input = "# This is a comment\n#{build_pkey(BASE64_RAW)}\n# Another comment"
        expected = build_pkey(BASE64_OUT)

        assert_equal [expected], RubySaml::PemFormatter.format_private_key_array(input)
        assert_equal expected, RubySaml::PemFormatter.format_private_key(input)
      end

      it 'ignores certs' do
        input = build_cert(BASE64_OUT)

        assert_empty RubySaml::PemFormatter.format_private_key_array(input)
        assert_nil RubySaml::PemFormatter.format_private_key(input)
      end

      it 'returns nil when PEM body contains equal sign not at end' do
        ['=ABCDEF', 'ABC=DEF', 'ABC+=DEF', " AB C\n=\nDEF ", "=\nABCDEF"].each do |input|
          assert_empty RubySaml::PemFormatter.format_private_key_array(input)
          assert_empty RubySaml::PemFormatter.format_private_key_array(build_pkey(input))
          assert_nil RubySaml::PemFormatter.format_private_key(input)
          assert_nil RubySaml::PemFormatter.format_private_key(build_pkey(input))
        end
      end

      it 'allows PEM body to contain one equal sign at end' do
        expected = build_pkey('AbC+DEf=')
        ['AbC+DEf=', 'AbC+DEf =', "\t A\nbC\t+DEf \t= \n"].each do |input|
          assert_equal [expected], RubySaml::PemFormatter.format_private_key_array(input)
          assert_equal [expected], RubySaml::PemFormatter.format_private_key_array(build_pkey(input))
          assert_equal expected, RubySaml::PemFormatter.format_private_key(input)
          assert_equal expected, RubySaml::PemFormatter.format_private_key(build_pkey(input))
        end
      end

      it 'allows PEM body to contain two equal signs at end' do
        expected = build_pkey('aBC+DEf==')
        ['aBC+DEf==', 'aBC+DEf= =', 'aBC+DEf = =', "\t a\nBC+\tDEf \t=\t= \n"].each do |input|
          assert_equal [expected], RubySaml::PemFormatter.format_private_key_array(input)
          assert_equal [expected], RubySaml::PemFormatter.format_private_key_array(build_pkey(input))
          assert_equal expected, RubySaml::PemFormatter.format_private_key(input)
          assert_equal expected, RubySaml::PemFormatter.format_private_key(build_pkey(input))
        end
      end

      it 'does not format when PEM body contains three equal signs at end' do
        ['ABCDEF===', 'ABCDEF = = ='].each do |input|
          assert_empty RubySaml::PemFormatter.format_private_key_array(input)
          assert_empty RubySaml::PemFormatter.format_private_key_array(build_pkey(input))
          assert_nil RubySaml::PemFormatter.format_private_key(input)
          assert_nil RubySaml::PemFormatter.format_private_key(build_pkey(input))
        end
      end

      it 'formats PEM to exactly 64 characters per line' do
        input = 'A' * 130
        expected = build_pkey("#{('A' * 64)}\n#{('A' * 64)}\nAA")

        assert_equal [expected], RubySaml::PemFormatter.format_private_key_array(input)
        assert_equal [expected], RubySaml::PemFormatter.format_private_key_array(build_pkey(input))
        assert_equal expected, RubySaml::PemFormatter.format_private_key(input)
        assert_equal expected, RubySaml::PemFormatter.format_private_key(build_pkey(input))
      end

      %w[RSA ECDSA EC DSA].each do |algo|
        it "preserves #{algo} in label" do
          input = build_pem("FOO \t #{algo}   PRIVATE\n KEY", BASE64_RAW)
          expected = build_pem("#{algo} PRIVATE KEY", BASE64_OUT)

          assert_equal [expected], RubySaml::PemFormatter.format_private_key_array(input)
          assert_equal expected, RubySaml::PemFormatter.format_private_key(input)
        end

        it "preserves #{algo} in label if it appears at end" do
          input = "-----BEGIN PRIVATE KEY-----\n#{BASE64_RAW}\n-----END  #{algo} PRIVATE KEY-----"
          expected = build_pem("#{algo} PRIVATE KEY", BASE64_OUT)

          assert_equal [expected], RubySaml::PemFormatter.format_private_key_array(input)
          assert_equal expected, RubySaml::PemFormatter.format_private_key(input)
        end
      end

      it 'removes unknown private key header prefix' do
        input = build_pem('  XXX   PRIVATE  KEY', BASE64_RAW)
        expected = build_pem('PRIVATE KEY', BASE64_OUT)

        assert_equal [expected], RubySaml::PemFormatter.format_private_key_array(input)
        assert_equal expected, RubySaml::PemFormatter.format_private_key(input)
      end
    end
  end
end
