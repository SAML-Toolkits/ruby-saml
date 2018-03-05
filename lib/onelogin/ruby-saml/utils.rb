module OneLogin
  module RubySaml

    # SAML2 Auxiliary class
    #
    class Utils
      # Given a REXML::Element instance, return the concatenation of all child text nodes. Assumes
      # that there all children other than text nodes can be ignored (e.g. comments). If nil is
      # passed, nil will be returned.
      def self.element_text(element)
        element.texts.map(&:value).join if element
      end
    end
  end
end
