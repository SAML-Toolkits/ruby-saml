

module RubySaml
  module DeprecatedMessageMixin
    def warn_deprecated_message
      klass = self.class
      warn "[DEPRECATION] #{klass} is deprecated. Please use #{klass.superclass} instead."
    end
  end

  class Authrequest < RubySaml::Messages::Sp::AuthnRequest
    include DeprecatedMessageMixin

    def initialize
      warn_deprecated_message
      super
    end
  end

  class Logoutrequest < RubySaml::Messages::Sp::LogoutRequest
    include DeprecatedMessageMixin

    def initialize
      warn_deprecated_message
      super
    end
  end

  class SloLogoutresponse < RubySaml::Messages::Sp::LogoutResponse
    include DeprecatedMessageMixin

    def initialize
      warn_deprecated_message
      super
    end
  end

  # class Response < RubySaml::Messages::Idp::Response
  #   include DeprecatedMessageMixin
  #
  #   def initialize(...)
  #     warn_deprecated_message
  #     super
  #   end
  # end
  #
  #
  # class Logoutresponse < RubySaml::Messages::Idp::LogoutResponse
  #   include DeprecatedMessageMixin
  #
  #   def initialize(...)
  #     warn_deprecated_message
  #     super
  #   end
  # end
  #
  # class SloLogoutrequest < RubySaml::Messages::Idp::LogoutRequest
  #   include DeprecatedMessageMixin
  #
  #   def initialize(...)
  #     warn_deprecated_message
  #     super
  #   end
  # end
end
