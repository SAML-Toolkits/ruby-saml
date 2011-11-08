module Onelogin::Saml
class Metadata
  class Document
    attr_accessor :id, :file, :expires_in
    def initialize(id, file, expires_in)
      @id = id
      @file = file
      @expires_in = expires_in
    end
    
    def time
      # convert to time
    end
  end
end
end