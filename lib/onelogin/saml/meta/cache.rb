module Onelogin::Saml
class Metadata
  class Cache
    
    def initialize
      @hash = {}
    end
    
    def read(id)
      document = @hash[id]
      unless document.nil?() || document.time > Time.new
        return document.file
      end
      return nil
    end
    
    def write(id, file)
      document = Document.new(id, file, Time.now)
      @hash[id] = document
      return true
    end
  end
end
end