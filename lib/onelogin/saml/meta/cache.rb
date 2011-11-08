module Onelogin::Saml
class Metadata
  class Cache
    
    def initialize
      @hash = {}
    end
    
    def read(id)
      document = @hash[id]
		#Logging.debug("READ id: #{id} document: #{document}")
      unless document.nil?() || document.expires_in < Time.now
        return document.file
      end
      return nil
    end
    
    def write(id, file, expiration)
		#Logging.debug("expiration: #{expiration}  id: #{id}  file: #{file} ")
      document = Document.new(id, file, Time.now + expiration)
      @hash[id] = document
      return true
    end
  end
end
end