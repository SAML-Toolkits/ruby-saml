# Simplistic log class when we're running in Rails
module Onelogin::Saml
	class Logging
		def self.debug(message)
			if defined? Rails
				Rails.logger.debug message
			else
				puts message
			end
		end
		
		def self.info(message)
			if defined? Rails
				Rails.logger.info message
			else
				puts message
			end
		end
	end
end