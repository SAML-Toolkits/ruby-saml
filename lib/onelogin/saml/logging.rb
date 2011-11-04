# Simplistic log class when we're running in Rails
module Onelogin::Saml
	class Logging
		
		def self.debug(message)
			if ENV != nil && ENV['logging_level'] != nil && ENV['logging_level'].to_i < 3
				return false
			end
			
			if defined? Rails
				Rails.logger.debug message
			else
				puts message
			end
		end
		
		def self.info(message)
			if ENV != nil && ENV['logging_level'] != nil && ENV['logging_level'].to_i < 2
				return false
			end
			
			if defined? Rails
				Rails.logger.info message
			else
				puts message
			end
		end
		def self.error(message)
			if ENV != nil && ENV['logging_level'] != nil && ENV['logging_level'].to_i < 1
				return false
			end
			
			if defined? Rails
				Rails.logger.error message
			else
				puts message
			end
		end
		
	end
end