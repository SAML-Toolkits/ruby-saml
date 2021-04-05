# docker build -t ruby-saml .
# docker run -it --rm ruby-saml bundle exec rake
ARG ruby_version=latest
FROM ruby:${ruby_version}

WORKDIR /src

COPY Gemfile .
COPY *gemspec .
RUN mkdir -p lib/onelogin/ruby-saml
COPY lib/onelogin/ruby-saml/version.rb lib/onelogin/ruby-saml/version.rb
RUN bundle

COPY . .
