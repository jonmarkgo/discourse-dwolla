# name: discourse-mymlh
# about: mymlh login provider
# version: 0.1
# author: Jonathan Gottfried

require 'auth/oauth2_authenticator'
require 'omniauth-oauth2'
require 'openssl'
require 'base64'

class MyMLHAuthenticator < ::Auth::OAuth2Authenticator
  def register_middleware(omniauth)
    omniauth.provider :mlh,
        setup: lambda { |env|
              strategy = env["omniauth.strategy"]
              strategy.options[:client_id] = SiteSetting.mymlh_app_id
              strategy.options[:client_secret] = SiteSetting.mymlh_secret
        }
  end

  def after_authenticate(auth_token)
    result = super

    if result.user && result.email && (result.user.email != result.email)
      begin
        result.user.update_columns(email: result.email)
      rescue
        used_by = User.find_by(email: result.email).try(:email)
        Rails.logger.warn("FAILED to update email for #{result.user.email} to #{result.email} cause it is in use by #{used_by}")
      end
    end

    result
  end

end
class OmniAuth::Strategies::MLH < OmniAuth::Strategies::OAuth2
  option :name, "mlh"

  option :client_options, {
    :site => 'https://my.mlh.io',
    :authorize_path  => '/oauth/authorize',
    :token_path => '/oauth/token'
  }

  uid { raw_info['data']['id'] }

  info do
    {
      :email                => raw_info['data']['email'],
      :created_at           => raw_info['data']['created_at'],
      :updated_at           => raw_info['data']['updated_at'],
      :first_name           => raw_info['data']['first_name'],
      :last_name            => raw_info['data']['last_name'],
      :graduation           => raw_info['data']['graduation'],
      :major                => raw_info['data']['major'],
      :shirt_size           => raw_info['data']['shirt_size'],
      :dietary_restrictions => raw_info['data']['dietary_restrictions'],
      :special_needs        => raw_info['data']['special_needs'],
      :date_of_birth        => raw_info['data']['date_of_birth'],
      :gender               => raw_info['data']['gender'],
      :phone_number         => raw_info['data']['phone_number'],
      :school               => {
                              :id =>  raw_info['data']['school']['id'],
                              :name =>  raw_info['data']['school']['name'],
                            }
    }
  end

  def raw_info
    @raw_info ||= access_token.get('/api/v1/user.json').parsed
  end
end
auth_provider title: 'Sign in with MyMLH',
              message: 'Log in using your MyMLh account. (Make sure your popup blocker is disabled.)',
              full_screen_login: true,
              authenticator: MyMLHAuthenticator.new('mlh',
                                                          trusted: true,
                                                          auto_create_account: true)
register_css <<CSS
.btn.mlh { background-color: #999; }
CSS

