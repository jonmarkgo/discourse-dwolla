# name: discourse-dwolla
# about: dwolla login provider
# version: 0.1
# author: Robin Ward

require_dependency 'auth/oauth2_authenticator'

class DwollaAuthenticator < ::Auth::OAuth2Authenticator
  def register_middleware(omniauth)
    omniauth.provider :oauth2,
                      :name => 'dwolla',
                      :client_id => GlobalSetting.dwolla_client_id,
                      :client_secret => GlobalSetting.dwolla_client_secret,
                      :scope => 'AccountInfoFull',
                      :provider_ignores_state => true,
                      :client_options => {
                        :site => 'https://www.dwolla.com',
                        :authorize_url => '/oauth/v2/authenticate',
                        :token_url => '/oauth/v2/token'
                      }
  end

  def after_authenticate(auth)
    result = Auth::Result.new
    token = URI.escape(auth['credentials']['token'])
    token.gsub!(/\+/, '%2B')

    json = JSON.parse(open("https://www.dwolla.com/oauth/rest/users/?oauth_token=#{token}").read)
    user = json['Response']
    result.name = user['Name']

    current_info = ::PluginStore.get("dwolla", "dwolla_user_#{user['Id']}")
    if current_info
      result.user = User.where(id: current_info[:user_id]).first
    end
    result.extra_data = { dwolla_user_id: user['Id'] }
    result
  end

  def after_create_account(user, auth)
    ::PluginStore.set("dwolla", "dwolla_user_#{auth[:extra_data][:dwolla_user_id]}", {user_id: user.id })
  end

end

auth_provider :title => 'with Dwolla',
              :authenticator => DwollaAuthenticator.new('dwolla'),
              :message => 'Authorizing with Dwolla (make sure pop up blockers are not enabled)',
              :frame_width => 600,
              :frame_height => 300

register_css <<CSS

  button.btn-social.dwolla {
    background-color: #d94d00
  }

CSS
