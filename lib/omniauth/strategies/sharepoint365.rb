require 'omniauth'
require 'uri'

module OmniAuth
  module Strategies
    class Sharepoint365
      include OmniAuth::Strategy

      @@request_envelope = "
        <s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:a='http://www.w3.org/2005/08/addressing' xmlns:u='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'>
          <s:Header>
            <a:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
            <a:ReplyTo>
              <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
            </a:ReplyTo>
            <a:To s:mustUnderstand='1'>https://login.microsoftonline.com/extSTS.srf</a:To>
            <o:Security s:mustUnderstand='1' xmlns:o='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'>
              <o:UsernameToken>
                <o:Username>[username]</o:Username>
                <o:Password>[password]</o:Password>
              </o:UsernameToken>
            </o:Security>
          </s:Header>
          <s:Body>
            <t:RequestSecurityToken xmlns:t='http://schemas.xmlsoap.org/ws/2005/02/trust'>
              <wsp:AppliesTo xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy'>
                <a:EndpointReference>
                  <a:Address>[endpoint]</a:Address>
                </a:EndpointReference>
              </wsp:AppliesTo>
              <t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>
              <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
              <t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType>
            </t:RequestSecurityToken>
          </s:Body>
        </s:Envelope>
      "
      
      option :fields, [:name, :site, :pass]
      option :uid_field, :name
      option :claims_provider_url, "https://login.microsoftonline.com"
      option :claims_provider_path, "/extSTS.srf"
      option :sharepoint_signin_url_path, "/_forms/default.aspx?wa=wsignin1.0"
      option :sharepoint_request_user_agent, "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)"
      option :http_adapter, :net_http

      def request_phase
        form = OmniAuth::Form.new(:title => (options[:title] || "Sharepoint Authentication"), :url => callback_path)
        form.text_field 'Site Url', 'site_url' 
        form.text_field 'Login', 'username'
        form.password_field 'Password', 'password'
        form.button 'Sign In'
        form.to_response
      end

      def callback_phase
        logger = env['rack.logger']

        @username = request['username']
        password = request['password']
        @endpoint = request['site_url']

        logger.info "Sending request to #{@endpoint} for user #{@username}"
        token = get_token_from_claims_provider(@username, password, @endpoint)        
        logger.info "Token returned = #{token}"

        logger.info "Sending request to #{options[:sharepoint_signin_url_path]}"
        @authentication_cookies = authenticate_with_token(token, @endpoint)
        logger.info "rtFa = #{@authentication_cookies[:rtFa]}"
        logger.info "fedAuth = #{@authentication_cookies[:fedAuth]}"
 
        super
      end

      def get_token_from_claims_provider(username, password, endpoint)
        conn = connection_for_url(options[:claims_provider_url])
        response = conn.post do |request|
          request.url options[:claims_provider_path]
          request_body = @@request_envelope.sub(/\[username\]/, username).sub(/\[password\]/, password).sub(/\[endpoint\]/, endpoint)

          request.headers['Content-Length'] = request_body.length.to_s
          request.body = request_body
        end

        root = MultiXml.parse(response.body)
        logger = env['rack.logger']
        logger.info response.body
        root['Envelope']['Body']['RequestSecurityTokenResponse']['RequestedSecurityToken']['BinarySecurityToken']['__content__']
      end

      def authenticate_with_token(token, endpoint)
        endpoint_uri = URI(endpoint)
        endpoint_host = "#{endpoint_uri.scheme}://#{endpoint_uri.host}"        
        conn = connection_for_url(endpoint_host)

        response = conn.post do |req|
          req.url options[:sharepoint_signin_url_path]
          req.headers['Content-Length'] = token.length.to_s
          req.headers['User-Agent'] = options[:sharepoint_request_user_agent]
          req.body = token
        end
        cookies = CGI::Cookie::parse(response.headers['set-cookie'])

        { :rtFa => cookies['rtFa'], :fedAuth => cookies['FedAuth'] }
      end

      def connection_for_url(url)
        Faraday.new(:url => url) do |builder|
          builder.request :url_encoded
          builder.response :logger
          builder.adapter options[:http_adapter]
        end 
      end

      uid {
        @username
      }

      info {
        { :name => @username, :urls => { "Site" => @endpoint}}
      }

      extra {
        { :raw_info => @authentication_cookies }
      }
    end
  end
end
