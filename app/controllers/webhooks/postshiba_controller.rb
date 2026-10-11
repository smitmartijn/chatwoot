# Use Rails' binary email parameter handling without Chatwoot's session callbacks.
class Webhooks::PostshibaController < ActionController::Base # rubocop:disable Rails/ApplicationController
  skip_forgery_protection
  before_action :verify_signature!
  # PostShiba includes binary attachmentN form fields alongside the raw MIME email.
  skip_parameter_encoding :create

  def create
    email = params.require(:email)
    recipients = envelope_recipients
    return head :unprocessable_entity unless email.is_a?(String) && valid_recipients?(recipients)

    # Preserve envelope recipients for forwarded mail, as the SendGrid ingress does.
    source = recipients.map { |recipient| "X-Original-To: #{recipient}\n" }.join.b + email.b
    ActionMailbox::InboundEmail.create_and_extract_message_id!(source)
    head :no_content
  rescue ActionController::ParameterMissing, JSON::ParserError
    head :unprocessable_entity
  end

  private

  def verify_signature!
    secret = Rails.configuration.postshiba_webhook_secrets[request.path_parameters[:receiver_id]]
    timestamp = request.headers['X-Capsule-Timestamp']
    signature = request.headers['X-Capsule-Signature']
    return head :unauthorized if secret.blank? || signature.blank? || !valid_timestamp?(timestamp)

    expected = "sha256=#{OpenSSL::HMAC.hexdigest('SHA256', secret, "#{timestamp}.#{request.raw_post}")}"
    head :unauthorized unless ActiveSupport::SecurityUtils.secure_compare(expected, signature)
  end

  def valid_timestamp?(timestamp)
    timestamp.to_s.match?(/\A\d+\z/) && (Time.current.to_i - timestamp.to_i).abs <= 5.minutes
  end

  def envelope_recipients
    return [] unless params.key?(:envelope)
    return unless params[:envelope].is_a?(String)

    envelope = JSON.parse(params[:envelope])
    return unless envelope.is_a?(Hash)

    recipients = envelope['rcpt_to'] || envelope['to']
    recipients.is_a?(String) ? [recipients] : recipients
  end

  def valid_recipients?(recipients)
    recipients.is_a?(Array) && recipients.all? { |recipient| recipient.is_a?(String) && !recipient.match?(/[\r\n]/) }
  end
end
