Rails.application.config.postshiba_webhook_secrets = JSON.parse(ENV.fetch('POSTSHIBA_WEBHOOK_SECRETS', '{}'))
