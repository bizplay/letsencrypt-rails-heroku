require 'open-uri'
require 'openssl'
require 'acme-client'
require 'platform-api'

namespace :letsencrypt do

  desc 'Renew your LetsEncrypt certificate'
  task :renew do
    max_number_retries = 5
    
    # Check configuration looks OK
    abort "letsencrypt-rails-heroku is configured incorrectly. Are you missing an environment variable or other configuration? You should have a heroku_token, heroku_app, acmp_email and acme_domain configured either via a `Letsencrypt.configure` block in an initializer or as environment variables." unless Letsencrypt.configuration.valid?

    # Set up Heroku client
    heroku = PlatformAPI.connect_oauth Letsencrypt.configuration.heroku_token
    heroku_app = Letsencrypt.configuration.heroku_app

    # Create a private key
    print "Creating account key..."
    private_key = OpenSSL::PKey::RSA.new(4096)
    puts "Done!"

    client = Acme::Client.new(private_key: private_key, endpoint: Letsencrypt.configuration.acme_endpoint, connection_options: { request: { open_timeout: 5, timeout: 5 } })

    print "Registering with LetsEncrypt..."
    registration = client.register(contact: "mailto:#{Letsencrypt.configuration.acme_email}")

    registration.agree_terms
    puts "Done!"
    puts ""

    domains = Letsencrypt.configuration.acme_domain.split(',').map(&:strip)
    nr_domains = domains.count

    begin
      domains.each_with_index do |domain, index|
        puts "Performing verification for #{domain} (#{index+1}/#{nr_domains}):"

        authorization = client.authorize(domain: domain)
        challenge = authorization.http01

        print "Setting config vars on Heroku..."
        heroku.config_var.update(heroku_app, {
          'ACME_CHALLENGE_FILENAME' => challenge.filename,
          'ACME_CHALLENGE_FILE_CONTENT' => challenge.file_content
        })
        puts "Done!"

        # Wait for request to go through
        print "Giving config vars time to change..."
        sleep(5)
        # count_down = max_number_retries
        # while ENV["ACME_CHALLENGE_FILENAME"] != challenge.filename && ENV["ACME_CHALLENGE_FILE_CONTENT"] != challenge.file_content && count_down > 0
        #   print "."
        #   sleep(2)
        #   count_down -= 1
        # end
        # if ENV["ACME_CHALLENGE_FILENAME"] != challenge.filename || ENV["ACME_CHALLENGE_FILE_CONTENT"] != challenge.file_content
        #   puts " Error config vars not set!"
        # else
          puts " Done!"
        # end
        puts "challenge.filename: #{challenge.filename} ENV[ACME_CHALLENGE_FILENAME]: #{ENV['ACME_CHALLENGE_FILENAME']}"
        puts "challenge.file_content: #{challenge.file_content} ENV[ACME_CHALLENGE_FILE_CONTENT]: #{ENV['ACME_CHALLENGE_FILE_CONTENT']}"
        envs = heroku.config_var.info(heroku_app)
        puts "envs[ACME_CHALLENGE_FILE_CONTENT]: #{envs['ACME_CHALLENGE_FILE_CONTENT']} envs[ACME_CHALLENGE_FILE_CONTENT]: #{envs['ACME_CHALLENGE_FILE_CONTENT']}"

        # Wait for app to come up
        print "Testing filename works (to bring up app)..."

        # Get the domain name from Heroku
        hostname = heroku.domain.list(heroku_app).first['hostname']
        open("http://#{hostname}/#{challenge.filename}").read
        puts " Done!"

        challenge.request_verification # => true
        challenge.verify_status # => 'pending'

        # Once you are ready to serve the confirmation request you can proceed.
        print "Giving LetsEncrypt some time to verify..."
        sleep(1)
        count_down = max_number_retries
        while challenge.verify_status == 'pending' && count_down > 0
          print "."
          sleep(2)
          count_down -= 1
        end

        if challenge.verify_status != 'valid'
          puts  " Problem verifying challenge."
          abort "Status: #{challenge.verify_status}, Error: #{challenge.error}"
        else
          puts  " Done!"
        end

        puts ""
      end
    rescue Acme::Client::Error => e
      warn "Error Acme client error:"
      heroku.config_var.update(heroku_app, {
        'ACME_CHALLENGE_FILENAME' => nil,
        'ACME_CHALLENGE_FILE_CONTENT' => nil
      })
      abort e.response.body
    end

    # Unset temporary config vars. We don't care about waiting for this to
    # restart
    heroku.config_var.update(heroku_app, {
      'ACME_CHALLENGE_FILENAME' => nil,
      'ACME_CHALLENGE_FILE_CONTENT' => nil
    })

    # Create CSR
    csr = Acme::Client::CertificateRequest.new(names: domains)

    # Get certificate
    certificate = client.new_certificate(csr) # => #<Acme::Client::Certificate ....>

    # Send certificates to Heroku via API
    
    # First check for existing certificates:
    certificates = heroku.sni_endpoint.list(heroku_app)

    begin
      if certificates.any?
        print "Updating existing certificate #{certificates[0]['name']}..."
        heroku.sni_endpoint.update(heroku_app, certificates[0]['name'], {
          certificate_chain: certificate.fullchain_to_pem,
          private_key: certificate.request.private_key.to_pem
        })
        puts "Done!"
      else
        print "Adding new certificate..."
        heroku.sni_endpoint.create(heroku_app, {
          certificate_chain: certificate.fullchain_to_pem,
          private_key: certificate.request.private_key.to_pem
        })
        puts "Done!"
      end
    rescue Excon::Error::UnprocessableEntity => e
      warn "Error adding certificate to Heroku. Response from Heroku’s API follows:"
      abort e.response.body
    end

  end

end
