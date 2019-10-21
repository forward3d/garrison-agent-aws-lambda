module Garrison
  class AwsHelper

    def self.whoami
      @whoami ||= ENV['AWS_ACCOUNT_ID'] || Aws::STS::Client.new(region: 'us-east-1').get_caller_identity.account
    end

    def self.all_regions
      Aws::Partitions.partition('aws').service('Lambda').regions
    end

    def self.list_functions(region)
      if ENV['AWS_ASSUME_ROLE_CREDENTIALS_ARN']
        role_credentials = Aws::AssumeRoleCredentials.new(
          client: Aws::STS::Client.new(region: region),
          role_arn: ENV['AWS_ASSUME_ROLE_CREDENTIALS_ARN'],
          role_session_name: 'garrison-agent-lambda'
        )

        client = Aws::Lambda::Client.new(credentials: role_credentials, region: region, logger: Logging, log_level: :debug)
      else
        client = Aws::Lambda::Client.new(region: region, logger: Logging, log_level: :debug)
      end

      Enumerator.new do |yielder|
        marker = nil

        loop do
          results = client.list_functions(marker: marker, max_items: 50)
          results.functions.map { |item| yielder << item }

          if results.next_marker
            marker = results.next_marker
          else
            raise StopIteration
          end
        end
      end.lazy
    end
  end
end
