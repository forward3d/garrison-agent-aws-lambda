module Garrison
  module Checks
    class CheckEncryptionAtRest < Check

      def settings
        self.source ||= 'aws-lambda'
        self.family ||= 'infrastructure'
        self.severity ||= 'critical'
        self.type ||= 'compliance'
        self.options[:regions] ||= 'all'
      end

      def key_values
        [
          { key: 'datacenter', value: 'aws' },
          { key: 'aws-service', value: 'lambda' },
          { key: 'aws-account', value: AwsHelper.whoami }
        ]
      end

      def perform
        options[:regions] = AwsHelper.all_regions if options[:regions] == 'all'

        options[:regions].each do |region|
          Logging.info "Checking region #{region}"
          begin
            AwsHelper.list_functions(region).each do |lambda|
              next unless lambda.kms_key_arn.nil?

              alert(
                name: 'Encryption At Rest Violation',
                target: lambda.function_name,
                detail: "kms_key_arn: nil",
                finding: lambda.to_h.to_json,
                finding_id: "#{lambda.function_arn}-encryption-at-rest",
                urls: [
                  {
                    name: "AWS Dashboard",
                    url: "https://console.aws.amazon.com/lambda/home?region=#{region}#/functions/#{lambda.function_name}"
                  }
                ],
                key_values: [
                  {
                    key: 'aws-region',
                    value: region
                  }
                ]
              )
            end
          rescue Aws::Lambda::Errors::UnrecognizedClientException => e
            Logging.warn "#{region} - #{e.message}"
            next
          end
        end
      end

    end
  end
end
