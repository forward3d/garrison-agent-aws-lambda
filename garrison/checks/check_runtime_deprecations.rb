module Garrison
  module Checks
    class CheckRuntimeDeprecations < Check

      def settings
        self.source ||= 'aws-lambda'
        self.family ||= 'infrastructure'
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
        today = Time.now.utc.to_date

        options[:regions].each do |region|
          Logging.info "Checking region #{region}"
          begin
            AwsHelper.list_functions(region).each do |lambda|
              deprecated_runtime = deprecated_runtimes.find { |r| r[:identifier] == lambda.runtime }
              if deprecated_runtime

                if today > deprecated_runtime[:dates][:no_update]
                  severity = "critical"
                  detail = "#{today} > #{deprecated_runtime[:dates][:no_update]} no_update date"
                  type = "no-update"
                elsif today > deprecated_runtime[:dates][:no_create]
                  severity = "medium"
                  detail = "#{today} > #{deprecated_runtime[:dates][:no_create]} no_create date"
                  type = "no-create"
                elsif today > deprecated_runtime[:dates][:end_of_life]
                  severity = "low"
                  detail = "#{today} > #{deprecated_runtime[:dates][:end_of_life]} end_of_life date"
                  type = "end-of-life"
                else
                  severity = "info"
                  detail = "#{today} < #{deprecated_runtime[:dates][:end_of_life]} end_of_life date"
                  type = "end-of-life-warning"
                end

                alert(
                  name: 'Runtime Deprecation',
                  target: lambda.function_name,
                  external_severity: severity,
                  detail: detail,
                  finding: lambda.to_h.to_json,
                  finding_id: "#{lambda.function_arn}-runtime-deprecation-#{type}",
                  urls: [
                    {
                      name: "AWS Dashboard",
                      url: "https://console.aws.amazon.com/lambda/home?region=#{region}#/functions/#{lambda.function_name}"
                    },
                    {
                      name: "Runtime Deprecation Notices",
                      url: "https://docs.aws.amazon.com/lambda/latest/dg/runtime-support-policy.html"
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
            end
          rescue Aws::Lambda::Errors::UnrecognizedClientException => e
            Logging.warn "#{region} - #{e.message}"
            next
          end

        end
      end

      private

      def deprecated_runtimes
        # data from https://docs.aws.amazon.com/lambda/latest/dg/runtime-support-policy.html
        [
          {
            name: "Node.js 0.10",
            identifier: "nodejs",
            dates: {
              end_of_life: Date.new(2016, 10, 31),
              no_create: Date.new(2016, 10, 31),
              no_update: Date.new(2016, 10, 31)
            }
          },
          {
            name: "Node.js 4.3",
            identifier: "nodejs4.3",
            dates: {
              end_of_life: Date.new(2018, 4, 30),
              no_create: Date.new(2018, 12, 15),
              no_update: Date.new(2019, 4, 30)
            }
          },
          {
            name: "Node.js 4.3",
            identifier: "nodejs4.3-edge",
            dates: {
              end_of_life: Date.new(2018, 4, 30),
              no_create: Date.new(2018, 12, 15),
              no_update: Date.new(2019, 4, 30)
            }
          },
          {
            name: "Node.js 6.10",
            identifier: "nodejs6.10",
            dates: {
              end_of_life: Date.new(2019, 4, 30),
              no_create: Date.new(2019, 4, 30),
              no_update: Date.new(2019, 8, 12)
            }
          },
          {
            name: ".NET Core 2.0",
            identifier: "dotnetcore2.0",
            dates: {
              end_of_life: Date.new(2019, 4, 30),
              no_create: Date.new(2019, 4, 30),
              no_update: Date.new(2019, 5, 30)
            }
          },
          {
            name: ".NET Core 1.0",
            identifier: "dotnetcore1.0",
            dates: {
              end_of_life: Date.new(2019, 6, 27),
              no_create: Date.new(2019, 6, 27),
              no_update: Date.new(2019, 7, 31)
            }
          },
          {
            name: "Node.js 8.10",
            identifier: "nodejs8.10",
            dates: {
              end_of_life: Date.new(2019, 12, 31),
              no_create: Date.new(2020, 1, 6),
              no_update: Date.new(2019, 1, 20)
            }
          },
          {
            name: "Python 2.7",
            identifier: "python2.7",
            dates: {
              end_of_life: Date.new(2020, 1, 1),
              no_create: Date.new(2020, 1, 6),
              no_update: Date.new(2020, 4, 20)
            }
          }
        ]
      end

    end
  end
end
