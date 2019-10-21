module Garrison
  module Checks
    class CheckSomething < Check

      def settings
        self.source ||= 'somewhere'
        self.severity ||= 'high'
        self.family ||= 'infrastructure'
        self.type ||= 'compliance'
        self.options[:something] ||= 'all'
      end

      def perform
        # do your check here and raise alerts here
      end

    end
  end
end
