require 'kubeprocess_baseresource'

class Etcd < KubeProcessBaseResource

# class Etcd < Inspec.resource(1)
  name 'etcd'
  desc 'Custom resource to validate etcd configs'
  example "
    describe etcd do
      its('allow-privileged') { should cmp 'true' }
    end

    describe etcd('etcd') do
      its('port') { should cmp 0 }
    end
  "

  def initialize(process = nil)
    @process = process || 'etcd'
    return skip_resource "Process #{@process} does not exist on the target node." unless inspec.processes(@process).exist?
  end

  # def initialize(process = nil)
  #   @process = process || 'etcd'
  # end

  # def exist?
  #   inspec.processes(@process).exist?
  # end

  # def method_missing(name)
  #   read_params[name.to_s] || ''
  # end

  # def params
  #   @params ||= read_params
  # end

  # def read_params
  #   return @params if defined?(@params)

  #   options = {
  #     assignment_regex: /--([^:]*?)=(.*?)\s*$/,
  #     multiple_values: true,
  #     line_separator: ' '
  #   }

  #   unless exist?
  #     skip_resource "Process #{@process} does not exist."
  #     return @params = {}
  #   end

  #   commands = inspec.processes(@process).commands.join
  #   process_args = commands.split(' ')[1..-1].join(' ')

  #   @params = inspec.parse_config(process_args, options).params
  # end

  # def to_s
  #   "Process arguments for #{@process}"
  # end
end
