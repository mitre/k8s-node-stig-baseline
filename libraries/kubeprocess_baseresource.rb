require 'kubernetes'

class KubeProcessBaseResource < Inspec.resource(1)

  def initialize(process = nil)
    @process = process
  end

  def exist?
    inspec.processes(@process).exist?
  end

  def method_missing(name)
    read_params[name.to_s] || nil
  end

  def params
    @params ||= read_params
  end

  def to_s
    "Process arguments for #{@process}"
  end

  private

  def read_params
    return @params if defined?(@params)
    return {} unless exist?

    options = {
      assignment_regex: /--([^:]*?)=(.*?)\s*$/,
      multiple_values: true,
      line_separator: ' '
    }


    commands = inspec.processes(@process).commands.join
    process_args = commands.split(' ')[1..-1].join(' ')

    @params = inspec.parse_config(process_args, options).params
  end
end
