require 'yaml'

class EtcdManifest < Inspec.resource(1)
  name 'etcd_manifest'
  desc 'Parses command-line parameters from a Kubernetes etcd static Pod manifest'

  def initialize(path)
    @path = path
    @manifest_file = inspec.file(path)
  end

  def exist?
    @manifest_file.file?
  end

  def params
    @params ||= read_params
  end

  def method_missing(name)
    params[name.to_s]
  end

  def respond_to_missing?(name, include_private = false)
    params.key?(name.to_s) || super
  end

  def to_s
    "etcd static Pod manifest #{@path}"
  end

  private

  def read_params
    return {} unless exist?

    manifest = YAML.safe_load(@manifest_file.content)
    containers = Array(manifest&.dig('spec', 'containers'))
    etcd_container = containers.find { |container| container['name'] == 'etcd' }
    etcd_container ||= containers.find do |container|
      command = Array(container['command']).first.to_s
      File.basename(command) == 'etcd'
    end
    return {} unless etcd_container

    parse_flags(Array(etcd_container['command']) + Array(etcd_container['args']))
  rescue Psych::SyntaxError
    {}
  end

  def parse_flags(tokens)
    tokens.each_with_index.each_with_object({}) do |(token, index), parsed|
      match = token.to_s.match(/\A--([^=\s]+)(?:=(.*))?\z/)
      next unless match

      key = match[1]
      value = match[2]
      if value.nil?
        following_token = tokens[index + 1].to_s
        value = following_token.start_with?('--') || following_token.empty? ? 'true' : following_token
      end
      parsed[key] = value
    end
  end
end
