require 'yaml'

# Reads etcd command-line flags from a static Pod manifest on the target node.
class EtcdManifest < Inspec.resource(1)
  name 'etcd_manifest'
  desc 'Parses command-line parameters from a Kubernetes etcd static Pod manifest'

  # InSpec initializes resource state in its registration wrapper.
  def initialize(path) # rubocop:disable Lint/MissingSuper
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

    etcd_container = find_etcd_container(YAML.safe_load(@manifest_file.content))
    return {} unless etcd_container

    parse_flags(Array(etcd_container['command']) + Array(etcd_container['args']))
  rescue Psych::SyntaxError
    {}
  end

  def find_etcd_container(manifest)
    containers = Array(manifest&.dig('spec', 'containers'))
    containers.find { |container| container['name'] == 'etcd' } || containers.find do |container|
      command = Array(container['command']).first.to_s
      File.basename(command) == 'etcd'
    end
  end

  def parse_flags(tokens)
    tokens.each_with_index.each_with_object({}) do |(token, index), parsed|
      match = token.to_s.match(/\A--([^=\s]+)(?:=(.*))?\z/)
      next unless match

      key, value = match.captures
      parsed[key] = value.nil? ? following_flag_value(tokens[index + 1]) : value
    end
  end

  def following_flag_value(token)
    value = token.to_s
    value.start_with?('--') || value.empty? ? 'true' : value
  end
end
