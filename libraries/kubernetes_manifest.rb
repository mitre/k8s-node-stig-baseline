require 'yaml'
require 'pathname'
require 'kubernetes_arguments'

# Reads saved component arguments and resolves container paths through hostPath mounts.
class KubernetesManifest < Inspec.resource(1)
  name 'kubernetes_manifest'
  attr_reader :params, :errors, :container

  # InSpec's resource registration wrapper initializes the resource base.
  def initialize(path, component) # rubocop:disable Lint/MissingSuper
    @path = path
    @component = component
    @errors = []
    @manifest = read_mapping(path)
    @container = component_container
    @params = KubernetesArguments.parse(arguments, boolean_flags)
  end

  def exist?
    inspec.file(@path).file?
  end

  def method_missing(name, *arguments)
    return super unless arguments.empty?

    params[name.to_s]
  end

  def respond_to_missing?(name, include_private = false)
    params.key?(name.to_s) || super
  end

  def tls_cipher_suites
    params['tls-cipher-suites'].to_s.split(',')
  end

  def to_s
    "#{@component} static Pod manifest #{@path}"
  end

  def host_path(path)
    return path_error('Configured path must be absolute') unless KubernetesArguments.path?(path)

    normalized = Pathname.new(path).cleanpath.to_s
    resolve_mount(normalized, matching_mount(normalized))
  end

  def read_mapping(path)
    target = inspec.file(path)
    return mapping_error("Missing or unreadable configuration file #{path}") unless target.file? && target.content.is_a?(String)

    result = YAML.safe_load(target.content)
    return result if result.is_a?(Hash)

    mapping_error("Configuration must be a YAML mapping: #{path}")
  rescue Psych::Exception
    mapping_error("Invalid or unsupported YAML in #{path}")
  end

  private

  def boolean_flags
    %w[anonymous-auth profiling use-service-account-credentials auto-tls peer-auto-tls client-cert-auth peer-client-cert-auth]
  end

  def arguments
    tokens = Array(container['command']) + Array(container['args'])
    @errors << 'Component command and args must contain only strings' unless tokens.all? { |token| token.is_a?(String) }
    tokens
  end

  def component_container
    containers = spec_items('containers')
    matches = containers.select { |item| item['name'] == @component || File.basename(Array(item['command']).first.to_s) == @component }
    return matches.first if matches.length == 1

    mapping_error("Expected exactly one #{@component} container in #{@path}")
  end

  def spec_items(key)
    spec = @manifest['spec']
    spec.is_a?(Hash) ? Array(spec[key]).select { |item| item.is_a?(Hash) } : []
  end

  def matching_mount(path)
    mounts = Array(container['volumeMounts']).select { |mount| mount.is_a?(Hash) }
    mounts.select { |mount| mounted?(path, mount['mountPath']) }.max_by { |mount| mount['mountPath'].length }
  end

  def volume_path(name)
    volume = spec_items('volumes').find { |item| item['name'] == name }
    volume && volume['hostPath'].is_a?(Hash) && volume['hostPath']['path']
  end

  def mounted?(path, mount_path)
    KubernetesArguments.path?(mount_path) && (path == mount_path || path.start_with?("#{mount_path.chomp('/')}/"))
  end

  def resolve_mount(path, mount)
    return path_error("No hostPath mount exposes #{path}") unless mount
    return path_error("Cannot resolve subPathExpr for #{path}") if mount['subPathExpr']

    base = volume_path(mount['name'])
    return path_error("No hostPath volume exposes #{path}") unless KubernetesArguments.path?(base)

    suffix = path.delete_prefix(mount['mountPath']).delete_prefix('/')
    File.join(*[base, mount.fetch('subPath', ''), suffix].reject(&:empty?))
  end

  def mapping_error(message)
    @errors << message
    {}
  end

  def path_error(message)
    @errors << message
    nil
  end
end
