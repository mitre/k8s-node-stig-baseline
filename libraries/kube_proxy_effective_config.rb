require 'yaml'
require 'pathname'
require 'kubernetes_arguments'

# Resolves kube-proxy's effective kubeconfig through either --kubeconfig or
# --config -> clientConnection.kubeconfig, using the process mount namespace.
class KubeProxyEffectiveConfig < Inspec.resource(1)
  name 'kube_proxy_effective_config'
  desc 'Finds the kube-proxy kubeconfig used by the running process'

  attr_reader :errors, :params, :configuration_path, :kubeconfig_path

  def initialize(process_name = nil)
    @process_name = process_name || inspec.kubernetes.kube_proxy_bin
    @errors = []
    @params = {}
    @processes = inspec.processes(@process_name)
    resolve if exist?
  end

  def exist?
    @processes.exist?
  end

  def kubeconfig_file
    inspec.file(@resolved_kubeconfig_path) if @resolved_kubeconfig_path
  end

  def to_s
    "Effective kube-proxy configuration for #{@process_name}"
  end

  private

  def resolve
    pids = Array(@processes.pids)
    return @errors << "Expected exactly one #{@process_name} process; found #{pids.length}" unless pids.length == 1

    @pid = pids.first
    argv = process_arguments
    return if argv.empty?

    @params = KubernetesArguments.parse(argv)
    apply_k3s_component_arguments(argv) if @process_name.match?(/k3s/)

    if @params.key?('kubeconfig')
      set_kubeconfig(@params['kubeconfig'], '--kubeconfig')
    elsif @params.key?('config')
      resolve_configuration_file(@params['config'])
    else
      @errors << 'Kube-proxy must specify --kubeconfig or --config'
    end
  end

  def process_arguments
    cmdline_path = "/proc/#{@pid}/cmdline"
    cmdline = inspec.file(cmdline_path)
    unless cmdline.file? && cmdline.content.is_a?(String)
      @errors << "Cannot read kube-proxy process arguments from #{cmdline_path}"
      return []
    end

    cmdline.content.split("\0").reject(&:empty?)
  end

  def apply_k3s_component_arguments(argv)
    argv.each_with_index do |token, index|
      match = token.match(/\A--kube-proxy-arg(?:=(.*))?\z/)
      next unless match

      argument = match[1] || argv[index + 1]
      name, value = argument.to_s.delete_prefix('--').split('=', 2)
      @params[name] = value.to_s unless name.to_s.empty?
    end
  end

  def resolve_configuration_file(path)
    @configuration_path = normalized_path(path, '--config')
    return unless @configuration_path

    config = read_process_mapping(@configuration_path)
    return unless config

    client_connection = config['clientConnection']
    unless client_connection.is_a?(Hash)
      @errors << "Kube-proxy configuration #{@configuration_path} must define clientConnection"
      return
    end

    set_kubeconfig(client_connection['kubeconfig'], "clientConnection.kubeconfig in #{@configuration_path}")
  end

  def set_kubeconfig(path, source)
    @kubeconfig_path = normalized_path(path, source)
    return unless @kubeconfig_path

    @resolved_kubeconfig_path = process_path(@kubeconfig_path)
    @errors << "Kube-proxy kubeconfig #{@kubeconfig_path} is missing or unreadable" unless inspec.file(@resolved_kubeconfig_path).file?
  end

  def read_process_mapping(path)
    resolved = process_path(path)
    target = inspec.file(resolved)
    unless target.file? && target.content.is_a?(String)
      @errors << "Kube-proxy configuration #{path} is missing or unreadable"
      return nil
    end

    mapping = YAML.safe_load(target.content)
    return mapping if mapping.is_a?(Hash)

    @errors << "Kube-proxy configuration #{path} must be a YAML mapping"
    nil
  rescue Psych::Exception
    @errors << "Kube-proxy configuration #{path} contains invalid or unsupported YAML"
    nil
  end

  def normalized_path(path, source)
    unless KubernetesArguments.path?(path)
      @errors << "#{source} must name an absolute path"
      return nil
    end

    Pathname.new(path).cleanpath.to_s
  end

  def process_path(path)
    "/proc/#{@pid}/root#{path}"
  end
end
