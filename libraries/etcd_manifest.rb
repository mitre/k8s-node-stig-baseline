require 'kubernetes_manifest'

# Assesses etcd's effective TLS settings, including config-file precedence.
class EtcdManifest < KubernetesManifest
  name 'etcd_manifest'
  desc 'Reads etcd TLS configuration from a static Pod manifest and its mounted configuration file'

  def initialize(path)
    super(path, 'etcd')
    apply_environment
    config_path = params['config-file']
    apply_config_file(config_path) if params.key?('config-file')
  end

  private

  def apply_environment
    Array(container['env']).each { |variable| apply_variable(variable) }
    @errors << 'Cannot resolve etcd envFrom settings from a node manifest' unless Array(container['envFrom']).empty?
  end

  def apply_variable(variable)
    return unless variable.is_a?(Hash) && variable['name'].to_s.start_with?('ETCD_')

    flag = variable['name'].delete_prefix('ETCD_').downcase.tr('_', '-')
    return if params.key?(flag)

    @errors << "Cannot resolve etcd environment variable #{variable['name']}" if variable['valueFrom']
    @params[flag] = variable['value']
  end

  def apply_config_file(config_path)
    path = host_path(config_path)
    config = path ? read_mapping(path) : {}
    # A configuration file replaces flags and environment settings, rather than merging.
    @params = {}
    apply_transport(config['client-transport-security'], '')
    apply_transport(config['peer-transport-security'], 'peer-')
  end

  def apply_transport(transport, prefix)
    return unless transport.is_a?(Hash)

    %w[cert-file key-file client-cert-auth auto-tls trusted-ca-file].each do |key|
      @params["#{prefix}#{key}"] = transport[key].to_s if transport.key?(key)
    end
  end
end
