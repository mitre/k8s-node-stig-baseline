require 'kubernetes_arguments'

# Rejects malformed tailoring before it can turn applicable checks into N/A.
module ::KubernetesNodeInputs
  MODE_KEYS = %w[manifest_files kubelet_config_file kube_proxy_kubeconfig_file kubelet_client_ca_file kubelet_kubeconfig_file kubeadm_conf_file etcd_data_files kubernetes_conf_files pki_certificate_files pki_private_key_files].freeze
  PATH_INPUTS = %w[manifests_path etcd_data_dir pki_path kubeadm_conf_path kubectl_path kubectl_kubeconfig_path].freeze
  POSITIVE_INPUTS = %w[audit_log_retention_days streaming_connection_idle_timeout_seconds].freeze

  module_function

  def value(name, value)
    raise ArgumentError, "Invalid input('#{name}'): #{requirement(name)}" unless valid?(name, value)

    value
  end

  def valid?(name, value)
    return KubernetesArguments.path?(value) if PATH_INPUTS.include?(name)
    return positive?(value) if POSITIVE_INPUTS.include?(name)

    predicate = { 'node_roles' => :roles?, 'kubernetes_minor_version' => :minor?, 'kubernetes_file_modes' => :modes?, 'kubernetes_conf_files' => :paths?, 'kubectl_minversion' => :version? }[name]
    predicate.nil? || public_send(predicate, value)
  end

  def roles?(value)
    value.is_a?(Array) && !value.empty? && (value - %w[control-plane worker]).empty?
  end

  def minor?(value)
    value.is_a?(Integer) && value >= 0
  end

  def positive?(value)
    value.is_a?(Numeric) && value.finite? && value > 0
  end

  def modes?(value)
    value.is_a?(Hash) && (MODE_KEYS - value.keys).empty? && value.values.all? { |mode| mode.is_a?(String) && mode.match?(/\A0[0-7]{3}\z/) }
  end

  def paths?(value)
    value.is_a?(Array) && !value.empty? && value.all? { |path| KubernetesArguments.path?(path) }
  end

  def version?(value)
    value.is_a?(String) && value.match?(/\Av?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)*\z/)
  end

  def requirement(name)
    return 'use an absolute path without NUL or newline characters' if PATH_INPUTS.include?(name)
    return 'use a finite number greater than zero' if POSITIVE_INPUTS.include?(name)

    {
      'node_roles' => 'supply a nonempty array containing only control-plane and/or worker',
      'kubernetes_minor_version' => 'supply the actual target minor version as a nonnegative integer; no version is assumed',
      'kubernetes_file_modes' => "supply all #{MODE_KEYS.join(', ')} keys with quoted four-digit octal modes",
      'kubernetes_conf_files' => 'supply at least one absolute configuration-file path',
      'kubectl_minversion' => 'supply a semantic version such as 1.12.9'
    }.fetch(name, 'supply a value matching the input declaration')
  end
end
