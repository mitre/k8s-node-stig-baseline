# Evaluates policy structure without exposing encryption keys in assessment output.
module ::KubernetesPolicy
  module_function

  def encrypted_secrets?(policy)
    return false unless policy['kind'] == 'EncryptionConfiguration' && policy['apiVersion'] == 'apiserver.config.k8s.io/v1'

    entry = secret_entry(policy)
    provider = entry.is_a?(Hash) && Array(entry['providers']).first
    encryption_provider?(provider)
  end

  def secret_entry(policy)
    Array(policy['resources']).find do |item|
      item.is_a?(Hash) && (Array(item['resources']) & ['secrets', 'secrets.', '*.', '*.*']).any?
    end
  end

  def encryption_provider?(provider)
    return false unless provider.is_a?(Hash) && provider.size == 1
    return false unless (provider.keys & %w[aescbc aesgcm secretbox kms]).any?

    settings = provider.values.first
    settings.is_a?(Hash) && !settings.empty?
  end

  def pod_security_plugin(policy)
    return {} unless policy['kind'] == 'AdmissionConfiguration' && policy['apiVersion'].to_s.match?(%r{\Aapiserver\.config\.k8s\.io/v1(?:alpha1|beta1)?\z})

    plugins = Array(policy['plugins']).select { |plugin| plugin.is_a?(Hash) && plugin['name'] == 'PodSecurity' }
    plugins.length == 1 ? plugins.first : {}
  end

  def pod_security_valid?(policy)
    return false unless policy.is_a?(Hash) && policy['kind'] == 'PodSecurityConfiguration'
    return false unless policy['apiVersion'].to_s.match?(%r{\Apod-security\.admission\.config\.k8s\.io/v1(?:alpha1|beta1)?\z})

    defaults = policy['defaults']
    defaults.is_a?(Hash) && %w[enforce audit warn].all? { |mode| valid_mode?(defaults, mode) }
  end

  def valid_mode?(defaults, mode)
    level = defaults.fetch(mode, 'privileged')
    version = defaults.fetch("#{mode}-version", 'latest')
    %w[privileged baseline restricted].include?(level) && version.is_a?(String) && version.match?(/\A(?:latest|v1\.\d+)\z/)
  end

  def compatible_versions?(client, server)
    versions = [client, server].map { |version| version.to_s.match(/\Av?(\d+)\.(\d+)\.\d+(?:[-+][0-9A-Za-z.-]+)*\z/) }
    versions.all? && versions[0][1] == versions[1][1] && (versions[0][2].to_i - versions[1][2].to_i).abs <= 1
  end
end
