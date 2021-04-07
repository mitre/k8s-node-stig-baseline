require "inspec/utils/object_traversal"

class KubeletConfigFile < Inspec.resource(1)
  name 'kubelet_config_file'
  desc 'Custom resource to validate kubelet configs'
  example "
    describe kubelet_config_file do
      its(['authentication','anonymous','enabled']) { should cmp false }
    end

    describe kubelet_config_file('/etc/kubernetes/kubelet-config.yaml') do
      its('rotateCertificates') { should cmp true }
    end
  "

  include ObjectTraverser

  KUBELET_CONFIG = '/etc/kubernetes/kubelet-config.yaml'

  def initialize(conf_path = nil)
    @conf_path = conf_path || inspec.kubelet.config.first || KUBELET_CONFIG
    read_params
  end

  def exist?
    inspec.file(@conf_path).exist?
  end

  def params
    @params ||= read_params
  end

  def method_missing(*keys)
    keys.shift if keys.is_a?(Array) && keys[0] == :[]
    value(keys)
  end

  def value(key)
    extract_value(key, @params)
  end

  def to_s
    "Kubelet Config File #{@conf_path}"
  end

  private

  def read_params
    return @params if defined?(@params)

    unless exist?
      skip_resource "Kubelet Config file #{@conf_path} does not exist."
      return @params = {}
    end

    if @conf_path.match?(/.yaml|yml$/)
      @params = inspec.yaml(@conf_path).params
    elsif @conf_path.match?(/.json$/)
      @params = inspec.json(@conf_path).params
    else
      skip_resource "Kubelet Config file #{@conf_path} is not a valid config file."
      @params = {}
    end
  end
end
