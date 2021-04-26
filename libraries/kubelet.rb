require 'kubeprocess_baseresource'

class Kubelet < KubeProcessBaseResource
  name 'kubelet'
  desc 'Custom resource to validate kubelet configs'
  example "
    describe kubelet do
      its('anonymous-auth') { should cmp 'false' }
    end

    describe kubelet('kubelet') do
      its('network-plugin') { should cmp 'cni' }
    end
  "

  def initialize(process = nil)
    @process = process || inspec.kubernetes.kubelet_bin
    return skip_resource "Process #{@process} does not exist on the target node." unless inspec.processes(@process).exist?
  end

  def config_file
    inspec.file(self.params['config'].join) if self.params['config']
  end

  def kubeconfig_file
    inspec.file(self.params['kubeconfig'].join) if self.params['kubeconfig']
  end

  def client_ca_file
    inspec.file(self.params['client-ca-file'].join) if self.params['client-ca-file']
  end
end
