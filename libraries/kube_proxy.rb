require 'kubeprocess_baseresource'

class KubeProxy < KubeProcessBaseResource
  name 'kube_proxy'
  desc 'Custom resource to validate kube-proxy configs'
  example "
    describe kube_proxy do
      its('anonymous-auth') { should cmp 'false' }
    end

    describe kube_proxy('kubelet') do
      its('network-plugin') { should cmp 'cni' }
    end
  "

  def initialize(process = nil)
    @process = process || inspec.kubernetes.kube_proxy_bin
    return skip_resource "Process #{@process} does not exist on the target node." unless inspec.processes(@process).exist?
  end

  def kubeconfig_file
    inspec.file(self.params['kubeconfig'].join) if self.params['kubeconfig']
  end
end
