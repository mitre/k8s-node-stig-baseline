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
end
