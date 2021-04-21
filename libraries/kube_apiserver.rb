require 'kubeprocess_baseresource'

class KubeAPIServer < KubeProcessBaseResource
  name 'kube_apiserver'
  desc 'Custom resource to validate kube-apiserver configs'
  example "
    describe kube_apiserver do
      its('allow-privileged') { should cmp 'true' }
    end

    describe kube_apiserver('kube-apiserver') do
      its('insecure-port') { should cmp 0 }
    end
  "

  def initialize(process = nil)
    @process = process || inspec.kubernetes.apiserver_bin
    return skip_resource "Process #{@process} does not exist on the target node." unless inspec.processes(@process).exist?
  end

  def tls_cipher_suites
    self.params['tls-cipher-suites'].join.split(',')
  end
end