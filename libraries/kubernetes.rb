# source: https://github.com/dev-sec/cis-kubernetes-benchmark

class Kubernetes < Inspec.resource(1)
  name 'kubernetes'
  desc 'Custom resource which abstracts the various kubernetes runtimes like hyperkube'

  def initialize
    @is_hyperkube = inspec.file('/usr/bin/hyperkube').file?
    Log.debug("The kubernetes installation uses hyperkube: #{@is_hyperkube}")
  end

  def apiserver_bin
    @is_hyperkube ? 'apiserver' : 'kube-apiserver'
  end

  def scheduler_bin
    'kube-scheduler'
  end

  def controllermanager_bin
    @is_hyperkube ? 'controller-manager' : 'kube-controller-manager'
  end

  def kubelet_bin
    'kubelet'
  end

  def kube_proxy_bin
    'kube-proxy'
  end
end