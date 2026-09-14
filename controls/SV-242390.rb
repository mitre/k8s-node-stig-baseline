control 'SV-242390' do
  title 'The Kubernetes API server must have anonymous authentication disabled.'
  desc 'The Kubernetes API Server controls Kubernetes via an API interface. A user who has access to the API essentially has root access to the entire Kubernetes cluster. To control access, users must be authenticated and authorized. By allowing anonymous connections, the controls put in place to secure the API can be bypassed.

Setting "--anonymous-auth" to "false" also disables unauthenticated requests from kubelets.

While there are instances where anonymous connections may be needed (e.g., health checks) and Role-Based Access Controls (RBACs) are in place to limit the anonymous access, this access should be disabled, and only enabled when necessary.'
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:

grep -i anonymous-auth *

If the setting "--anonymous-auth" is set to "true" in the Kubernetes API Server manifest file, this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane.

Set the value of  "--anonymous-auth" to "false".'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000033-CTR-000100'
  tag gid: 'V-242390'
  tag rid: 'SV-242390r1137640_rule'
  tag stig_id: 'CNTR-K8-000360'
  tag fix_id: 'F-45623r927089_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  only_if("This control applies only to control-plane nodes; input('node_roles') must include 'control-plane'.", impact: 0.0) do
    input('node_roles').include?('control-plane')
  end

  kube_apiserver_manifest = kubernetes_manifest(::File.join(input('manifests_path'), 'kube-apiserver.yaml'), 'kube-apiserver')
  describe kube_apiserver_manifest do
    its('errors') { should be_empty }
  end

  describe kube_apiserver_manifest do
    its('anonymous-auth') { should_not cmp 'true' }
  end
end
