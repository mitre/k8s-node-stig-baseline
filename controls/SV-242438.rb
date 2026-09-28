control 'SV-242438' do
  title 'Kubernetes API Server must configure timeouts to limit attack surface.'
  desc 'Kubernetes API Server request timeouts sets the duration a request stays open before timing out. Since the API Server is the central component in the Kubernetes Control Plane, it is vital to protect this service. If request timeouts were not set, malicious attacks or unwanted activities might affect multiple deployments across different applications or environments. This might deplete all resources from the Kubernetes infrastructure causing the information system to go offline. The "--request-timeout" value must never be set to "0". This disables the request-timeout feature. (By default, the "--request-timeout" is set to "1 minute".)'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -I request-timeout *

If Kubernetes API Server manifest file does not exist, this is a finding.

If the setting "--request-timeout" is set to "0" in the Kubernetes API Server manifest file, or is not configured this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane.

Set the value of "--request-timeout" greater than "0".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000435-CTR-001070'
  tag gid: 'V-242438'
  tag rid: 'SV-242438r961620_rule'
  tag stig_id: 'CNTR-K8-002600'
  tag fix_id: 'F-45671r927127_fix'
  tag cci: ['CCI-002385', 'CCI-002415']
  tag nist: ['SC-5', 'SC-7 (21)']

  only_if("This control applies only to control-plane nodes; input('node_roles') must include 'control-plane'.", impact: 0.0) do
    input('node_roles').include?('control-plane')
  end

  kube_apiserver_manifest = kubernetes_manifest(::File.join(input('manifests_path'), 'kube-apiserver.yaml'), 'kube-apiserver')
  describe kube_apiserver_manifest do
    its('errors') { should be_empty }
  end

  timeout = KubernetesArguments.duration(kube_apiserver_manifest.params['request-timeout'])
  describe 'API Server request timeout is a positive duration' do
    it 'is configured with a valid duration greater than zero' do
      expect(timeout).not_to be_nil, 'The API Server --request-timeout must be configured with a valid Kubernetes duration'
      expect(timeout).to be > 0
    end
  end
end
