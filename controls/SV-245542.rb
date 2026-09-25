control 'SV-245542' do
  title 'Kubernetes API Server must disable basic authentication to protect
information in transit.'
  desc 'Kubernetes basic authentication sends and receives request containing
username, uid, groups, and other fields over a clear text HTTP communication.
Basic authentication does not provide any security mechanisms using encryption
standards. PKI certificate-based authentication must be set over a secure
channel to ensure confidentiality and integrity. Basic authentication must not
be set in the manifest file.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i basic-auth-file *

If "basic-auth-file" is set in the Kubernetes API server manifest file this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Remove the setting "--basic-auth-file".'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000439-CTR-001080'
  tag gid: 'V-245542'
  tag rid: 'SV-245542r961632_rule'
  tag stig_id: 'CNTR-K8-002620'
  tag fix_id: 'F-48772r863944_fix'
  tag cci: ['CCI-002418', 'CCI-002448']
  tag nist: ['SC-8', 'SC-12 (3)']

  only_if("This control applies only to control-plane nodes; input('node_roles') must include 'control-plane'.", impact: 0.0) do
    input('node_roles').include?('control-plane')
  end

  kube_apiserver_manifest = kubernetes_manifest(::File.join(input('manifests_path'), 'kube-apiserver.yaml'), 'kube-apiserver')
  describe kube_apiserver_manifest do
    its('errors') { should be_empty }
  end

  if kube_apiserver_manifest.errors.empty?
    describe kube_apiserver_manifest do
      its('basic-auth-file') { should be_nil }
    end
  end
end
