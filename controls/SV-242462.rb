control 'SV-242462' do
  title 'The Kubernetes API Server must be set to audit log max size.'
  desc 'The Kubernetes API Server must be set for enough storage to retain log
information over the period required. When audit logs are large in size, the
monitoring service for events becomes degraded. The function of the maximum log
file size is to set these limits.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i audit-log-maxsize *

If the setting "--audit-log-maxsize" is not set in the Kubernetes API Server manifest file or it is set to less than "100", this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane.

Set the value of "--audit-log-maxsize" to a minimum of "100".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag gid: 'V-242462'
  tag rid: 'SV-242462r961863_rule'
  tag stig_id: 'CNTR-K8-003290'
  tag fix_id: 'F-45695r927136_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  only_if("This control applies only to control-plane nodes; input('node_roles') must include 'control-plane'.", impact: 0.0) do
    input('node_roles').include?('control-plane')
  end

  kube_apiserver_manifest = kubernetes_manifest(::File.join(input('manifests_path'), 'kube-apiserver.yaml'), 'kube-apiserver')
  describe kube_apiserver_manifest do
    its('errors') { should be_empty }
  end

  if kube_apiserver_manifest.errors.empty?
    describe kube_apiserver_manifest do
      its('audit-log-maxsize') { should cmp >= 100 }
    end
  end
end
