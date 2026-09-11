control 'SV-242461' do
  title 'Kubernetes API Server audit logs must be enabled.'
  desc 'Kubernetes API Server validates and configures pods and services for
the API object. The REST operation provides frontend functionality to the
cluster share state. Enabling audit logs provides a way to monitor and identify
security risk events or misuse of information. Audit logs are necessary to
provide evidence in the case the Kubernetes API Server is compromised requiring
a Cyber Security Investigation.'
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:
grep -i audit-policy-file *

If the setting "audit-policy-file" is not set or is found in the Kubernetes API manifest file without valid content, this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the argument "--audit-policy-file" to "log file directory".'
  desc 'caveat', 'Kubernetes API Server process is not running on the target.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag gid: 'V-242461'
  tag rid: 'SV-242461r961863_rule'
  tag stig_id: 'CNTR-K8-003280'
  tag fix_id: 'F-45694r863923_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  unless kube_apiserver.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes API Server process is not running on the target.'
  end

  audit_policy_path = Array(kube_apiserver.params['audit-policy-file']).join

  describe 'Kubernetes API Server audit policy path' do
    subject { audit_policy_path }
    it { should_not be_empty }
  end

  unless audit_policy_path.empty?
    describe file(audit_policy_path) do
      it { should exist }
      its('size') { should be > 0 }
    end

    if file(audit_policy_path).exist? && file(audit_policy_path).size.positive?
      describe yaml(audit_policy_path) do
        its('apiVersion') { should match %r{\Aaudit\.k8s\.io/v\d+\z} }
        its('kind') { should cmp 'Policy' }
        its('rules') { should_not be_empty }
      end
    end
  end
end
