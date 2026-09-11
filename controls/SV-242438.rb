control 'SV-242438' do
  title 'Kubernetes API Server must configure timeouts to limit attack surface.'
  desc 'Kubernetes API Server request timeouts sets the duration a request stays open before timing out. Since the API Server is the central component in the Kubernetes Control Plane, it is vital to protect this service. If request timeouts were not set, malicious attacks or unwanted activities might affect multiple deployments across different applications or environments. This might deplete all resources from the Kubernetes infrastructure causing the information system to go offline. The "--request-timeout" value must never be set to "0". This disables the request-timeout feature. (By default, the "--request-timeout" is set to "1 minute".)'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -I request-timeout *

If Kubernetes API Server manifest file does not exist, this is a finding.

If the setting "--request-timeout" is set to "0" in the Kubernetes API Server manifest file, or is not configured this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane.

Set the value of "--request-timeout" greater than "0".'
  desc 'caveat', 'Kubernetes API Server process is not running on the target.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000435-CTR-001070'
  tag gid: 'V-242438'
  tag rid: 'SV-242438r961620_rule'
  tag stig_id: 'CNTR-K8-002600'
  tag fix_id: 'F-45671r927127_fix'
  tag cci: ['CCI-002385', 'CCI-002415']
  tag nist: ['SC-5', 'SC-7 (21)']

  unless kube_apiserver.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes API Server process is not running on the target.'
  end

  describe kube_apiserver do
    its('request-timeout') { should_not be_nil }
    its('request-timeout') { should_not be_empty }
    its('request-timeout') { should_not cmp '0' }
  end
end
