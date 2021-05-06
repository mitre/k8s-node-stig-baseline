# encoding: UTF-8

control 'CNTR-K8-002630' do
  title "Kubernetes API Server must disable token authentication to protect
information in transit."
  desc  "Kubernetes token authentication uses password known as secrets in a
plaintext file. This file contains sensitive information such as token,
username and user uid. This token is used by service accounts within pods to
authenticate with the API Server. This information is very valuable for
attackers with malicious intent if the service account is privileged having
access to the token. With this token a threat actor can impersonate the service
account gaining access to the Rest API service."
  desc  'rationale', ''
  desc  'check', "
    Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Master
Node. Run the command:

    grep -i token-auth-file *

    If \"token-auth-file\" is set in the Kubernetes API server manifest file,
this is a finding.
  "
  desc 'fix', "Edit the Kubernetes API Server manifest file in the
/etc/kubernetes/manifests directory on the Kubernetes Master Node. Remove
parameter \"--token-auth-file\"."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-CTR-001080'
  tag gid: 'CNTR-K8-002630'
  tag rid: 'CNTR-K8-002630_rule'
  tag stig_id: 'CNTR-K8-002630'
  tag fix_id: 'F-CNTR-K8-002630_fix'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

  unless kube_apiserver.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes API Server process is not running on the target.'
  end

  describe kube_apiserver do
    its('token-auth-file') { should be_nil }
  end
end
