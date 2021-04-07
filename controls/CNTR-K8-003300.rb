# encoding: UTF-8

control 'CNTR-K8-003300' do
  title 'The Kubernetes API Server must be set to audit log maximum backup.'
  desc  "The Kubernetes API Server must set enough storage to retain logs for
monitoring suspicious activity and system misconfiguration, and provide
evidence for Cyber Security Investigations."
  desc  'rationale', ''
  desc  'check', "
    Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Master
Node. Run the command:

    grep -i audit-log-maxbackup *

    If the setting \"audit-log-maxbackup\" is not set in the Kubernetes API
Server manifest file or it is set less than \"10\", this is a finding.
  "
  desc  'fix', "Edit the Kubernetes API Server manifest file in the
/etc/kubernetes/manifests directory on the Kubernetes Master Node. Set the
value of \"--audit-log-maxbackup\" to a minimum of \"10\"."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag gid: 'CNTR-K8-003300'
  tag rid: 'CNTR-K8-003300_rule'
  tag stig_id: 'CNTR-K8-003300'
  tag fix_id: 'F-CNTR-K8-003300_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
