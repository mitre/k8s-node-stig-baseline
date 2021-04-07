# encoding: UTF-8

control 'CNTR-K8-003330' do
  title "The Kubernetes PKI CRT must have file permissions set to 644 or more
restrictive."
  desc  "The Kubernetes PKI directory contains all certificates (.crt files)
supporting secure network communications in the Kubernetes Control Plane. If
these files can be modified, data traversing within the architecture components
would become unsecure and compromised."
  desc  'rationale', ''
  desc  'check', "
    Review the permissions of the Kubernetes PKI cert files by using the
command:

    find /etc/kubernetes/pki -name \"*.crt\" | xargs stat -c '%n %a'

    If any of the files are have permissions more permissive than \"644\", this
is a finding.
  "
  desc  'fix', "
    Change the ownership of the cert files to \"644\" by executing the command:

    chmod -R 644 /etc/kubernetes/pki/*.crt
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag gid: 'CNTR-K8-003330'
  tag rid: 'CNTR-K8-003330_rule'
  tag stig_id: 'CNTR-K8-003330'
  tag fix_id: 'F-CNTR-K8-003330_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

