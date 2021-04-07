# encoding: UTF-8

control 'CNTR-K8-003340' do
  title "The Kubernetes PKI keys must have file permissions set to 600 or more
restrictive."
  desc  "The Kubernetes PKI directory contains all certificate key files
supporting secure network communications in the Kubernetes Control Plane. If
these files can be modified, data traversing within the architecture components
would become unsecure and compromised."
  desc  'rationale', ''
  desc  'check', "
    Review the permissions of the Kubernetes PKI key files by using the command:

    find /etc/kubernetes/pki -name \"*.key\" | xargs stat -c '%n %a'

    If any of the files are have permissions more permissive than \"600\", this
is a finding.
  "
  desc  'fix', "
    Change the ownership of the cert files to \"600\" by executing the command:

    chmod -R 600 /etc/kubernetes/pki/*.key
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag gid: 'CNTR-K8-003340'
  tag rid: 'CNTR-K8-003340_rule'
  tag stig_id: 'CNTR-K8-003340'
  tag fix_id: 'F-CNTR-K8-003340_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

