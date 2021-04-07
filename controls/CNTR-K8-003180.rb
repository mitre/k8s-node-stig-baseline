# encoding: UTF-8

control 'CNTR-K8-003180' do
  title 'The Kubernetes component PKI must be owned by root.'
  desc  "The Kubernetes PKI directory contains all certificates (.crt files)
supporting secure network communications in the Kubernetes Control Plane. If
these files can be modified, data traversing within the architecture components
would become unsecure and compromised. Many of the security settings within the
document are implemented through this file."
  desc  'rationale', ''
  desc  'check', "
    Review the PKI files in Kubernetes by using the command:

    ls -laR /etc/kubernetes/pki/

    If the command returns any non root:root file permissions, this is a
finding.
  "
  desc  'fix', "
    Change the ownership of the PKI to root: root by executing the command:

    chown -R root:root /etc/kubernetes/pki/
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'CNTR-K8-003180'
  tag rid: 'CNTR-K8-003180_rule'
  tag stig_id: 'CNTR-K8-003180'
  tag fix_id: 'F-CNTR-K8-003180_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
