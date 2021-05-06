# encoding: UTF-8

control 'CNTR-K8-000890' do
  title 'The Kubernetes kubelet configuration file must be owned by root.'
  desc  "The kubelet configuration file contains the runtime configuration of
the kubelet service. If an attacker can gain access to this file, changes can
be made to open vulnerabilities and bypass user authorizations inherit within
Kubernetes with RBAC implemented."
  desc  'rationale', ''
  desc  'check', "
    On the Master and worker nodes, change to the /etc/kubernetes/manifest
directory. Run the command:

    ls -l kubelet

    Each kubelet configuration file must have permissions of \"644\" or more
restrictive.

    If any kubelet configuration file is less restrictive than \"644\", this is
a finding.
  "
  desc 'fix', "
    On the Master node, change to the /etc/kubernetes/manifest directory. Run
the command:

    chmod 644 kubelet

    To verify the change took place, run the command:

    ls -l kubelet

    The kubelet file should now have the permissions of \"644\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-CTR-000305'
  tag gid: 'CNTR-K8-000890'
  tag rid: 'CNTR-K8-000890_rule'
  tag stig_id: 'CNTR-K8-000890'
  tag fix_id: 'F-CNTR-K8-000890_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  describe kubelet do
    its('config_file') { should_not be_more_permissive_than('0644') }
  end
end
