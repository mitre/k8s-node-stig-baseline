# encoding: UTF-8

control 'V-242406' do
  title 'The Kubernetes kubelet configuration file must be owned by root.'
  desc  "The kubelet configuration file contains the runtime configuration of
the kubelet service. If an attacker can gain access to this file, changes can
be made to open vulnerabilities and bypass user authorizations inherent within
Kubernetes with RBAC implemented."
  desc  'rationale', ''
  desc  'check', "
    On the Master and worker nodes, change to the /etc/sysconfig directory. Run
the command:

    ls -l kubelet

    Each kubelet configuration file must be owned by root:root.

    If any manifest file is not owned by root:root, this is a finding.
  "
  desc 'fix', "
    On the Master and Worker nodes, change to the /etc/sysconfig directory. Run
the command:

    chown root:root kubelet

    To verify the change took place, run the command:

    ls -l kubelet

    The kubelet file should now be owned by root:root.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-CTR-000300'
  tag gid: 'V-242406'
  tag rid: 'SV-242406r712574_rule'
  tag stig_id: 'CNTR-K8-000880'
  tag fix_id: 'F-45639r712573_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  describe kubelet do
    its('config_file') { should be_owned_by('root') }
    its('config_file') { should be_grouped_into('root') }
  end
end
