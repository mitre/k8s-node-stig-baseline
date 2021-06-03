# encoding: UTF-8

control 'V-242427' do
  title 'Kubernetes etcd must have a key file for secure communication.'
  desc  "Kubernetes stores configuration and state information in a distributed
key-value store called etcd. Anyone who can write to etcd can effectively
control the Kubernetes cluster. Even just reading the contents of etcd could
easily provide helpful hints to a would-be attacker. Using authenticity
protection, the communication can be protected against man-in-the-middle
attacks/session hijacking and the insertion of false information into sessions.

    The communication session is protected by utilizing transport encryption
protocols, such as TLS. TLS provides the Kubernetes API Server and etcd with a
means to be able to authenticate sessions and encrypt traffic.

    To enable encrypted communication for etcd, the parameter etcd-keyfile must
be set. This parameter gives the location of the key file used to secure etcd
communication.
  "
  desc  'rationale', ''
  desc  'check', "
    Change to the /etc/kubernetes/manifests directory on the Kubernetes Master
Node. Run the command:

    grep -i key-file *

    If the setting \"key-file\" is not configured in the Kubernetes etcd
manifest file, this is a finding.
  "
  desc 'fix', "Edit the etcd manifest file in the
/etc/kubernetes/manifests directory on the Kubernetes Master Node. Set the
value of \"--key-file\" to the Approved Organizational Certificate."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag gid: 'V-242427'
  tag rid: 'SV-242427r712637_rule'
  tag stig_id: 'CNTR-K8-001490'
  tag fix_id: 'F-45660r712636_fix'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']

  if etcd.exist?
    describe.one do
      describe etcd do
        its('key-file') { should_not be_nil }
      end

      describe process_env_var('etcd') do
        its(:ETCD_KEY_FILE) { should_not be_nil }
      end
    end
  else
    describe 'ETCD process is not running on the target.' do
      skip
    end
  end
end
