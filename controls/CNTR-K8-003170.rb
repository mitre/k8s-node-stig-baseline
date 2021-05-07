# encoding: UTF-8

control 'CNTR-K8-003170' do
  title 'The Kubernetes Kubelet certificate authority must be owned by root.'
  desc  "The Kubernetes kubelet certificate authority file contains settings
for the Kubernetes Node TLS certificate authority. Any request presenting a
client certificate signed by one of the authorities in the client-ca-file is
authenticated with an identity corresponding to the CommonName of the client
certificate. If this file can be changed, the Kubernetes architecture could
be compromised. The scheduler will implement the changes immediately. Many of
the security settings within the document are implemented through this file."
  desc  'rationale', ''
  desc  'check', "
    Change to the /etc/sysconfig/ directory on the Kubernetes Master Node.
Review the ownership of the Kubernetes  client-ca-file by using the command:

more kubelet
--client-ca-file argument
Note certificate location

Review the ownership of the Kubernetes client-ca-file by using the command:
stat -c   %U:%G <location from --client-ca-file argument>| grep -v root:root

If the command returns any non root:root file permissions, this is a finding.
"
  desc 'fix', "
    Change the permissions of the --client-ca-file to \"root\" by executing 
the command:

chown root:root <location from --client-ca-file argument>/ *
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'CNTR-K8-003170'
  tag rid: 'CNTR-K8-003170_rule'
  tag stig_id: 'CNTR-K8-003170'
  tag fix_id: 'F-CNTR-K8-003170_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # The check/fix text is likely a wrong guidance. Its title does not match the rest of the metadata.
  # It is likely a follow up to CNTR-K8-003160 which checks for file mode for `Kubelet` `client-ca-file`.
  # Automation code created matches the expect correct guidance.

  describe.one do
    describe kubelet do
      its('client_ca_file') { should_not be_nil }
      its('client_ca_file') { should be_owned_by('root') }
      its('client_ca_file') { should be_grouped_into('root') }
    end

    client_ca_file = kubelet_config_file.params.dig('authentication', 'x509', 'clientCAFile')
    if client_ca_file
      describe file(client_ca_file) do
        it { should be_owned_by('root') }
        it { should be_grouped_into('root') }
      end
    end
  end
end
