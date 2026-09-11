control 'SV-242449' do
  title 'The Kubernetes Kubelet certificate authority file must have file
permissions set to 644 or more restrictive.'
  desc 'The Kubernetes kubelet certificate authority file contains settings
for the Kubernetes Node TLS certificate authority. Any request presenting a
client certificate signed by one of the authorities in the client-ca-file is
authenticated with an identity corresponding to the CommonName of the client
certificate. If this file can be changed, the Kubernetes architecture could be
compromised. The scheduler will implement the changes immediately. Many of the
security settings within the document are implemented through this file.'
  desc 'check', 'On the Control Plane, run the command:
ps -ef | grep kubelet

If the "--client-ca-file" option exists, this is a finding. 

Note the path to the config file (identified by --config).

Run the command:
grep -i clientCAFile <path_to_config_file>

Note the path to the client ca file.

Run the command:
stat -c %a <path_to_client_ca_file>

If the client ca file has permissions more permissive than "644", this is a finding.'
  desc 'fix', 'On the Control Plane, run the command:
ps -ef | grep kubelet

Remove the "--client-ca-file" option.

Note the path to the config file (identified by --config).

Run the command:
grep -i clientCAFile <path_to_config_file>

Note the path to the client ca file.

Run the command:
chmod 644 <path_to_client_ca_file>'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'V-242449'
  tag rid: 'SV-242449r961863_rule'
  tag stig_id: 'CNTR-K8-003160'
  tag fix_id: 'F-45682r919324_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe.one do
    describe kubelet do
      its('client_ca_file') { should_not be_nil }
      its('client_ca_file') { should_not be_more_permissive_than('0644') }
    end

    client_ca_file = kubelet_config_file.params.dig('authentication', 'x509', 'clientCAFile')
    if client_ca_file
      describe file(client_ca_file) do
        it { should_not be_more_permissive_than('0644') }
      end
    end
  end
end
