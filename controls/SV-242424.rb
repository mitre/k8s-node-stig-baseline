control 'SV-242424' do
  title 'Kubernetes Kubelet must enable tlsPrivateKeyFile for client authentication to secure service.'
  desc 'Kubernetes container and pod configuration are maintained by Kubelet. Kubelet agents register nodes with the API Server, mount volume storage, and perform health checks for containers and pods. Anyone who gains access to Kubelet agents can effectively control applications within the pods and containers. Using authenticity protection, the communication can be protected against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

The communication session is protected by utilizing transport encryption protocols such as TLS. TLS provides the Kubernetes API Server with a means to authenticate sessions and encrypt traffic.

To enable encrypted communication for Kubelet, the tlsPrivateKeyFile must be set. This parameter gives the location of the SSL Certificate Authority file used to secure Kubelet communication.'
  desc 'check', 'On the Control Plane, run the command:
ps -ef | grep kubelet

If the "--tls-private-key-file" option exists, this is a finding.

Note the path to the config file (identified by --config).

Run the command:
grep -i tlsPrivateKeyFile <path_to_config_file>

If the setting "tlsPrivateKeyFile" is not set or contains no value, this is a finding.'
  desc 'fix', 'On the Control Plane, run the command:
ps -ef | grep kubelet

Remove the "--tls-private-key-file" option if present.

Note the path to the config file (identified by --config).

Edit the Kubernetes Kubelet config file:
Set "tlsPrivateKeyFile" to  a path containing the appropriate private key.

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag gid: 'V-242424'
  tag rid: 'SV-242424r1043178_rule'
  tag stig_id: 'CNTR-K8-001460'
  tag fix_id: 'F-45657r918181_fix'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']

  only_if("This control applies only to control-plane nodes; input('node_roles') must include 'control-plane'.", impact: 0.0) do
    input('node_roles').include?('control-plane')
  end

  describe kubelet do
    its('tls-private-key-file') { should be_nil }
  end

  tls_private_key_file = kubelet_config_file.params['tlsPrivateKeyFile']
  describe 'Kubelet tlsPrivateKeyFile configuration' do
    it 'is configured as a non-empty path' do
      expect(tls_private_key_file).to be_a(String), 'tlsPrivateKeyFile must be configured as a string path'
      expect(tls_private_key_file.strip).not_to be_empty, 'tlsPrivateKeyFile must not be empty'
    end
  end
end
