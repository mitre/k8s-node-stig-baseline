require 'kubernetes_node_inputs'

control 'SV-242420' do
  title 'Kubernetes Kubelet must have the SSL Certificate Authority set.'
  desc 'Kubernetes container and pod configuration are maintained by Kubelet. Kubelet agents register nodes with the API Server, mount volume storage, and perform health checks for containers and pods. Anyone who gains access to Kubelet agents can effectively control applications within the pods and containers. Using authenticity protection, the communication can be protected against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

The communication session is protected by utilizing transport encryption protocols such as TLS. TLS provides the Kubernetes API Server with a means to authenticate sessions and encrypt traffic.

To enable encrypted communication for Kubelet, the clientCAFile must be set. This parameter gives the location of the SSL Certificate Authority file used to secure Kubelet communication.'
  desc 'check', 'On the Control Plane, run the command:
ps -ef | grep kubelet

If the "--client-ca-file" option exists, this is a finding.

Note the path to the config file (identified by --config).

Run the command:
grep -i clientCAFile <path_to_config_file>

If the setting "clientCAFile" is not set or contains no value, this is a finding.'
  desc 'fix', 'On the Control Plane, run the command:
ps -ef | grep kubelet

Remove the "--client-ca-file" option if present.

Note the path to the config file (identified by --config).

Edit the Kubernetes Kubelet config file:
Set the value of "clientCAFile" to a path containing an Approved Organizational Certificate.

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag gid: 'V-242420'
  tag rid: 'SV-242420r1043178_rule'
  tag stig_id: 'CNTR-K8-001420'
  tag fix_id: 'F-45653r918178_fix'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']

  only_if("This control applies only to control-plane nodes; input('node_roles') must include 'control-plane'.", impact: 0.0) do
    KubernetesNodeInputs.value('node_roles', input('node_roles')).include?('control-plane')
  end

  describe kubelet do
    its('client-ca-file') { should be_nil }
  end

  describe kubelet_config_file do
    its(%w[authentication x509 clientCAFile]) { should_not be_nil }
    its(%w[authentication x509 clientCAFile]) { should_not be_empty }
  end
end
