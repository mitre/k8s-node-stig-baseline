require 'kubernetes_node_inputs'

control 'SV-245541' do
  title 'Kubernetes Kubelet must not disable timeouts.'
  desc 'Idle connections from the Kubelet can be used by unauthorized users to perform malicious activity to the nodes, pods, containers, and cluster within the Kubernetes Control Plane. Setting the streamingConnectionIdleTimeout defines the maximum time an idle session is permitted prior to disconnect. Setting the value to "0" never disconnects any idle sessions. Idle timeouts must never be set to "0" and should be defined at "5m" (the default is 4hr).'
  desc 'check', 'Follow these steps to check streaming-connection-idle-timeout:

1. On the Control Plane, run the command:

ps -ef | grep kubelet

If the "--streaming-connection-idle-timeout" option exists, this is a finding.

Note the path to the config file (identified by --config).

2. Run the command:

grep -i streamingConnectionIdleTimeout <path_to_config_file>

If the setting "streamingConnectionIdleTimeout" is set to less than "5m" or is not configured, this is a finding.'
  desc 'fix', 'Follow these steps to configure streaming-connection-idle-timeout:
1. On the Control Plane, run the command:
ps -ef | grep kubelet

Remove the "--streaming-connection-idle-timeout" option if present.

Note the path to the config file (identified by --config).

2. Edit the Kubernetes Kubelet file in the --config directory on the Kubernetes Control Plane:

Set the argument "streamingConnectionIdleTimeout" to a value of "5m".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000190-CTR-000500'
  tag gid: 'V-245541'
  tag rid: 'SV-245541r1069469_rule'
  tag stig_id: 'CNTR-K8-001300'
  tag fix_id: 'F-48771r1069468_fix'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']

  only_if("This control applies only to control-plane nodes; input('node_roles') must include 'control-plane'.", impact: 0.0) do
    KubernetesNodeInputs.value('node_roles', input('node_roles')).include?('control-plane')
  end

  describe kubelet do
    its('streaming-connection-idle-timeout') { should be_nil }
  end

  timeout = kubelet_config_file.params['streamingConnectionIdleTimeout'].to_s
  units = { 'h' => 3600, 'm' => 60, 's' => 1, 'ms' => 0.001, 'us' => 0.000001, 'µs' => 0.000001, 'ns' => 0.000000001 }
  duration_parts = timeout.scan(/(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/)
  parsed_timeout = (duration_parts.sum { |value, unit| value.to_f * units.fetch(unit) } if !timeout.empty? && duration_parts.flatten.join == timeout)

  describe 'Kubelet streamingConnectionIdleTimeout in seconds' do
    subject { parsed_timeout }
    it { should_not be_nil }
    it { should be >= KubernetesNodeInputs.value('streaming_connection_idle_timeout_seconds', input('streaming_connection_idle_timeout_seconds')) }
  end
end
