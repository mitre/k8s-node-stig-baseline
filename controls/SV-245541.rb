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

  describe.one do
    describe kubelet do
      its('streaming-connection-idle-timeout') { should_not be_nil }
      its('streaming-connection-idle-timeout') { should_not cmp 0 }
    end

    describe kubelet_config_file do
      its('streamingConnectionIdleTimeout') { should_not be_nil }
      its('streamingConnectionIdleTimeout') { should_not cmp 0 }
    end
  end
end
