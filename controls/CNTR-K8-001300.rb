# encoding: UTF-8

control 'CNTR-K8-001300' do
  title 'Kubernetes Kubelet must not disable timeouts.'
  desc  "Idle connections from the Kubelet can be use by unauthorized users to
perform malicious activity to the nodes, pods, containers, and cluster within
the Kubernetes Control Plane. Setting the streaming connection idle timeout
defines the maximum time an idle session is permitted prior to disconnect.
Setting the value to \"0\" never disconnects any idle sessions. Idle timeouts
must never be set to \"0\" and should be defined at a minimum of \"5 minutes\"."
  desc  'rationale', ''
  desc  'check', "
    Change to the /etc/sysconfig/ directory on the Kubernetes Master Node. Run
the command:

    grep -i streaming-connection-idle-timeout kubelet

    If the setting streaming-connection-idle-timeout is set to \"0\" or the
parameter is not configured in the Kubernetes Kubelet, this is a finding.
  "
  desc  'fix', "
    Edit the Kubernetes Kubelet file in the /etc/sysconfig directory on the
Kubernetes Master Node. Set the argument
\"--streaming-connection-idle-timeout\" to a value other than \"0\". Reset
Kubelet service using the following command:

    service kubelet restart
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000190-CTR-000500'
  tag gid: 'CNTR-K8-001300'
  tag rid: 'CNTR-K8-001300_rule'
  tag stig_id: 'CNTR-K8-001300'
  tag fix_id: 'F-CNTR-K8-001300_fix'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end

