# encoding: UTF-8

control 'CNTR-K8-000400' do
  title 'Kubernetes Worker Nodes must not have sshd service running.'
  desc  "Worker Nodes are maintained and monitored by the Master Node. Direct
access and manipulation of the nodes should not take place by administrators.
Worker nodes should be treated as immutable and updated via replacement rather
than in-place upgrades."
  desc  'rationale', ''
  desc  'check', "
    Log in to each worker node. Verify that the sshd service is not running. To
validate that the service is not running, run the command:

    systemctl status sshd

    If the service sshd is active (running), this is a finding.

    Note: If console access is not available, SSH access can be attempted. If
the worker nodes cannot be reached, this requirement is \"not a finding\".
  "
  desc  'fix', "
    To stop the sshd service, run the command:

    systemctl stop sshd

    Note: If access to the worker node is through an SSH session, it is
important to realize there are two requirements for disabling and stopping the
sshd service and they should be done during the same SSH session. Disabling the
service must be performed first and then the service stopped to guarantee both
settings can be made if the session is interrupted.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag gid: 'CNTR-K8-000400'
  tag rid: 'CNTR-K8-000400_rule'
  tag stig_id: 'CNTR-K8-000400'
  tag fix_id: 'F-CNTR-K8-000400_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

