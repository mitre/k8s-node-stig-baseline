# encoding: UTF-8

control 'CNTR-K8-003170' do
  title 'The Kubernetes Kubelet certificate authority must be owned by root.'
  desc  "The Kubernetes kube proxy kubeconfig contain the argument and setting
for the Master Nodes. These settings contain network rules for restricting
network communication between pods, clusters, and networks. If these files can
be changed, data traversing between the Kubernetes Control Panel components
would be compromised. Many of the security settings within the document are
implemented through this file."
  desc  'rationale', ''
  desc  'check', "
    Check if Kube-Proxy is running and obtain --kubeconfig parameter use the
following command:
    ps -ef | grep kube-proxy

    If Kube-Proxy exists:
    Review the permissions of the Kubernetes Kube Proxy by using the command:
    stat -c %a <location from --kubeconfig>

    If the command returns any non root:root file permissions, this is a
finding.
  "
  desc  'fix', "
    Change the permissions of the Kube Proxy to \"root\" by executing the
command:

    chown root:root <location from kubeconfig>.
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
end

