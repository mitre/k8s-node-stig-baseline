# encoding: UTF-8

control 'CNTR-K8-003190' do
  title "The Kubernetes kubelet config must have file permissions set to 644 or
more restrictive."
  desc  "The Kubernetes kubelet agent registers nodes with the API Server,
mounts volume storage for pods, and performs health checks to containers within
pods. If these files can be modified, the information system would be unaware
of pod or container degradation. Many of the security settings within the
document are implemented through this file."
  desc  'rationale', ''
  desc  'check', "
    Review the permissions of the Kubernetes Kubelet conf by using the command:

    stat -c %a  /etc/kubernetes/kubelet.conf

    If any of the files are have permissions more permissive than \"644\", this
is a finding.
  "
  desc  'fix', "
    Change the permissions of the Kubelet to \"644\" by executing the command:

    chown 644 /etc/kubernetes/kubelet.conf
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'CNTR-K8-003190'
  tag rid: 'CNTR-K8-003190_rule'
  tag stig_id: 'CNTR-K8-003190'
  tag fix_id: 'F-CNTR-K8-003190_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

