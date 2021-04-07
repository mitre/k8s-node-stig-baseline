# encoding: UTF-8

control 'CNTR-K8-003200' do
  title 'The Kubernetes kubelet config must be owned by root.'
  desc  "The Kubernetes kubelet agent registers nodes with the API server and
performs health checks to containers within pods. If these files can be
modified, the information system would be unaware of pod or container
degradation. Many of the security settings within the document are implemented
through this file."
  desc  'rationale', ''
  desc  'check', "
    Review the Kubernetes Kubelet conf files by using the command:

    stat -c %U:%G /etc/kubernetes/kubelet.conf| grep -v root:root

    If the command returns any non root:root file permissions, this is a
finding.
  "
  desc  'fix', "
    Change the ownership of the kubelet.conf to root: root by executing the
command:

    chown root:root /etc/kubernetes/kubelet.conf
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'CNTR-K8-003200'
  tag rid: 'CNTR-K8-003200_rule'
  tag stig_id: 'CNTR-K8-003200'
  tag fix_id: 'F-CNTR-K8-003200_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
