# encoding: UTF-8

control 'CNTR-K8-003240' do
  title 'The Kubernetes kubelet config must be owned by root.'
  desc  "The Kubernetes kubelet agent registers nodes with the API Server and
performs health checks to containers within pods. If this file can be modified,
the information system would be unaware of pod or container degradation."
  desc  'rationale', ''
  desc  'check', "
    Review the Kubernetes Kubeadm kubelet conf file by using the command:

    stat -c %U:%G /var/lib/kubelet/config.yaml| grep -v root:root

    If the command returns any non root:root file permissions, this is a
finding.
  "
  desc  'fix', "
    Change the ownership of the kubelet config to \"root: root\" by executing
the command:

    chown root:root /var/lib/kubelet/config.yaml
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001330'
  tag gid: 'CNTR-K8-003240'
  tag rid: 'CNTR-K8-003240_rule'
  tag stig_id: 'CNTR-K8-003240'
  tag fix_id: 'F-CNTR-K8-003240_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe file(kubelet.params['config'].first) do
    it { should be_owned_by('root')}
    it { should be_grouped_into('root')}
  end
end

