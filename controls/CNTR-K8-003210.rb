# encoding: UTF-8

control 'CNTR-K8-003210' do
  title 'The Kubernetes kubeadm must be owned by root.'
  desc  "The Kubernetes kubeeadm.conf contains sensitive information regarding
the cluster nodes configuration. If this file can be modified, the Kubernetes
Platform Plane would be degraded or compromised for malicious intent. Many of
the security settings within the document are implemented through this file."
  desc  'rationale', ''
  desc  'check', "
    Review the Kubernetes kubeadm by using the command:

    stat -c %U:%G /usr/bin/kubeadm| grep -v root:root

    If the command returns any non root:root file permissions, this is a
finding.
  "
  desc 'fix', "
    Change the ownership of the kubeadm to root: root by executing the command:

    chown root:root /user/bin/kubeadm
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'CNTR-K8-003210'
  tag rid: 'CNTR-K8-003210_rule'
  tag stig_id: 'CNTR-K8-003210'
  tag fix_id: 'F-CNTR-K8-003210_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe  file(input('kubeadm_path')) do
    it { should be_owned_by('root') }
    it { should be_grouped_into('root') }
  end
end
