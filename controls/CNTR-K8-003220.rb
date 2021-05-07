# encoding: UTF-8

control 'CNTR-K8-003220' do
  title "The Kubernetes  kubeadm.conf must have file permissions set to 644
or more restrictive."
  desc  "The Kubernetes kubeadm.conf contains sensitive information regarding
the cluster nodes configuration. If this file can be modified, the Kubernetes
Platform Plane would be degraded or compromised for malicious intent. Many of
the security settings within the document are implemented through this file."
  desc  'rationale', ''
  desc  'check', "
    Review the permissions of the Kubernetes kubelet by using the command:

    stat -c %a /usr/bin/kubeadm

    If any of the files have permissions more permissive than \"644\", this is
a finding.
  "
  desc 'fix', "
    Change the permissions of Kubeadm to \"644\" by executing the command:

    chown 644 /usr/bin/kubeadm
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'CNTR-K8-003220'
  tag rid: 'CNTR-K8-003220_rule'
  tag stig_id: 'CNTR-K8-003220'
  tag fix_id: 'F-CNTR-K8-003220_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  kubeadm_path = input('kubeadm_path')

  if file(kubeadm_path).exist?
    describe file(kubeadm_path) do
      it { should_not be_more_permissive_than('0644') }
    end
  else
    describe "Kubeadm file #{kubeadm_path} not found on target" do
      skip
    end
  end
end
