# encoding: UTF-8

control 'V-242454' do
  title 'The Kubernetes kubeadm must be owned by root.'
  desc  "The Kubernetes kubeadm.conf contains sensitive information regarding
the cluster nodes configuration. If this file can be modified, the Kubernetes
Platform Plane would be degraded or compromised for malicious intent. Many of
the security settings within the document are implemented through this file."
  desc  'rationale', ''
  desc  'check', "
    Review the Kubeadm.conf file :

    Get the path for Kubeadm.conf by running:

    systemctl status kubelet

  Note the configuration file installed by the kubeadm is written to

  default Location: /etc/systemd/system/kubelet.service.d/10-kubeadm.conf

    stat -c %U:%G <Kubeadm.conf path> | grep -v root:root

If the command returns any non root:root file permissions, this is a finding.
  "
  desc 'fix', "
    Change the ownership of the kubeadm.conf to root: root by executing the
command:

    chown root:root <Kubeadm.conf path>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'V-242454'
  tag rid: 'SV-242454r712718_rule'
  tag stig_id: 'CNTR-K8-003210'
  tag fix_id: 'F-45687r712717_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  kubeadm_conf_path = input('kubeadm_conf_path')

  if file(kubeadm_conf_path).exist?
    describe file(kubeadm_conf_path) do
      it { should be_owned_by('root') }
      it { should be_grouped_into('root') }
    end
  else
    describe "Kubeadm file #{kubeadm_conf_path} not found on target" do
      skip
    end
  end
end
