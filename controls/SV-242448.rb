control 'SV-242448' do
  title 'The Kubernetes Kube Proxy kubeconfig must be owned by root.'
  desc 'The Kubernetes Kube Proxy kubeconfig contain the argument and setting for the Control Planes. These settings contain network rules for restricting network communication between pods, clusters, and networks. If these files can be changed, data traversing between the Kubernetes Control Panel components would be compromised. Many of the security settings within the document are implemented through this file.'
  desc 'check', 'Check if Kube-Proxy is running use the following command:
    ps -ef | grep kube-proxy

    If Kube-Proxy exists:
    Review the permissions of the Kubernetes Kube Proxy by using the command:
    stat -c   %U:%G <location from --kubeconfig>| grep -v root:root

    If the command returns any non root:root file permissions, this is a
finding.'
  desc 'fix', 'Change the ownership of the Kube Proxy to root:root by executing the
command:

    chown root:root <location from kubeconfig>.'
  desc 'caveat', "Set input('kube_proxy_expected') to false only when an alternative network proxy implementation makes kube-proxy inapplicable on this node."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'V-242448'
  tag rid: 'SV-242448r961863_rule'
  tag stig_id: 'CNTR-K8-003150'
  tag fix_id: 'F-45681r712699_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  only_if("This control is not applicable when input('kube_proxy_expected') is false because an alternative network proxy implementation is in use.", impact: 0.0) do
    input('kube_proxy_expected')
  end

  effective_config = kube_proxy_effective_config

  describe 'Kube-proxy process' do
    subject { effective_config.exist? }
    it { should eq true }
  end

  if effective_config.exist?
    describe effective_config do
      its('errors') { should be_empty }
    end

    if effective_config.errors.empty?
      describe "Kube-proxy kubeconfig #{effective_config.kubeconfig_path}" do
        subject { effective_config.kubeconfig_file }
        it { should be_owned_by('root') }
        it { should be_grouped_into('root') }
      end
    end
  end
end
