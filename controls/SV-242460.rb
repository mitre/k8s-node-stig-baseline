control 'SV-242460' do
  title 'The Kubernetes admin kubeconfig must have file permissions set to 644 or more restrictive.'
  desc 'The Kubernetes admin kubeconfig files contain the arguments and settings for the Control Plane services. These services are controller and scheduler. If these files can be changed, the scheduler will be implementing the changes immediately.'
  desc 'check', 'Review the permissions of the Kubernetes config files by using the command:

    stat -c %a /etc/kubernetes/admin.conf
    stat -c %a /etc/kubernetes/scheduler.conf
    stat -c %a /etc/kubernetes/controller-manager.conf

    If any of the files are have permissions more permissive than "644", this
is a finding.'
  desc 'fix', 'Change the permissions of the conf files to "644" by executing the
command:

    chmod 644 /etc/kubernetes/admin.conf
    chmod 644 /etc/kubernetes/scheduler.conf
    chmod 644 /etc/kubernetes/controller-manager.conf'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag gid: 'V-242460'
  tag rid: 'SV-242460r961863_rule'
  tag stig_id: 'CNTR-K8-003270'
  tag fix_id: 'F-45693r712735_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  kubernetes_conf_files = Array(input('kubernetes_conf_files'))
  overly_permissive_files = kubernetes_conf_files.reject do |file_name|
    conf_file = file(file_name)
    conf_file.exist? && !conf_file.more_permissive_than?('0644')
  end

  describe 'Configured Kubernetes conf files' do
    it 'should include at least one path' do
      expect(kubernetes_conf_files).not_to be_empty, "input('kubernetes_conf_files') must include at least one path"
    end
    it 'should exist and have mode 0644 or more restrictive' do
      expect(overly_permissive_files).to be_empty, "Missing files or files with permissions more permissive than 0644:\n\t- #{overly_permissive_files.join("\n\t- ")}"
    end
  end
end
