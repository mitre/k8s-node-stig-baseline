require 'kubernetes_node_inputs'

control 'SV-242446' do
  title 'The Kubernetes conf files must be owned by root.'
  desc 'The Kubernetes conf files contain the arguments and settings for the Control Plane services. These services are controller and scheduler. If these files can be changed, the scheduler will be implementing the changes immediately. Many of the security settings within the document are implemented through this file.'
  desc 'check', 'Review the Kubernetes conf files by using the command:

    stat -c %U:%G /etc/kubernetes/admin.conf | grep -v root:root
    stat -c %U:%G /etc/kubernetes/scheduler.conf | grep -v root:root
    stat -c %U:%G /etc/kubernetes/controller-manager.conf | grep -v root:root

    If the command returns any non root:root file permissions, this is a
finding.'
  desc 'fix', 'Change the ownership of the conf files to root: root by executing the
command:

    chown root:root /etc/kubernetes/admin.conf
    chown root:root /etc/kubernetes/scheduler.conf
    chown root:root /etc/kubernetes/controller-manager.conf'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'V-242446'
  tag rid: 'SV-242446r961863_rule'
  tag stig_id: 'CNTR-K8-003130'
  tag fix_id: 'F-45679r712693_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  kubernetes_conf_files = Array(KubernetesNodeInputs.value('kubernetes_conf_files', input('kubernetes_conf_files')))
  incorrectly_owned_files = kubernetes_conf_files.reject do |file_name|
    conf_file = file(file_name)
    conf_file.exist? && conf_file.owned_by?('root') && conf_file.grouped_into?('root')
  end

  describe 'Configured Kubernetes conf files' do
    it 'should include at least one path' do
      expect(kubernetes_conf_files).not_to be_empty, "input('kubernetes_conf_files') must include at least one path"
    end
    it 'should exist and be owned by root:root' do
      expect(incorrectly_owned_files).to be_empty, "Missing files or files not owned by root:root:\n\t- #{incorrectly_owned_files.join("\n\t- ")}"
    end
  end
end
