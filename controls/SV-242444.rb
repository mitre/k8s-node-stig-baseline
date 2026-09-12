require 'kubernetes_node_inputs'
require 'shellwords'

control 'SV-242444' do
  title 'The Kubernetes component manifests must be owned by root.'
  desc 'The Kubernetes manifests are those files that contain the arguments and settings for the Control Plane services. These services are etcd, the api server, controller, proxy, and scheduler. If these files can be changed, the scheduler will be implementing the changes immediately. Many of the security settings within the document are implemented through these manifests.'
  desc 'check', 'Review the ownership of the Kubernetes manifests files by using the command:

    stat -c %U:%G /etc/kubernetes/manifests/* | grep -v root:root

    If the command returns any non root:root file permissions, this is a
finding.'
  desc 'fix', 'Change the ownership of the manifest files to root: root by executing the
command:

    chown root:root /etc/kubernetes/manifests/*'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'V-242444'
  tag rid: 'SV-242444r961863_rule'
  tag stig_id: 'CNTR-K8-003110'
  tag fix_id: 'F-45677r712687_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  manifests_path = KubernetesNodeInputs.value('manifests_path', input('manifests_path'))
  manifest_search = command("find -L #{Shellwords.escape(manifests_path)} \\( -type f -o -type l \\) -print0")
  manifests_files = manifest_search.stdout.split("\0").reject(&:empty?)
  incorrectly_owned_files = manifests_files.reject do |file_name|
    manifest_file = file(file_name)
    manifest_file.owned_by?('root') && manifest_file.grouped_into?('root')
  end

  describe 'Kubernetes manifest file discovery' do
    it "should successfully search #{manifests_path}" do
      expect(manifest_search.exit_status).to eq(0), "Unable to search for Kubernetes manifest files: #{manifest_search.stderr.strip}"
    end
  end

  describe 'Kubernetes manifest files' do
    it 'should be owned by root:root' do
      expect(incorrectly_owned_files).to be_empty, "Manifest files not owned by root:root:\n\t- #{incorrectly_owned_files.join("\n\t- ")}"
    end
  end
end
