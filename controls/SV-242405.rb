control 'SV-242405' do
  title 'The Kubernetes manifests must be owned by root.'
  desc 'The manifest files contain the runtime configuration of the API
server, proxy, scheduler, controller, and etcd. If an attacker can gain access
to these files, changes can be made to open vulnerabilities and bypass user
authorizations inherit within Kubernetes with RBAC implemented.'
  desc 'check', 'On the Control Plane, change to the /etc/kubernetes/manifest directory. Run the command:
ls -l *

Each manifest file must be owned by root:root.

If any manifest file is not owned by root:root, this is a finding.'
  desc 'fix', 'On the Control Plane, change to the /etc/kubernetes/manifest directory. Run the command:
chown root:root *

To verify the change took place, run the command:
ls -l *

All the manifest files should be owned by root:root.'
  desc 'caveat', "Kubernetes Manifest files not present of the target at specified path #{manifests_path}."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-CTR-000295'
  tag gid: 'V-242405'
  tag rid: 'SV-242405r960960_rule'
  tag stig_id: 'CNTR-K8-000860'
  tag fix_id: 'F-45638r863813_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  manifests_path = input('manifests_path')
  manifest_search = command("find #{manifests_path} -type f -print")
  manifests_files = manifest_search.stdout.lines.map(&:strip).reject(&:empty?)
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
