control 'SV-242408' do
  title 'The Kubernetes manifest files must have least privileges.'
  desc 'The manifest files contain the runtime configuration of the API
server, scheduler, controller, and etcd. If an attacker can gain access to
these files, changes can be made to open vulnerabilities and bypass user
authorizations inherent within Kubernetes with RBAC implemented.'
  desc 'check', 'On both Control Plane and Worker Nodes, change to the /etc/kubernetes/manifest directory. Run the command:
ls -l *

Each manifest file must have permissions "644" or more restrictive.

If any manifest file is less restrictive than "644", this is a finding.'
  desc 'fix', 'On both Control Plane and Worker Nodes, change to the /etc/kubernetes/manifest directory. Run the command:
chmod 644 *

To verify the change took place, run the command:
ls -l *

All the manifest files should now have privileges of "644".'
  desc 'caveat', "Kubernetes Manifest files not present of the target at specified path #{manifests_path}."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-CTR-000310'
  tag satisfies: ['SRG-APP-000133-CTR-000310', 'SRG-APP-000133-CTR-000295', 'SRG-APP-000516-CTR-001335']
  tag gid: 'V-242408'
  tag rid: 'SV-242408r960960_rule'
  tag stig_id: 'CNTR-K8-000900'
  tag fix_id: 'F-45641r918173_fix'
  tag cci: ['CCI-001499', 'CCI-000366']
  tag nist: ['CM-5 (6)', 'CM-6 b']

  manifests_path = input('manifests_path')
  expected_mode = input('kubernetes_file_modes')['manifest_files']
  manifest_search = command("find #{manifests_path} -type f -print")
  manifests_files = manifest_search.stdout.lines.map(&:strip).reject(&:empty?)
  overly_permissive_files = manifests_files.select { |file_name| file(file_name).more_permissive_than?(expected_mode) }

  describe 'Kubernetes manifest file discovery' do
    it "should successfully search #{manifests_path}" do
      expect(manifest_search.exit_status).to eq(0), "Unable to search for Kubernetes manifest files: #{manifest_search.stderr.strip}"
    end
  end

  describe 'Kubernetes manifest files' do
    it "should have mode #{expected_mode} or more restrictive" do
      expect(overly_permissive_files).to be_empty, "Manifest files with permissions more permissive than #{expected_mode} from input('kubernetes_file_modes')['manifest_files']:\n\t- #{overly_permissive_files.join("\n\t- ")}"
    end
  end
end
