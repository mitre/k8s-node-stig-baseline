require 'shellwords'

control 'SV-242459' do
  title 'The Kubernetes etcd must have file permissions set to 644 or more
restrictive.'
  desc 'The Kubernetes etcd key-value store provides a way to store data to the Control Plane. If these files can be changed, data to API object and Control Plane would be compromised.'
  desc 'check', 'Review the permissions of the Kubernetes etcd by using the command:

ls -AR /var/lib/etcd/*

If any of the files have permissions more permissive than "644", this is a finding.'
  desc 'fix', 'Change the permissions of the manifest files to "644" by executing the command:

chmod -R 644 /var/lib/etcd/*'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag gid: 'V-242459'
  tag rid: 'SV-242459r961863_rule'
  tag stig_id: 'CNTR-K8-003260'
  tag fix_id: 'F-45692r918199_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  only_if('This control applies only to control-plane nodes that manage etcd.', impact: 0.0) do
    input('node_roles').map(&:to_s).include?('control-plane') && input('etcd_managed_on_node')
  end

  expected_mode = input('kubernetes_file_modes')['etcd_data_files']
  data_dir = input('etcd_data_dir')
  etcd_data_directory = directory(data_dir)

  describe etcd_data_directory do
    it { should exist }
  end

  if etcd_data_directory.exist?
    etcd_search = command("find #{Shellwords.escape(data_dir)} -type f -print")
    etcd_files = etcd_search.stdout.lines.map(&:strip).reject(&:empty?)
    overly_permissive_files = etcd_files.select { |file_name| file(file_name).more_permissive_than?(expected_mode) }

    describe 'Kubernetes etcd data file discovery' do
      it "should successfully search #{data_dir}" do
        expect(etcd_search.exit_status).to eq(0), "Unable to search the etcd data directory: #{etcd_search.stderr.strip}"
      end
    end

    describe 'Kubernetes etcd data files' do
      it "should have mode #{expected_mode} or more restrictive" do
        expect(overly_permissive_files).to be_empty, "etcd files with permissions more permissive than #{expected_mode} from input('kubernetes_file_modes')['etcd_data_files']:\n\t- #{overly_permissive_files.join("\n\t- ")}"
      end
    end
  end
end
