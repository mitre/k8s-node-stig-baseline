require 'shellwords'

control 'SV-242445' do
  title 'The Kubernetes component etcd must be owned by etcd.'
  desc 'The Kubernetes etcd key-value store provides a way to store data to the Control Plane. If these files can be changed, data to API object and the Control Plane would be compromised. The scheduler will implement the changes immediately. Many of the security settings within the document are implemented through this file.'
  desc 'check', 'Review the ownership of the Kubernetes etcd files by using the command:

    stat -c %U:%G /var/lib/etcd/* | grep -v etcd:etcd

    If the command returns any non etcd:etcd file permissions, this is a
finding.'
  desc 'fix', 'Change the ownership of the manifest files to etcd:etcd by executing the
command:

    chown etcd:etcd /var/lib/etcd/*'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'V-242445'
  tag rid: 'SV-242445r961863_rule'
  tag stig_id: 'CNTR-K8-003120'
  tag fix_id: 'F-45678r712690_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  only_if("This control applies only to control-plane nodes; input('node_roles') does not include 'control-plane'.", impact: 0.0) do
    input('node_roles').map(&:to_s).include?('control-plane')
  end
  only_if("This control is not applicable because input('etcd_managed_on_node') is false for an external etcd topology.", impact: 0.0) do
    input('etcd_managed_on_node')
  end

  data_dir = input('etcd_data_dir')
  etcd_data_directory = directory(data_dir)

  describe etcd_data_directory do
    it { should exist }
  end

  if etcd_data_directory.exist?
    etcd_search = command("find #{Shellwords.escape(data_dir)} -mindepth 1 -maxdepth 1 -print")
    etcd_entries = etcd_search.stdout.lines.map(&:strip).reject(&:empty?)
    incorrectly_owned_entries = etcd_entries.reject do |entry|
      etcd_entry = file(entry)
      etcd_entry.owned_by?('etcd') && etcd_entry.grouped_into?('etcd')
    end

    describe 'Kubernetes etcd data discovery' do
      it "should successfully search #{data_dir}" do
        expect(etcd_search.exit_status).to eq(0), "Unable to search the etcd data directory: #{etcd_search.stderr.strip}"
      end
    end

    describe 'Kubernetes etcd data entries' do
      it 'should be owned by etcd:etcd' do
        expect(incorrectly_owned_entries).to be_empty, "etcd data entries not owned by etcd:etcd:\n\t- #{incorrectly_owned_entries.join("\n\t- ")}"
      end
    end
  end
end
