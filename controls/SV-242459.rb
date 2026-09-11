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

  if etcd.exist?
    data_dir = Array(etcd.params['data-dir']).join
    data_dir = process_env_var('etcd').params['ETCD_DATA_DIR'].to_s if data_dir.empty?
    data_dir = '/var/lib/etcd' if data_dir.empty?
    etcd_files = command("find #{data_dir} -type f -print").stdout.lines.map(&:strip).reject(&:empty?)

    describe directory(data_dir) do
      it { should exist }
    end

    etcd_files.each do |file_name|
      describe file(file_name) do
        it { should_not be_more_permissive_than('0644') }
      end
    end
  else
    describe 'ETCD process is not running on the target.' do
      skip
    end
  end
end
