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

  if etcd.exist?
    data_dir = Array(etcd.params['data-dir']).join
    data_dir = process_env_var('etcd').params['ETCD_DATA_DIR'].to_s if data_dir.empty?
    data_dir = '/var/lib/etcd' if data_dir.empty?
    etcd_entries = command("find #{data_dir} -mindepth 1 -maxdepth 1 -print").stdout.lines.map(&:strip).reject(&:empty?)

    describe directory(data_dir) do
      it { should exist }
    end

    etcd_entries.each do |entry|
      describe file(entry) do
        it { should be_owned_by('etcd') }
        it { should be_grouped_into('etcd') }
      end
    end
  else
    describe 'ETCD process is not running on the target.' do
      skip
    end
  end
end
