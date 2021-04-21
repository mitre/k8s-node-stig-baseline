# encoding: UTF-8

control 'CNTR-K8-003260' do
  title "The Kubernetes etcd must have file permissions set to 644 or more
restrictive."
  desc  "The Kubernetes etcd key-value store provides a way to store data to
the Master Node. If these files can be changed, data to API object and master
node would be compromised."
  desc  'rationale', ''
  desc  'check', "
    Review the permissions of the Kubernetes etcd by using the command:

    stat -c %a  /var/lib/etcd/*

    If any of the files are have permissions more permissive than \"644\", this
is a finding.
  "
  desc  'fix', "
    Change the permissions of the manifest files to \"644\" by executing the
command:

    chmod 644/var/lib/etcd/*
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag gid: 'CNTR-K8-003260'
  tag rid: 'CNTR-K8-003260_rule'
  tag stig_id: 'CNTR-K8-003260'
  tag fix_id: 'F-CNTR-K8-003260_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  unless etcd.exist?
    impact 0.0
    desc 'caveat','ETCD process is not running on the target.'
  end

  describe.one do
    describe file(etcd.params['data-dir']) do
      it { should_not be_more_permissive_than('0644')}
    end

    describe file(process_env_var('etcd').params['ETCD_DATA_DIR']) do
      it { should_not be_more_permissive_than('0644')}
    end
  end

