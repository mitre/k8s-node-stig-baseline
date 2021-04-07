# encoding: UTF-8

control 'CNTR-K8-003120' do
  title 'The Kubernetes component etcd must be owned by etcd.'
  desc  "The Kubernetes etcd key-value store provides a way to store data to
the Master Node. If these files can be changed, data to API object and the
master node would be compromised. The scheduler will implement the changes
immediately. Many of the security settings within the document are implemented
through this file."
  desc  'rationale', ''
  desc  'check', "
    Review the ownership of the Kubernetes etcd files by using the command:

    stat -c %U:%G /var/lib/etcd/* | grep -v etcd:etcd

    If the command returns any non etcd:etcd file permissions, this is a
finding.
  "
  desc  'fix', "
    Change the ownership of the manifest files to etcd:etcd by executing the
command:

    chown etcd:etcd /var/lib/etcd/*
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'CNTR-K8-003120'
  tag rid: 'CNTR-K8-003120_rule'
  tag stig_id: 'CNTR-K8-003120'
  tag fix_id: 'F-CNTR-K8-003120_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

