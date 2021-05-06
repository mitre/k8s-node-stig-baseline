# encoding: UTF-8

control 'CNTR-K8-003250' do
  title "The Kubernetes API Server must have file permissions set to 644 or
more restrictive."
  desc  "The Kubernetes manifests are those files that contain the arguments
and settings for the Master Node services. These services are etcd, the API
Server, controller, proxy, and scheduler. If these files can be changed, the
scheduler will be implementing the changes immediately. Many of the security
settings within the document are implemented through these manifests."
  desc  'rationale', ''
  desc  'check', "
    Review the permissions of the Kubernetes Kubelet by using the command:

    stat -c %a  /etc/kubernetes/manifests/*

    If any of the files are have permissions more permissive than \"644\", this
is a finding.
  "
  desc 'fix', "
    Change the permissions of the manifest files to \"root: root\" by executing
the command:

    chown root:root /etc/kubernetes/manifests/*
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag gid: 'CNTR-K8-003250'
  tag rid: 'CNTR-K8-003250_rule'
  tag stig_id: 'CNTR-K8-003250'
  tag fix_id: 'F-CNTR-K8-003250_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  manifests_path = input('manifests_path')
  manifests_files = command("find #{manifests_path} -type f").stdout.split

  if manifests_files.empty?
    desc 'caveat', "Kubernetes Manifest files not present of the target at specified path #{manifests_path}."

    describe "Kubernetes Manifest files not present of the target at specified path #{manifests_path}." do
      skip
    end
  end

  manifests_files.each do |file_name|
    describe file(file_name) do
      it { should_not be_more_permissive_than('0644') }
    end
  end
end
