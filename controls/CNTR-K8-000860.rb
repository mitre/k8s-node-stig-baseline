# encoding: UTF-8

control 'CNTR-K8-000860' do
  title 'The Kubernetes manifests must be owned by root.'
  desc  "The manifest files contain the runtime configuration of the API
server, proxy, scheduler, controller, and etcd. If an attacker can gain access
to these files, changes can be made to open vulnerabilities and bypass user
authorizations inherit within Kubernetes with RBAC implemented."
  desc  'rationale', ''
  desc  'check', "
    On the Master node, change to the /etc/kubernetes/manifest directory. Run
the command:

    ls -l *

    Each manifest file must be owned by root:root.

    If any manifest file is not owned by root:root, this is a finding.
  "
  desc  'fix', "
    On the Master node, change to the /etc/kubernetes/manifest directory. Run
the command:

    chown root:root *

    To verify the change took place, run the command:

    ls -l *

    All the manifest files should be owned by root:root.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-CTR-000295'
  tag gid: 'CNTR-K8-000860'
  tag rid: 'CNTR-K8-000860_rule'
  tag stig_id: 'CNTR-K8-000860'
  tag fix_id: 'F-CNTR-K8-000860_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  manifests_path = input('manifests_path')
  manifests_files = command('find /etc/kubernetes/manifests -type f').stdout.split

  if manifests_files.empty?
    impact 0.0
    desc 'caveat', "Kubernetes Manifest files not present of the target at specified path #{manifests_path}."

    describe "Kubernetes Manifest files not present of the target at specified path #{manifests_path}."
      skip
    end
  end

  manifests_files.each do |file_name|
    describe file(file_name) do
      it { should be_owned_by('root')}
      it { should be_grouped_into('root')}
    end
  end
end

