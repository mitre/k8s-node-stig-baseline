# encoding: UTF-8

control 'CNTR-K8-000900' do
  title 'The Kubernetes manifests must have least privileges.'
  desc  "The manifest files contain the runtime configuration of the API
server, scheduler, controller, and etcd. If an attacker can gain access to
these files, changes can be made to open vulnerabilities and bypass user
authorizations inherent within Kubernetes with RBAC implemented.


  "
  desc  'rationale', ''
  desc  'check', "
    On the Master node, change to the /etc/kubernetes/manifest directory. Run
the command:

    ls -l *

    Each manifest file must have permissions \"644\" or more restrictive.

    If any manifest file is less restrictive than \"644\", this is a finding.
  "
  desc  'fix', "
    On the Master node, change to the /etc/kubernetes/manifest directory. Run
the command:

    chmod 644 *

    To verify the change took place, run the command:

    ls -l *

    All the manifest files should now have privileges of \"644\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-CTR-000310'
  tag satisfies: ['SRG-APP-000133-CTR-000310', 'SRG-APP-000133-CTR-000295']
  tag gid: 'CNTR-K8-000900'
  tag rid: 'CNTR-K8-000900_rule'
  tag stig_id: 'CNTR-K8-000900'
  tag fix_id: 'F-CNTR-K8-000900_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

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

