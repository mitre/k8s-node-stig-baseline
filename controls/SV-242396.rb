require 'json'
require 'shellwords'

control 'SV-242396' do
  title 'Kubernetes Kubectl cp command must give expected access and results.'
  desc 'One of the tools heavily used to interact with containers in the
Kubernetes cluster is kubectl. The command is the tool System Administrators
used to create, modify, and delete resources. One of the capabilities of the
tool is to copy files to and from running containers (i.e., kubectl cp). The
command uses the "tar" command of the container to copy files from the
container to the host executing the "kubectl cp" command. If the "tar"
command on the container has been replaced by a malicious user, the command can
copy files anywhere on the host machine. This flaw has been fixed in later
versions of the tool. It is recommended to use kubectl versions newer than
1.12.9.'
  desc 'check', 'From the Control Plane and each Worker node, check the version of kubectl by executing the command:

kubectl version --client

If the Control Plane or any Worker nodes are not using kubectl version 1.12.9 or newer, this is a finding.'
  desc 'fix', 'Upgrade the Control Plane and Worker nodes to the latest version of kubectl.'
  desc 'caveat', 'kubectl command available on target on the target.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-CTR-000090'
  tag gid: 'V-242396'
  tag rid: 'SV-242396r1137638_rule'
  tag stig_id: 'CNTR-K8-000430'
  tag fix_id: 'F-45629r863789_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  kubectl_minversion = input('kubectl_minversion')
  kubectl_version = command("#{Shellwords.escape(input('kubectl_path'))} version --client --output=json")

  describe 'kubectl client version command' do
    subject { kubectl_version }
    its('exit_status') { should cmp 0 }
  end

  if kubectl_version.exit_status.zero?
    begin
      client = JSON.parse(kubectl_version.stdout)
    rescue JSON::ParserError
      client = {}
    end
    reported = client.is_a?(Hash) ? client.dig('clientVersion', 'gitVersion') : nil

    # kubectl prefixes gitVersion with "v", which Gem::Version cannot parse.
    reported_version = reported.to_s[/\Av?(\d+\.\d+(?:\.\d+)?)/, 1]
    minimum_version = kubectl_minversion.to_s[/\Av?(\d+\.\d+(?:\.\d+)?)/, 1]

    describe 'kubectl client version' do
      it "is reported and is at least #{kubectl_minversion}" do
        expect(reported_version).not_to be_nil, "Could not read a version from kubectl output: #{reported.inspect}"
        expect(minimum_version).not_to be_nil, "input('kubectl_minversion') is not a version number: #{kubectl_minversion.inspect}"
        expect(Gem::Version.new(reported_version)).to be >= Gem::Version.new(minimum_version),
                                                      "kubectl is #{reported}, which is older than the required #{kubectl_minversion}"
      end
    end
  end
end
