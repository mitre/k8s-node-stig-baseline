require 'json'
require 'shellwords'

control 'SV-242443' do
  title 'Kubernetes must contain the latest updates as authorized by IAVMs,
CTOs, DTMs, and STIGs.'
  desc 'Kubernetes software must stay up to date with the latest patches,
service packs, and hot fixes. Not updating the Kubernetes control plane will
expose the organization to vulnerabilities.

    Flaws discovered during security assessments, continuous monitoring,
incident response activities, or information system error handling must also be
addressed expeditiously.

    Organization-defined time periods for updating security-relevant container
platform components may vary based on a variety of factors including, for
example, the security category of the information system or the criticality of
the update (i.e., severity of the vulnerability related to the discovered
flaw).

    This requirement will apply to software patch management solutions that are
used to install patches across the enclave and also to applications themselves
that are not part of that patch management solution. For example, many browsers
today provide the capability to install their own patch software. Patch
criticality, as well as system criticality will vary. Therefore, the tactical
situations regarding the patch management process will also vary. This means
that the time period utilized must be a configurable parameter. Time frames for
application of security-relevant software updates may be dependent upon the
IAVM process.

    The container platform components will be configured to check for and
install security-relevant software updates within an identified time period
from the availability of the update. The container platform registry will
ensure the images are current. The specific time period will be defined by an
authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', 'Authenticate on the Kubernetes Control Plane. Run the command:
kubectl version --short

If kubectl version has a setting not supporting Kubernetes skew policy, this is a finding.

Note: Kubernetes Skew Policy can be found at: https://kubernetes.io/docs/setup/release/version-skew-policy/#supported-versions'
  desc 'fix', 'Upgrade Kubernetes to the supported version. Institute and
adhere to the policies and procedures to ensure that patches are consistently
applied within the time allowed.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000456-CTR-001125'
  tag gid: 'V-242443'
  tag rid: 'SV-242443r1137649_rule'
  tag stig_id: 'CNTR-K8-002720'
  tag fix_id: 'F-45676r712684_fix'
  tag cci: ['CCI-002605', 'CCI-002635']
  tag nist: ['SI-2 c', 'SI-3 (10) (a)']

  desc 'scope', 'Host-local portion of this STIG requirement; combine with the sibling cluster profile.'

  only_if("This control applies to control-plane nodes declared in input('node_roles').", impact: 0.0) do
    input('node_roles').include?('control-plane')
  end

  version_command = command("#{Shellwords.escape(input('kubectl_path'))} --kubeconfig=#{Shellwords.escape(input('kubectl_kubeconfig_path'))} version --output=json")
  describe 'kubectl retrieves its client version and the target API Server version' do
    subject { version_command }
    its('exit_status') { should cmp 0 }
  end

  if version_command.exit_status == 0
    begin
      versions = JSON.parse(version_command.stdout)
    rescue JSON::ParserError
      versions = {}
    end
    client = versions.is_a?(Hash) && versions.dig('clientVersion', 'gitVersion')
    server = versions.is_a?(Hash) && versions.dig('serverVersion', 'gitVersion')
    client_version = client.to_s.match(/\Av?(\d+)\.(\d+)\.\d+/)
    server_version = server.to_s.match(/\Av?(\d+)\.(\d+)\.\d+/)
    describe 'kubectl and API Server report readable versions' do
      subject { !client_version.nil? && !server_version.nil? }
      it { should eq true }
    end

    if client_version && server_version
      describe 'kubectl and API Server major versions' do
        subject { client_version[1] }
        it { should eq server_version[1] }
      end
      describe 'kubectl is within one minor version of the contacted API Server' do
        subject { (client_version[2].to_i - server_version[2].to_i).abs }
        it { should be <= 1 }
      end
    end
  end
end
