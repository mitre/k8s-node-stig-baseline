require 'shellwords'

control 'SV-242467' do
  title 'The Kubernetes PKI keys must have file permissions set to 600 or more
restrictive.'
  desc 'The Kubernetes PKI directory contains all certificate key files
supporting secure network communications in the Kubernetes Control Plane. If
these files can be modified, data traversing within the architecture components
would become unsecure and compromised.'
  desc 'check', %q(Review the permissions of the Kubernetes PKI key files by using the command:

sudo find /etc/kubernetes/pki -name "*.key" | xargs stat -c '%n %a'

If any of the files have permissions more permissive than "600", this is a finding.)
  desc 'fix', 'Change the ownership of the key files to "600" by executing the command:

find /etc/kubernetes/pki -name "*.key" | xargs chmod 600'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag gid: 'V-242467'
  tag rid: 'SV-242467r961863_rule'
  tag stig_id: 'CNTR-K8-003340'
  tag fix_id: 'F-45700r918206_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  pki_path = input('pki_path')
  expected_mode = input('kubernetes_file_modes')['pki_private_key_files']
  pki_search = command("find -L #{Shellwords.escape(pki_path)} \\( -type f -o -type l \\) -name '*.key' -print0")
  pki_files = pki_search.stdout.split("\0").reject(&:empty?)
  overly_permissive_files = pki_files.select { |file_name| !file(file_name).file? || file(file_name).more_permissive_than?(expected_mode) }

  describe 'Kubernetes PKI key discovery' do
    it "should successfully search #{pki_path}" do
      expect(pki_search.exit_status).to eq(0), "Unable to search for Kubernetes PKI keys: #{pki_search.stderr.strip}"
    end
  end

  describe 'Kubernetes PKI key files' do
    it "should have mode #{expected_mode} or more restrictive" do
      expect(overly_permissive_files).to be_empty, "PKI key files with permissions more permissive than #{expected_mode} from input('kubernetes_file_modes')['pki_private_key_files']:\n\t- #{overly_permissive_files.join("\n\t- ")}"
    end
  end
end
