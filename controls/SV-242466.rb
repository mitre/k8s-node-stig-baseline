control 'SV-242466' do
  title 'The Kubernetes PKI CRT must have file permissions set to 644 or more
restrictive.'
  desc 'The Kubernetes PKI directory contains all certificates (.crt files)
supporting secure network communications in the Kubernetes Control Plane. If
these files can be modified, data traversing within the architecture components
would become unsecure and compromised.'
  desc 'check', %q(Review the permissions of the Kubernetes PKI cert files by using the command:

sudo find /etc/kubernetes/pki/* -name "*.crt" | xargs stat -c '%n %a'

If any of the files have permissions more permissive than "644", this is a finding.)
  desc 'fix', 'Change the ownership of the cert files to "644" by executing the command:

find /etc/kubernetes/pki -name "*.crt" | xargs chmod 644'
  desc 'caveat', "Kubernetes PKI files not present of the target at specified path #{pki_path}."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag gid: 'V-242466'
  tag rid: 'SV-242466r961863_rule'
  tag stig_id: 'CNTR-K8-003330'
  tag fix_id: 'F-45699r918202_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  pki_path = input('pki_path')
  expected_mode = input('kubernetes_file_modes')['pki_certificate_files']
  pki_search = command("find #{pki_path} -type f -name '*.crt' -print")
  pki_files = pki_search.stdout.lines.map(&:strip).reject(&:empty?)
  overly_permissive_files = pki_files.select { |file_name| file(file_name).more_permissive_than?(expected_mode) }

  describe 'Kubernetes PKI certificate discovery' do
    it "should successfully search #{pki_path}" do
      expect(pki_search.exit_status).to eq(0), "Unable to search for Kubernetes PKI certificates: #{pki_search.stderr.strip}"
    end
  end

  describe 'Kubernetes PKI certificate files' do
    it "should have mode #{expected_mode} or more restrictive" do
      expect(overly_permissive_files).to be_empty, "PKI certificate files with permissions more permissive than #{expected_mode} from input('kubernetes_file_modes')['pki_certificate_files']:\n\t- #{overly_permissive_files.join("\n\t- ")}"
    end
  end
end
