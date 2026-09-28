require 'shellwords'

control 'SV-242451' do
  title 'The Kubernetes component PKI must be owned by root.'
  desc 'The Kubernetes PKI directory contains all certificates (.crt files)
supporting secure network communications in the Kubernetes Control Plane. If
these files can be modified, data traversing within the architecture components
would become unsecure and compromised. Many of the security settings within the
document are implemented through this file.'
  desc 'check', 'Review the PKI files in Kubernetes by using the command:

    ls -laR /etc/kubernetes/pki/

    If the command returns any non root:root file permissions, this is a
finding.'
  desc 'fix', 'Change the ownership of the PKI to root: root by executing the command:

    chown -R root:root /etc/kubernetes/pki/'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'V-242451'
  tag rid: 'SV-242451r961863_rule'
  tag stig_id: 'CNTR-K8-003180'
  tag fix_id: 'F-45684r712708_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  pki_path = input('pki_path')
  pki_search = command("find -L #{Shellwords.escape(pki_path)} -print0")
  pki_entries = pki_search.stdout.split("\0").reject(&:empty?)
  incorrectly_owned_entries = pki_entries.reject do |entry|
    pki_entry = file(entry)
    pki_entry.owned_by?('root') && pki_entry.grouped_into?('root')
  end

  describe directory(pki_path) do
    it { should exist }
  end

  describe 'Kubernetes PKI file discovery' do
    it "should successfully search #{pki_path}" do
      expect(pki_search.exit_status).to eq(0), "Unable to search the Kubernetes PKI directory: #{pki_search.stderr.strip}"
    end
  end

  describe 'Kubernetes PKI entries' do
    it 'should be owned by root:root' do
      expect(incorrectly_owned_entries).to be_empty, "PKI entries not owned by root:root:\n\t- #{incorrectly_owned_entries.join("\n\t- ")}"
    end
  end
end
