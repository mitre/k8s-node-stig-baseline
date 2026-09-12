control 'SV-274882' do
  title 'Kubernetes Secrets must be encrypted at rest.'
  desc 'Kubernetes Secrets may store sensitive information such as passwords, tokens, and keys. These values are stored in the etcd database used by Kubernetes unencrypted. To protect these Secrets at rest, these values must be encrypted.'
  desc 'check', %q(Change to the /etc/kubernetes/manifests directory on the Kubernetes Master Node. Run the command:
grep -i encryption-provider-config *

If the setting "encryption-provider-config" is not configured, this is a finding.

If the setting is configured, check the contents of the file specified by its argument.

If the file does not specify the Secret's resource, this is a finding.

If the identity provider is specified as the first provider for the resource, this is also a finding.)
  desc 'fix', %q(Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node.

Set the value of "--encryption-provider-config" to the path to the encryption config.

The encryption config must specify the Secret's resource and provider. Below is an example:
{
  "kind": "EncryptionConfiguration",
  "apiVersion": "apiserver.config.k8s.io/v1",
  "resources": [
    {
      "resources": [
        "secrets"
      ],
      "providers": [
        {
          "aescbc": {
            "keys": [
              {
                "name": "aescbckey",
                "secret": "xxxxxxxxxxxxxxxxxxx"
              }
            ]
          }
        },
        {
          "identity": {}
        }
      ]
    }
  ]
})
  impact 0.7
  tag check_id: 'C-78983r1107240_chk'
  tag severity: 'high'
  tag gid: 'V-274882'
  tag rid: 'SV-274882r1137640_rule'
  tag stig_id: 'CNTR-K8-001162'
  tag gtitle: 'SRG-APP-000033-CTR-000100'
  tag fix_id: 'F-78888r1107241_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  desc 'scope', 'Host-local portion of this STIG requirement; combine with the sibling cluster profile.'

  only_if("This control applies to control-plane nodes declared in input('node_roles').", impact: 0.0) do
    input('node_roles').include?('control-plane')
  end

  manifest = kubernetes_manifest(::File.join(input('manifests_path'), 'kube-apiserver.yaml'), 'kube-apiserver')
  policy_path = manifest.host_path(manifest.params['encryption-provider-config'])
  policy = policy_path ? manifest.read_mapping(policy_path) : {}

  describe manifest do
    its('errors') { should be_empty }
  end

  describe 'Encryption configuration format' do
    it('uses EncryptionConfiguration') { expect(policy['kind']).to eq 'EncryptionConfiguration' }
    it('uses the supported API version') { expect(policy['apiVersion']).to eq 'apiserver.config.k8s.io/v1' }
  end

  # Kubernetes applies the first matching resource rule and its first provider.
  secret_rule = Array(policy['resources']).find do |rule|
    rule.is_a?(Hash) && (Array(rule['resources']) & ['secrets', 'secrets.', '*.', '*.*']).any?
  end
  first_provider = secret_rule && Array(secret_rule['providers']).first
  provider_name = first_provider.is_a?(Hash) && first_provider.keys.first
  provider_settings = first_provider.is_a?(Hash) && first_provider[provider_name]

  describe 'Encryption configuration includes a rule for Secrets' do
    subject { !secret_rule.nil? }
    it { should eq true }
  end

  # Report only the provider name, never encryption key material.
  describe 'The first provider for Secrets uses encryption instead of identity' do
    subject { provider_name }
    it { should be_in %w[aescbc aesgcm secretbox kms] }
  end

  describe 'The encryption provider has configuration settings' do
    subject { provider_settings.is_a?(Hash) && !provider_settings.empty? && first_provider.size == 1 }
    it { should eq true }
  end
end
