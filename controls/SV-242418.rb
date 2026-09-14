control 'SV-242418' do
  title 'The Kubernetes API server must use approved cipher suites.'
  desc 'The Kubernetes API server communicates to the kubelet service on the
nodes to deploy, update, and delete resources. If an attacker were able to get
between this communication and modify the request, the Kubernetes cluster could
be compromised. Using approved cypher suites for the communication ensures the
protection of the transmitted information, confidentiality, and integrity so
that the attacker cannot read or alter this communication.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i tls-cipher-suites *

If the setting feature tls-cipher-suites is not set in the Kubernetes API server manifest file or contains no value or does not contain TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane.

Set the value of "--tls-cipher-suites" to:
"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag gid: 'V-242418'
  tag rid: 'SV-242418r1043178_rule'
  tag stig_id: 'CNTR-K8-001400'
  tag fix_id: 'F-45651r927105_fix'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']

  only_if("This control applies only to control-plane nodes; input('node_roles') must include 'control-plane'.", impact: 0.0) do
    input('node_roles').include?('control-plane')
  end

  kube_apiserver_manifest = kubernetes_manifest(::File.join(input('manifests_path'), 'kube-apiserver.yaml'), 'kube-apiserver')
  describe kube_apiserver_manifest do
    its('errors') { should be_empty }
  end

  approved_cipher_suites = %w[
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  ]

  describe 'Kubernetes API Server TLS cipher suites' do
    subject { kube_apiserver_manifest.tls_cipher_suites.sort }
    it { should cmp approved_cipher_suites.sort }
  end
end
