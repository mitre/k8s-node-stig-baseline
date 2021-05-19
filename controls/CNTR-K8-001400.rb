# encoding: UTF-8

control 'V-242418' do
  title 'The Kubernetes API server must use approved cipher suites.'
  desc  "The Kubernetes API server communicates to the kubelet service on the
nodes to deploy, update, and delete resources. If an attacker were able to get
between this communication and modify the request, the Kubernetes cluster could
be compromised. Using approved cypher suites for the communication ensures the
protection of the transmitted information, confidentiality, and integrity so
that the attacker cannot read or alter this communication."
  desc  'rationale', ''
  desc  'check', "
    Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Master
Node. Run the command:

    grep -i tls-cipher-suites *

    If the setting feature tls-cipher-suites is not set in the Kubernetes API
server manifest file or contains no value or does not contain
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM
_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM
_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM
_SHA384, this is a finding.
  "
  desc 'fix', "
    Edit the Kubernetes API Server manifest file in the
/etc/kubernetes/manifests directory on the Kubernetes Master Node. Set the
value of tls-cipher-suites to:
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM
_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM
_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM
_SHA384
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag gid: 'V-242418'
  tag rid: 'SV-242418r712610_rule'
  tag stig_id: 'CNTR-K8-001400'
  tag fix_id: 'F-45651r717025_fix'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']

  unless kube_apiserver.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes API Server process is not running on the target.'
  end

  describe kube_apiserver do
    its('tls_cipher_suites') { should include 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256' }
    its('tls_cipher_suites') { should include 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256' }
    its('tls_cipher_suites') { should include 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305' }
    its('tls_cipher_suites') { should include 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384' }
    its('tls_cipher_suites') { should include 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305' }
    its('tls_cipher_suites') { should include 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384' }
    its('tls_cipher_suites.count') { should cmp 6 }
  end
end
