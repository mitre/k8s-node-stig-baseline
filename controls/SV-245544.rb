require 'kubernetes_node_inputs'

control 'SV-245544' do
  title 'Kubernetes endpoints must use approved organizational certificate and
key pair to protect information in transit.'
  desc 'Kubernetes control plane and external communication is managed by API
Server. The main implementation of the API Server is to manage hardware
resources for pods and container using horizontal or vertical scaling. Anyone
who can gain access to the API Server can effectively control your Kubernetes
architecture. Using authenticity protection, the communication can be protected
against man-in-the-middle attacks/session hijacking and the insertion of false
information into sessions.

    The communication session is protected by utilizing transport encryption
protocols, such as TLS. TLS provides the Kubernetes API Server with a means to
be able to authenticate sessions and encrypt traffic.

    By default, the API Server does not authenticate to the kubelet HTTPs
endpoint. To enable secure communication for API Server, the parameter
-kubelet-client-certificate and kubelet-client-key must be set. This parameter
gives the location of the certificate and key pair used to secure API Server
communication.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i kubelet-client-certificate *
grep -I kubelet-client-key *

If the setting "--kubelet-client-certificate" is not configured in the Kubernetes API server manifest file or contains no value, this is a finding.

If the setting "--kubelet-client-key" is not configured in the Kubernetes API server manifest file or contains no value, this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the value of "--kubelet-client-certificate" and "--kubelet-client-key" to an Approved Organizational Certificate and key pair.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000439-CTR-001080'
  tag gid: 'V-245544'
  tag rid: 'SV-245544r961632_rule'
  tag stig_id: 'CNTR-K8-002640'
  tag fix_id: 'F-48774r863950_fix'
  tag cci: ['CCI-002418', 'CCI-002448']
  tag nist: ['SC-8', 'SC-12 (3)']

  only_if("This control applies only to control-plane nodes; input('node_roles') must include 'control-plane'.", impact: 0.0) do
    KubernetesNodeInputs.value('node_roles', input('node_roles')).include?('control-plane')
  end

  kube_apiserver_manifest = kubernetes_manifest(::File.join(KubernetesNodeInputs.value('manifests_path', input('manifests_path')), 'kube-apiserver.yaml'), 'kube-apiserver')
  describe kube_apiserver_manifest do
    its('errors') { should be_empty }
  end

  describe kube_apiserver_manifest do
    its('kubelet-client-certificate') { should_not be_nil }
    its('kubelet-client-certificate') { should_not be_empty }
    its('kubelet-client-key') { should_not be_nil }
    its('kubelet-client-key') { should_not be_empty }
  end
end
