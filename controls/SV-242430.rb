control 'SV-242430' do
  title 'Kubernetes etcd must have a certificate for communication.'
  desc 'Kubernetes stores configuration and state information in a distributed key-value store called etcd. Anyone who can write to etcd can effectively control the Kubernetes cluster. Even just reading the contents of etcd could easily provide helpful hints to a would-be attacker. Using authenticity protection, the communication can be protected against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

The communication session is protected by utilizing transport encryption protocols, such as TLS. TLS provides the Kubernetes API Server and etcd with a means to be able to authenticate sessions and encrypt traffic.

To enable encrypted communication for etcd, the parameter "--etcd-certfile" must be set. This parameter gives the location of the SSL certification file used to secure etcd communication.'
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:
grep -i etcd-certfile *

If the setting "--etcd-certfile" is not set in the Kubernetes API Server manifest file, this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane.

Set the value of "--etcd-certfile" to the certificate to be used for communication with etcd.'
  impact 0.5
  tag check_id: 'C-45705r927116_chk'
  tag severity: 'medium'
  tag gid: 'V-242430'
  tag rid: 'SV-242430r1043178_rule'
  tag stig_id: 'CNTR-K8-001520'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag fix_id: 'F-45663r927117_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']

  only_if("This control applies only to control-plane nodes; input('node_roles') must include 'control-plane'.", impact: 0.0) do
    input('node_roles').include?('control-plane')
  end

  kube_apiserver_manifest = kubernetes_manifest(::File.join(input('manifests_path'), 'kube-apiserver.yaml'), 'kube-apiserver')
  describe kube_apiserver_manifest do
    its('errors') { should be_empty }
  end

  if kube_apiserver_manifest.errors.empty?
    describe kube_apiserver_manifest do
      its('etcd-certfile') { should_not be_nil }
      its('etcd-certfile') { should_not be_empty }
    end
  end
end
