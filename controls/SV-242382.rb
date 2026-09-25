control 'SV-242382' do
  title 'The Kubernetes API Server must enable Node,RBAC as the authorization
mode.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DOD-approved PKIs, all DOD systems (e.g., networks, web servers, and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset.

Node,RBAC is the method within Kubernetes to control access of users and applications. Kubernetes uses roles to grant authorization API requests made by kubelets.'
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:
grep -i authorization-mode *

If the setting authorization-mode is set to "AlwaysAllow" in the Kubernetes API Server manifest file or is not configured, this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane.

Set the value of "--authorization-mode" to "Node,RBAC".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-CTR-000090'
  tag satisfies: ['SRG-APP-000033-CTR-000090', 'SRG-APP-000033-CTR-000095', 'SRG-APP-000340-CTR-000770', 'SRG-APP-000378-CTR-000880']
  tag gid: 'V-242382'
  tag rid: 'SV-242382r1137638_rule'
  tag stig_id: 'CNTR-K8-000270'
  tag fix_id: 'F-45615r918145_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  only_if("This control applies only to control-plane nodes; input('node_roles') must include 'control-plane'.", impact: 0.0) do
    input('node_roles').include?('control-plane')
  end

  kube_apiserver_manifest = kubernetes_manifest(::File.join(input('manifests_path'), 'kube-apiserver.yaml'), 'kube-apiserver')
  describe kube_apiserver_manifest do
    its('errors') { should be_empty }
  end

  if kube_apiserver_manifest.errors.empty?
    describe kube_apiserver_manifest do
      its('authorization-mode') { should cmp 'Node,RBAC' }
    end
  end
end
