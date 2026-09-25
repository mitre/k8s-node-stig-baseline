control 'SV-242385' do
  title 'The Kubernetes Controller Manager must have secure binding.'
  desc 'Limiting the number of attack vectors and implementing authentication
and encryption on the endpoints available to external sources is paramount when
securing the overall Kubernetes cluster. The Controller Manager API service
exposes port 10252/TCP by default for health and metrics information use. This
port does not encrypt or authenticate connections. If this port is exposed
externally, an attacker can use this port to attack the entire Kubernetes
cluster. By setting the bind address to only localhost (i.e., 127.0.0.1), only
those internal services that require health and metrics information can access
the Control Manager API.'
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:

grep -i bind-address *

If the setting bind-address is not set to "127.0.0.1" or is not found in the Kubernetes Controller Manager manifest file, this is a finding.'
  desc 'fix', 'Edit the Kubernetes Controller Manager manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the argument "--bind-address" to "127.0.0.1".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-CTR-000090'
  tag gid: 'V-242385'
  tag rid: 'SV-242385r1137638_rule'
  tag stig_id: 'CNTR-K8-000310'
  tag fix_id: 'F-45618r863759_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  only_if("This control applies only to control-plane nodes; input('node_roles') must include 'control-plane'.", impact: 0.0) do
    input('node_roles').include?('control-plane')
  end

  kube_controller_manager_manifest = kubernetes_manifest(::File.join(input('manifests_path'), 'kube-controller-manager.yaml'), 'kube-controller-manager')
  describe kube_controller_manager_manifest do
    its('errors') { should be_empty }
  end

  if kube_controller_manager_manifest.errors.empty?
    describe kube_controller_manager_manifest do
      its('bind-address') { should cmp '127.0.0.1' }
    end
  end
end
