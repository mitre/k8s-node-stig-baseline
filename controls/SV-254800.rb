require 'kubernetes_policy'
require 'kubernetes_node_inputs'

control 'SV-254800' do
  title 'Kubernetes must have a Pod Security Admission control file configured.'
  desc 'An admission controller intercepts and processes requests to the Kubernetes API prior to persistence of the object, but after the request is authenticated and authorized.

Kubernetes (> v1.23)offers a built-in Pod Security admission controller to enforce the Pod Security Standards. Pod security restrictions are applied at the namespace level when pods are created.

The Kubernetes Pod Security Standards define different isolation levels for Pods. These standards define how to restrict the behavior of pods in a clear, consistent fashion.'
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:

"grep -i admission-control-config-file *"

If the setting "--admission-control-config-file" is not configured in the Kubernetes API Server manifest file, this is a finding.

Inspect the .yaml file defined by the --admission-control-config-file. Verify PodSecurity is properly configured.
If least privilege is not represented, this is a finding.'
  desc 'fix', %q(Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane.

Set the value of "--admission-control-config-file" to a valid path for the file.

Create an admission controller config file:
Example File:
```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: PodSecurity
  configuration:
    apiVersion: pod-security.admission.config.k8s.io/v1beta1
    kind: PodSecurityConfiguration
    # Defaults applied when a mode label is not set.
    defaults:
      enforce: "privileged"
      enforce-version: "latest"
    exemptions:
      # Don't forget to exempt namespaces or users that are responsible for deploying
      # cluster components, because they need to run privileged containers
      usernames: ["admin"]
      namespaces: ["kube-system"]

See for more details:
Migrate from PSP to PSA:
https://kubernetes.io/docs/tasks/configure-pod-container/migrate-from-psp/

Best Practice: https://kubernetes.io/docs/concepts/security/pod-security-policy/#recommended-practice.)
  impact 0.7
  tag check_id: 'C-58411r927123_chk'
  tag severity: 'high'
  tag gid: 'V-254800'
  tag rid: 'SV-254800r961359_rule'
  tag stig_id: 'CNTR-K8-002011'
  tag gtitle: 'SRG-APP-000342-CTR-000775'
  tag fix_id: 'F-58357r927124_fix'
  tag 'documentable'
  tag cci: ['CCI-002263']
  tag nist: ['AC-16 a']

  desc 'scope', 'Host-local portion of this STIG requirement; combine with the sibling cluster profile.'

  only_if("This control applies to control-plane nodes declared in input('node_roles').", impact: 0.0) do
    KubernetesNodeInputs.value('node_roles', input('node_roles')).include?('control-plane')
  end

  manifest = kubernetes_manifest(::File.join(KubernetesNodeInputs.value('manifests_path', input('manifests_path')), 'kube-apiserver.yaml'), 'kube-apiserver')
  policy_path = manifest.host_path(manifest.params['admission-control-config-file'])
  policy = policy_path ? manifest.read_mapping(policy_path) : {}
  plugin = KubernetesPolicy.pod_security_plugin(policy)
  configuration = plugin['configuration']
  if plugin['path']
    plugin_path = manifest.host_path(plugin['path'])
    configuration = plugin_path ? manifest.read_mapping(plugin_path) : {}
  end

  describe manifest do
    its('errors') { should be_empty }
  end

  describe 'Admission configuration contains valid PodSecurity settings' do
    subject { KubernetesPolicy.pod_security_valid?(configuration) }
    it { should eq true }
  end

  if KubernetesPolicy.pod_security_valid?(configuration)
    describe 'PodSecurity defaults and exemptions represent organizational least privilege' do
      skip "Review defaults #{configuration['defaults'].inspect} and exemptions #{configuration['exemptions'].inspect} from #{policy_path} against namespace policies and documented organizational requirements."
    end
  end
end
