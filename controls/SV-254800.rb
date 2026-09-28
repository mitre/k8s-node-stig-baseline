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
    input('node_roles').include?('control-plane')
  end

  manifest = kubernetes_manifest(::File.join(input('manifests_path'), 'kube-apiserver.yaml'), 'kube-apiserver')
  policy_path = manifest.host_path(manifest.params['admission-control-config-file'])
  policy = policy_path ? manifest.read_mapping(policy_path) : {}

  describe manifest do
    its('errors') { should be_empty }
  end

  if manifest.errors.empty?
    describe 'Admission configuration format' do
      it('uses AdmissionConfiguration') { expect(policy['kind']).to eq 'AdmissionConfiguration' }
      it('uses a supported API version') { expect(policy['apiVersion'].to_s).to match(%r{\Aapiserver\.config\.k8s\.io/v1(?:alpha1|beta1)?\z}) }
    end

    plugins = Array(policy['plugins']).select { |entry| entry.is_a?(Hash) && entry['name'] == 'PodSecurity' }
    describe 'Admission configuration contains one PodSecurity plugin' do
      subject { plugins.length }
      it { should eq 1 }
    end

    if plugins.length == 1
      plugin = plugins.first
      configuration = plugin['configuration']
      configuration_path = policy_path
      if plugin['path']
        configuration_path = manifest.host_path(plugin['path'])
        configuration = configuration_path ? manifest.read_mapping(configuration_path) : nil
      end

      if manifest.errors.empty?
        describe 'PodSecurity configuration type' do
          subject { configuration.is_a?(Hash) && configuration['kind'] }
          it { should eq 'PodSecurityConfiguration' }
        end

        if configuration.is_a?(Hash)
          describe 'PodSecurity configuration API version' do
            subject { configuration['apiVersion'].to_s }
            it { should match(%r{\Apod-security\.admission\.config\.k8s\.io/v1(?:alpha1|beta1)?\z}) }
          end

          defaults = configuration['defaults']
          pod_security_levels = %w[privileged baseline restricted]
          minimum_level = input('minimum_pod_security_level').to_s
          minimum_index = pod_security_levels.index(minimum_level)

          if defaults.is_a?(Hash)
            %w[enforce audit warn].each do |mode|
              # Kubernetes applies "privileged" when a mode is unset.
              configured_level = defaults.fetch(mode, 'privileged').to_s
              configured_index = pod_security_levels.index(configured_level)

              describe "PodSecurity #{mode} level" do
                it "is at least the #{minimum_level} standard" do
                  expect(minimum_index).not_to be_nil, "input('minimum_pod_security_level') must be one of #{pod_security_levels.join(', ')}; got #{minimum_level.inspect}"
                  # An unrecognized level indexes to nil, which be >= reports as a failure.
                  expect(configured_index).to be >= minimum_index, "#{mode} is #{configured_level.inspect}; input('minimum_pod_security_level') requires at least #{minimum_level} (#{pod_security_levels.join(' < ')})"
                end
              end
              describe "PodSecurity #{mode} version" do
                subject { defaults.fetch("#{mode}-version", 'latest') }
                it { should match(/\A(?:latest|v1\.\d+)\z/) }
              end
            end

            describe 'PodSecurity exemptions represent organizational least privilege' do
              skip "The enforce, audit, and warn levels are checked against input('minimum_pod_security_level'). Review the exemptions #{configuration['exemptions'].inspect} from #{configuration_path} (admission configuration: #{policy_path}) against documented organizational requirements."
            end
          else
            # Effective policy comes from namespace labels, which a node scan cannot read.
            describe 'PodSecurity namespace policy' do
              skip "#{configuration_path} configures no defaults, so namespaces without a pod-security.kubernetes.io label fall back to \"privileged\". Confirm every namespace carries an explicit enforce label of at least #{minimum_level}."
            end
          end
        end
      end
    end
  end
end
