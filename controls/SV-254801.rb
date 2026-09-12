control 'SV-254801' do
  title 'Kubernetes must enable PodSecurity admission controller on static pods and Kubelets.'
  desc 'PodSecurity admission controller is a component that validates and enforces security policies for pods running within a Kubernetes cluster. It is responsible for evaluating the security context and configuration of pods against defined policies.

To enable PodSecurity admission controller on Static Pods (kube-apiserver, kube-controller-manager, or kube-schedule), the argument "--feature-gates=PodSecurity=true" must be set.

To enable PodSecurity admission controller on Kubelets, the featureGates PodSecurity=true argument must be set.

(Note: The PodSecurity feature gate is GA as of  v1.25.)'
  desc 'check', %q(On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:
grep -i feature-gates *

For each manifest file, if the "--feature-gates" setting does not exist, does not contain the "--PodSecurity" flag, or sets the flag to "false", this is a finding.

On each Control Plane and Worker Node, run the command:
ps -ef | grep kubelet

If the "--feature-gates" option exists, this is a finding.

Note the path to the config file (identified by --config).

Inspect the content of the config file:
If the "featureGates" setting is not present, does not contain the "PodSecurity" flag, or sets the flag to "false", this is a finding.)
  desc 'fix', %q(On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:
grep -i feature-gates *

Ensure the argument "--feature-gates=PodSecurity=true" is present in each manifest file.

On each Control Plane and Worker Node, run the command:
ps -ef | grep kubelet

Remove the "--feature-gates" option if present.

Note the path to the config file (identified by --config).

Edit the Kubernetes Kubelet config file:
Add a "featureGates" setting if one does not yet exist. Add the feature gate "PodSecurity=true".

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet)
  impact 0.7
  tag check_id: 'C-58412r918278_chk'
  tag severity: 'high'
  tag gid: 'V-254801'
  tag rid: 'SV-254801r961359_rule'
  tag stig_id: 'CNTR-K8-002001'
  tag gtitle: 'SRG-APP-000342-CTR-000775'
  tag fix_id: 'F-58358r918213_fix'
  tag 'documentable'
  tag cci: ['CCI-002263']
  tag nist: ['AC-16 a']

  desc 'scope', 'Host-local portion of this STIG requirement; combine with the sibling cluster profile.'

  minor_version = input('kubernetes_minor_version')
  if input('node_roles').include?('control-plane')
    components = minor_version < 25 ? %w[kube-apiserver kube-controller-manager kube-scheduler] : ['kube-apiserver']
    components.each do |component|
      manifest = kubernetes_manifest(::File.join(input('manifests_path'), "#{component}.yaml"), component)
      describe manifest do
        its('errors') { should be_empty }
      end
      if minor_version < 25
        feature_gates = manifest.params['feature-gates'].to_s.split(',').map(&:strip)
        describe "#{component} enables PodSecurity before Kubernetes 1.25" do
          subject { feature_gates }
          it { should include 'PodSecurity=true' }
          it { should_not include 'PodSecurity=false' }
        end
      else
        disabled_plugins = manifest.params['disable-admission-plugins'].to_s.split(',').map(&:strip)
        describe "#{component} keeps PodSecurity admission enabled" do
          subject { disabled_plugins }
          it { should_not include 'PodSecurity' }
          it('has a value when disable-admission-plugins is present') do
            expect(manifest.params['disable-admission-plugins']).not_to eq('')
          end
        end
      end
    end
  end

  if minor_version < 25
    describe kubelet do
      its('feature-gates') { should be_nil }
      its('config_file') { should be_file }
    end
    describe kubelet_config_file do
      its(%w[featureGates PodSecurity]) { should cmp true }
    end
  elsif !input('node_roles').include?('control-plane')
    impact 0.0
    describe 'Kubelet PodSecurity feature gate on Kubernetes 1.25 and newer' do
      skip "input('kubernetes_minor_version') is #{minor_version}; the graduated PodSecurity feature gate is no longer configured on this worker."
    end
  end
end
