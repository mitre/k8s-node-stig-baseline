control 'SV-242399' do
  title 'Kubernetes DynamicKubeletConfig must not be enabled.'
  desc 'Kubernetes allows a user to configure kubelets with dynamic
configurations. When dynamic configuration is used, the kubelet will watch for
changes to the configuration file. When changes are made, the kubelet will
automatically restart. Allowing this capability bypasses access restrictions
and authorizations. Using this capability, an attacker can lower the security
posture of the kubelet, which includes allowing the ability to run arbitrary
commands in any container running on that node.'
  desc 'check', %q(This check is only applicable for Kubernetes versions 1.25 and older.  

On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:
grep -i feature-gates *

In each manifest file, if the feature-gates does not exist, or does not contain the "DynamicKubeletConfig" flag, or sets the flag to "true", this is a finding.

On each Control Plane and Worker node, run the command:
ps -ef | grep kubelet

Verify the "feature-gates" option is not present.

Note the path to the config file (identified by --config).

Inspect the content of the config file:
If the "featureGates" setting is not present, or does not contain the "DynamicKubeletConfig", or sets the flag to "true", this is a finding.)
  desc 'fix', %q(This fix is only applicable to Kubernetes version 1.25 and older.

On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:
grep -i feature-gates *

Edit the manifest files so that every manifest has a "--feature-gates" setting with "DynamicKubeletConfig=false".

On each Control Plane and Worker Node, run the command:
ps -ef | grep kubelet

Remove the "feature-gates" option if present.

Note the path to the config file (identified by --config).

Edit the config file: 
Add a "featureGates" setting if one does not yet exist. Add the feature gate "DynamicKubeletConfig=false".

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag gid: 'V-242399'
  tag rid: 'SV-242399r1137639_rule'
  tag stig_id: 'CNTR-K8-000460'
  tag fix_id: 'F-45632r918163_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  only_if('This control applies only to Kubernetes 1.25 and older.', impact: 0.0) do
    input('kubernetes_minor_version') <= 25
  end

  describe kube_scheduler do
    its('feature-gates.to_s') { should match /DynamicKubeletConfig=false/i }
  end

  describe kube_controller_manager do
    its('feature-gates.to_s') { should match /DynamicKubeletConfig=false/i }
  end

  describe kube_apiserver do
    its('feature-gates.to_s') { should match /DynamicKubeletConfig=false/i }
  end

  describe kubelet do
    its('feature-gates') { should be_nil }
  end

  describe kubelet_config_file do
    its(%w(featureGates DynamicKubeletConfig)) { should cmp 'false' }
  end
end
