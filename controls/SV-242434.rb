control 'SV-242434' do
  title 'Kubernetes Kubelet must enable kernel protection.'
  desc 'System kernel is responsible for memory, disk, and task management.
The kernel provides a gateway between the system hardware and software.
Kubernetes requires kernel access to allocate resources to the Control Plane.
Threat actors that penetrate the system kernel can inject malicious code or
hijack the Kubernetes architecture. It is vital to implement protections
through Kubernetes components to reduce the attack surface.'
  desc 'check', 'On the Control Plane, run the command:
ps -ef | grep kubelet

If the "--protect-kernel-defaults" option exists, this is a finding.

Note the path to the config file (identified by --config).

Run the command:
grep -i protectKernelDefaults <path_to_config_file>

If the setting "protectKernelDefaults" is not set or is set to false, this is a finding.'
  desc 'fix', 'On the Control Plane, run the command:
ps -ef | grep kubelet

Remove the "--protect-kernel-defaults" option if present.

Note the path to the Kubernetes Kubelet config file (identified by --config).

Edit the Kubernetes Kubelet config file: 
Set "protectKernelDefaults" to "true". 

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000233-CTR-000585'
  tag gid: 'V-242434'
  tag rid: 'SV-242434r961131_rule'
  tag stig_id: 'CNTR-K8-001620'
  tag fix_id: 'F-45667r918187_fix'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']

  describe kubelet do
    its('protect-kernel-defaults') { should be_nil }
  end

  describe kubelet_config_file do
    its('protectKernelDefaults') { should cmp 'true' }
  end
end
