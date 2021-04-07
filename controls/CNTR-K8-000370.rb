# encoding: UTF-8

control 'CNTR-K8-000370' do
  title 'The Kubernetes Kubelet must have anonymous authentication disabled.'
  desc  "A user who has access to the Kubelet essentially has root access to
the nodes contained within the Kubernetes Control Plane. To control access,
users must be authenticated and authorized. By allowing anonymous connections,
the controls put in place to secure the Kubelet can be bypassed.

    Setting anonymous authentication to \"false\" also disables unauthenticated
requests from kubelets.

    While there are instances where anonymous connections may be needed (e.g.,
health checks) and Role-Based Access Controls (RBAC) are in place to limit the
anonymous access, this access must be disabled and only enabled when necessary.
  "
  desc  'rationale', ''
  desc  'check', "
    Change to the /etc/sysconfig/ directory on the Kubernetes Master Node. Run
the command:

    grep -i anonymous-auth kubelet

    If the setting \"anonymous-auth\" is set to \"true\" or the parameter not
set in the Kubernetes Kubelet configuration file, this is a finding.
  "
  desc  'fix', "
    Edit the Kubernetes Kubelet file in the/etc/sysconfig/ directory on the
Kubernetes Master Node.

    Set the argument \"--anonymous-auth\" to \"false\".

    Restart kubelet service using command:
    service kubelet restart
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000033-CTR-000090'
  tag gid: 'CNTR-K8-000370'
  tag rid: 'CNTR-K8-000370_rule'
  tag stig_id: 'CNTR-K8-000370'
  tag fix_id: 'F-CNTR-K8-000370_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

