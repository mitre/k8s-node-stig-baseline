# encoding: UTF-8

control 'CNTR-K8-000360' do
  title 'The Kubernetes API server must have anonymous authentication disabled.'
  desc  "The Kubernetes API Server controls Kubernetes via an API interface. A
user who has access to the API essentially has root access to the entire
Kubernetes cluster. To control access, users must be authenticated and
authorized. By allowing anonymous connections, the controls put in place to
secure the API can be bypassed.

    Setting anonymous authentication to \"false\" also disables unauthenticated
requests from kubelets.

    While there are instances where anonymous connections may be needed (e.g.,
health checks) and Role-Based Access Controls (RBAC) are in place to limit the
anonymous access, this access should be disabled, and only enabled when
necessary.
  "
  desc  'rationale', ''
  desc  'check', "
    Change to the /etc/kubernetes/manifests directory on the Kubernetes Master
Node. Run the command:

    grep -i anonymous-auth *

    If the setting anonymous-auth is set to \"true\" in the Kubernetes API
Server manifest file, this is a finding.
  "
  desc  'fix', "Edit the Kubernetes API Server manifest file in the
/etc/kubernetes/manifests directory on the Kubernetes Master Node. Set the
argument --anonymous-auth to \"false\"."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000033-CTR-000100'
  tag gid: 'CNTR-K8-000360'
  tag rid: 'CNTR-K8-000360_rule'
  tag stig_id: 'CNTR-K8-000360'
  tag fix_id: 'F-CNTR-K8-000360_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

