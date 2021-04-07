# encoding: UTF-8

control 'CNTR-K8-000300' do
  title 'The Kubernetes Scheduler must have secure binding.'
  desc  "Limiting the number of attack vectors and implementing authentication
and encryption on the endpoints available to external sources is paramount when
securing the overall Kubernetes cluster. The Scheduler API service exposes port
10251/TCP by default for health and metrics information use. This port does not
encrypt or authenticate connections. If this port is exposed externally, an
attacker can use this port to attack the entire Kubernetes cluster. By setting
the bind address to localhost (i.e., 127.0.0.1), only those internal services
that require health and metrics information can access the Scheduler API."
  desc  'rationale', ''
  desc  'check', "
    Change to the /etc/kubernetes/manifests directory on the Kubernetes Master
Node. Run the command:

    grep -i bind-address *

    If the setting \"bind-address\" is not set to \"127.0.0.1\" or is not found
in the Kubernetes Scheduler manifest file, this is a finding.
  "
  desc  'fix', "Edit the Kubernetes Scheduler manifest file in the
/etc/kubernetes/manifests directory on the Kubernetes Master Node. Set the
argument \"--bind-address\" to \"127.0.0.1\"."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-CTR-000090'
  tag gid: 'CNTR-K8-000300'
  tag rid: 'CNTR-K8-000300_rule'
  tag stig_id: 'CNTR-K8-000300'
  tag fix_id: 'F-CNTR-K8-000300_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

