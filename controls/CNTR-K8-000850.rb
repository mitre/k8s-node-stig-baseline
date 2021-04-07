# encoding: UTF-8

control 'CNTR-K8-000850' do
  title 'Kubernetes Kubelet must deny hostname override.'
  desc  "Kubernetes allows for the overriding of hostnames. Allowing this
feature to be implemented within the kubelets may break the TLS setup between
the kubelet service and the API server. This setting also can make it difficult
to associate logs with nodes if security analytics needs to take place. The
better practice is to setup nodes with resolvable FQDNs and avoid overriding
the hostnames."
  desc  'rationale', ''
  desc  'check', "
    On the Master and each Worker node, change to the /etc/sysconfig/ directory
and run the command:

    grep -i hostname-override kubelet
    --hostname-override

    If any of the nodes have the setting \"hostname-override\" present, this is
a finding.
  "
  desc  'fix', "
    Edit the Kubernetes Kubelet file in the /etc/sysconfig directory on the
Master and Worker nodes and remove the \"--hostname-override\" setting. Restart
the service after the change is made by running:

    service kubelet restart
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-CTR-000290'
  tag gid: 'CNTR-K8-000850'
  tag rid: 'CNTR-K8-000850_rule'
  tag stig_id: 'CNTR-K8-000850'
  tag fix_id: 'F-CNTR-K8-000850_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end

