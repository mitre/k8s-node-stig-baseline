# encoding: UTF-8

control 'CNTR-K8-001460' do
  title "Kubernetes Kubelet must enable tls-private-key-file for client
authentication to secure service."
  desc  "Kubernetes container and pod configuration are maintained by Kubelet.
Kubelet agents register nodes with the API Server, mount volume storage, and
perform health checks for containers and pods. Anyone who gains access to
Kubelet agents can effectively control applications within the pods and
containers. Using authenticity protection, the communication can be protected
against man-in-the-middle attacks/session hijacking and the insertion of false
information into sessions.

    The communication session is protected by utilizing transport encryption
protocols, such as TLS. TLS provides the Kubernetes API Server with a means to
be able to authenticate sessions and encrypt traffic.

    To enable encrypted communication for Kubelet, the parameter etcd-cafile
must be set. This parameter gives the location of the SSL Certificate Authority
file used to secure Kubelet communication.
  "
  desc  'rationale', ''
  desc  'check', "
    Change to the /etc/sysconfig/ directory on the Kubernetes Master Node. Run
the commands:

    grep -i tls-private-key-file kubelet

    If the setting \"tls-private-key-file\" is not configured in the Kubernetes
Kubelet, this is a finding.
  "
  desc 'fix', "
    Edit the Kubernetes Kuberlet file in the /etc/sysconfig directory on the
Kubernetes Master Node. Set the argument tls-private-key-file to an Approved
Organization Certificate. Reset Kubelet service using the following command:

    service kubelet restart
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag gid: 'CNTR-K8-001460'
  tag rid: 'CNTR-K8-001460_rule'
  tag stig_id: 'CNTR-K8-001460'
  tag fix_id: 'F-CNTR-K8-001460_fix'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']

  describe.one do
    describe kubelet do
      its('tls-private-key-file') { should_not be_nil }
    end

    describe kubelet_config_file do
      its('tlsPrivateKeyFile') { should_not be_nil }
    end
  end
end
