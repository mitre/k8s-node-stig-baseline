# encoding: UTF-8

control 'CNTR-K8-001480' do
  title 'Kubernetes etcd must enable client authentication to secure service.'
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
    Change to the /etc/kubernetes/manifests directory on the Kubernetes Master
Node. Run the command:

    grep -i client-cert-auth *

    If the setting \"client-cert-auth\" is not configured in the Kubernetes
etcd manifest file or set to \"false\", this is a finding.
  "
  desc 'fix', "Edit the Kubernetes etcd manifest file in the
/etc/kubernetes/manifests directory on the Kubernetes Master Node. Set the
value of \"--client-cert-auth\" to \"true\" for the etcd."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag gid: 'CNTR-K8-001480'
  tag rid: 'CNTR-K8-001480_rule'
  tag stig_id: 'CNTR-K8-001480'
  tag fix_id: 'F-CNTR-K8-001480_fix'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']

  # The check/fix text is likely a wrong guidance.
  # This control likely will refer to peer-client-cert-auth config.
  # `client-cert-auth` config is already addressed in `CNTR-K8-001450`.
  # Automation code created matches the expect correct guidance.

  unless etcd.exist?
    impact 0.0
    desc 'caveat', 'ETCD process is not running on the target.'
  end

  describe.one do
    describe etcd do
      its('peer-client-cert-auth') { should_not be_nil }
    end

    describe process_env_var('etcd') do
      its(:ETCD_PEER_CA_FILE) { should_not be_nil }
    end
  end
end
