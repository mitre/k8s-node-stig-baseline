# encoding: UTF-8

control 'CNTR-K8-001530' do
  title 'Kubernetes etcd must have a key file for secure communication.'
  desc  "Kubernetes stores configuration and state information in a distributed
key-value store called etcd. Anyone who can write to etcd can effectively
control a Kubernetes cluster. Even just reading the contents of etcd could
easily provide helpful hints to a would-be attacker. Using authenticity
protection, the communication can be protected against man-in-the-middle
attacks/session hijacking and the insertion of false information into sessions.

    The communication session is protected by utilizing transport encryption
protocols, such as TLS. TLS provides the Kubernetes API Server and etcd with a
means to be able to authenticate sessions and encrypt traffic.

    To enable encrypted communication for etcd, the parameter etcd-keyfile must
be set. This parameter gives the location of the key file used to secure etcd
communication.
  "
  desc  'rationale', ''
  desc  'check', "
    Change to the /etc/kubernetes/manifests directory on the Kubernetes Master
Node. Run the command:

    grep -i etcd-keyfile *

    If the setting \"etcd-keyfile\" is not configured in the Kubernetes API
Server manifest file, this is a finding.
  "
  desc  'fix', "Edit the Kubernetes API Server manifest file in the
/etc/kubernetes/manifests directory on the Kubernetes Master Node. Set the
value of \"--etcd-keyfile\" to the certificate to be used for communication
with etcd."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag gid: 'CNTR-K8-001530'
  tag rid: 'CNTR-K8-001530_rule'
  tag stig_id: 'CNTR-K8-001530'
  tag fix_id: 'F-CNTR-K8-001530_fix'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end

