# encoding: UTF-8

control 'CNTR-K8-001410' do
  title 'Kubernetes API Server must have the SSL Certificate Authority set.'
  desc  "Kubernetes control plane and external communication is managed by API
Server. The main implementation of the API Server is to manage hardware
resources for pods and containers using horizontal or vertical scaling. Anyone
who can access the API Server can effectively control the Kubernetes
architecture. Using authenticity protection, the communication can be protected
against man-in-the-middle attacks/session hijacking and the insertion of false
information into sessions.

    The communication session is protected by utilizing transport encryption
protocols, such as TLS. TLS provides the Kubernetes API Server with a means to
be able to authenticate sessions and encrypt traffic.

    To enable encrypted communication for API Server, the parameter etcd-cafile
must be set. This parameter gives the location of the SSL Certificate Authority
file used to secure API Server communication.
  "
  desc  'rationale', ''
  desc  'check', "
    Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Master
Node. Run the command:

    grep -i client-ca-file *

    If the setting feature client-ca-file is not set in the Kubernetes API
server manifest file or contains no value, this is a finding.
  "
  desc  'fix', "Edit the Kubernetes API Server manifest file in the
/etc/kubernetes/manifests directory on the Kubernetes Master Node. Set the
value of client-ca-file to path containing Approved Organizational Certificate."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag gid: 'CNTR-K8-001410'
  tag rid: 'CNTR-K8-001410_rule'
  tag stig_id: 'CNTR-K8-001410'
  tag fix_id: 'F-CNTR-K8-001410_fix'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end

