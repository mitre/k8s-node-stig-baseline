# encoding: UTF-8

control 'CNTR-K8-001500' do
  title 'Kubernetes etcd must have a certificate for communication.'
  desc  "Kubernetes stores configuration and state information in a distributed
key-value store called etcd. Anyone who can write to etcd can effectively
control a Kubernetes cluster. Even just reading the contents of etcd could
easily provide helpful hints to a would-be attacker. Using authenticity
protection, the communication can be protected against man-in-the-middle
attacks/session hijacking and the insertion of false information into sessions.

    The communication session is protected by utilizing transport encryption
protocols, such as TLS. TLS provides the Kubernetes API Server and etcd with a
means to be able to authenticate sessions and encrypt traffic.

    To enable encrypted communication for etcd, the parameter etcd-certfile
must be set. This parameter gives the location of the SSL certification file
used to secure etcd communication.
  "
  desc  'rationale', ''
  desc  'check', "
    Change to the /etc/kubernetes/manifests directory on the Kubernetes Master
Node. Run the command:

    grep -i etcd-certfile *

    If the setting \"etcd-certfile\" is not configured in the Kubernetes etcd
manifest file, this is a finding.
  "
  desc 'fix', "Edit the Kubernetes etcd manifest file in the
/etc/kubernetes/manifests directory on the Kubernetes Master Node. Set the
value of \"--etcd-certfile\" to the Approved Organizational Certificate."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag gid: 'CNTR-K8-001500'
  tag rid: 'CNTR-K8-001500_rule'
  tag stig_id: 'CNTR-K8-001500'
  tag fix_id: 'F-CNTR-K8-001500_fix'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']

  # The check/fix text is likely a wrong guidance.
  # This control matches `cert-file`; `etcd-certfile` is configured at Kubelet-apiserver level and addressed in CNTR-K8-001520
  # Automation code created matches the expect correct guidance.

  unless etcd.exist?
    impact 0.0
    desc 'caveat', 'ETCD process is not running on the target.'
  end

  describe.one do
    describe etcd do
      its('cert-file') { should_not be_nil }
    end

    describe process_env_var('etcd') do
      its(:ETCD_CERT_FILE) { should_not be_nil }
    end
  end
end
