# encoding: UTF-8

control 'CNTR-K8-003160' do
  title "The Kubernetes Kubelet certificate authority file must have file
permissions set to 644 or more restrictive."
  desc  "The Kubernetes kubelet certificate authority file contains settings
for the Kubernetes Node TLS certificate authority. Any request presenting a
client certificate signed by one of the authorities in the client-ca-file is
authenticated with an identity corresponding to the CommonName of the client
certificate. If this file can be changed, the Kubernetes architecture could be
compromised. The scheduler will implement the changes immediately. Many of the
security settings within the document are implemented through this file."
  desc  'rationale', ''
  desc  'check', "
    Change to the /etc/sysconfig/ directory on the Kubernetes Master Node. Run
command:

    more kubelet
    --client-ca-file argument
    Note certificate location

    If the ca-file argument location file has permissions more permissive than
\"644\", this is a finding.
  "
  desc  'fix', "
    Change the permissions of the --client-ca-file to \"644\" by executing the
command:

    chown 644 <kubelet --client--ca-file argument location>.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'CNTR-K8-003160'
  tag rid: 'CNTR-K8-003160_rule'
  tag stig_id: 'CNTR-K8-003160'
  tag fix_id: 'F-CNTR-K8-003160_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe.one do
    describe file(kubelet.params['client-ca-file'].first) do
      it { should_not be_more_permissive_than('0644')}
    end

    describe file(kubelet_config_file.params['authentication']['x509']['clientCAFile']) do
      it { should_not be_more_permissive_than('0644')}
    end
  end
end

