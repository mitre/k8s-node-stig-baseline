control 'SV-242392' do
  title 'The Kubernetes kubelet must enable explicit authorization.'
  desc 'Kubelet is the primary agent on each node. The API server communicates
with each kubelet to perform tasks such as starting/stopping pods. By default,
kubelets allow all authenticated requests, even anonymous ones, without
requiring any authorization checks from the API server. This default behavior
bypasses any authorization controls put in place to limit what users may
perform within the Kubernetes cluster. To change this behavior, the default
setting of AlwaysAllow for the authorization mode must be set to "Webhook".'
  desc 'check', %q(Run the following command on each Worker Node:
ps -ef | grep kubelet
Verify that the --authorization-mode exists and is set to "Webhook".

If the --authorization-mode argument is not set to "Webhook" or doesn't exist, this is a finding.)
  desc 'fix', 'Edit the Kubernetes Kubelet service file in the --config directory on the Kubernetes Worker Node:

Set the value of "--authorization-mode" to "Webhook" in KUBELET_SYSTEM_PODS_ARGS variable.

Restart the kubelet service using the following command:

systemctl daemon-reload && systemctl restart kubelet'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag gid: 'V-242392'
  tag rid: 'SV-242392r1137639_rule'
  tag stig_id: 'CNTR-K8-000380'
  tag fix_id: 'F-45625r1069460_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  describe kubelet do
    its('authorization-mode') { should cmp 'Webhook' }
  end
end
