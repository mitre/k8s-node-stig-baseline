# encoding: UTF-8

control 'CNTR-K8-000420' do
  title 'Kubernetes dashboard must not be enabled.'
  desc  "While the Kubernetes dashboard is not inherently insecure on its own,
it is often coupled with a misconfiguration of Role-Based Access control (RBAC)
permissions that can unintentionally over-grant access. It is not commonly
protected with \"NetworkPolicies\", preventing all pods from being able to
reach it. In increasingly rare circumstances, the Kubernetes dashboard is
exposed publicly to the internet."
  desc  'rationale', ''
  desc  'check', "
    From the master node, run the command:

    kubectl get pods --all-namespaces -l k8s-app=kubernetes-dashboard

    If any resources are returned, this is a finding.
  "
  desc  'fix', "
    Delete the Kubernetes dashboard deployment with the following command:

    kubectl delete deployment kubernetes-dashboard --namespace=kube-system
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag gid: 'CNTR-K8-000420'
  tag rid: 'CNTR-K8-000420_rule'
  tag stig_id: 'CNTR-K8-000420'
  tag fix_id: 'F-CNTR-K8-000420_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

