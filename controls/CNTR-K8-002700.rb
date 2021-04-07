# encoding: UTF-8

control 'CNTR-K8-002700' do
  title "Kubernetes must remove old components after updated versions have been
installed."
  desc  "Previous versions of Kubernetes components that are not removed after
updates have been installed may be exploited by adversaries by allowing the
vulnerabilities to still exist within the cluster. It is important for
Kubernetes to remove old pods when newer pods are created using new images to
always be at the desired security state."
  desc  'rationale', ''
  desc  'check', "
    To view all pods and the images used to create the pods, from the Master
node, run the following command:

    kubectl get pods --all-namespaces -o jsonpath=\"{..image}\" | \\
    tr -s '[[:space:]]' '\
    ' | \\
    sort | \\
    uniq -c

    Review the images used for pods running within Kubernetes.

    If there are multiple versions of the same image, this is a finding.
  "
  desc  'fix', "
    Remove any old pods that are using older images. On the Master node, run
the command:

    kubectl delete pod podname
    (Note: \"podname\" is the name of the pod to delete.)
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000454-CTR-001110'
  tag gid: 'CNTR-K8-002700'
  tag rid: 'CNTR-K8-002700_rule'
  tag stig_id: 'CNTR-K8-002700'
  tag fix_id: 'F-CNTR-K8-002700_fix'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end

