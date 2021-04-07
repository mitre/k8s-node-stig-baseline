# encoding: UTF-8

control 'CNTR-K8-002000' do
  title "The Kubernetes API server must have the ValidatingAdmissionWebhook
enabled."
  desc  "Enabling the admissions webhook allows for Kubernetes to apply
policies against objects that are to be created, read, updated, or deleted. By
applying a pod security policy, control can be given to not allow images to be
instantiated that run as the root user. If pods run as the root user, the pod
then has root privileges to the host system and all the resources it has. An
attacker can use this to attack the Kubernetes cluster. By implementing a
policy that does not allow root or privileged pods, the pod users are limited
in what the pod can do and access."
  desc  'rationale', ''
  desc  'check', "
    Change to the /etc/kubernetes/manifests directory on the Kubernetes Master
Node. Run the command:

    grep -i ValidatingAdmissionWebhook *

    If a line is not returned that includes enable-admission-plugins and
ValidatingAdmissionWebhook, this is a finding.
  "
  desc  'fix', "
    Edit the Kubernetes API Server manifest file in the
/etc/kubernetes/manifests directory on the Kubernetes Master Node. Set the
argument \"--enable-admission-plugins\" to include
\"ValidatingAdmissionWebhook\".  Each enabled plugin is separated by commas.

    Note: It is best to implement policies first and then enable the webhook,
otherwise a denial of service may occur.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000342-CTR-000775'
  tag gid: 'CNTR-K8-002000'
  tag rid: 'CNTR-K8-002000_rule'
  tag stig_id: 'CNTR-K8-002000'
  tag fix_id: 'F-CNTR-K8-002000_fix'
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end

