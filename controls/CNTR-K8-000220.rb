# encoding: UTF-8

control 'CNTR-K8-000220' do
  title "The Kubernetes Controller Manager must create unique service accounts
for each work payload."
  desc  "The Kubernetes Controller Manager is a background process that embeds
core control loops regulating cluster system state through the API Server.
Every process executed in a pod has an associated service account. By default,
service accounts use the same credentials for authentication. Implementing the
default settings poses a High risk to the Kubernetes Controller Manager.
Setting the use-service-account-credential value lowers the attack surface by
generating unique service accounts settings for each controller instance."
  desc  'rationale', ''
  desc  'check', "
    Change to the /etc/kubernetes/manifests directory on the Kubernetes Master
Node. Run the command:

    grep -i use-service-account-credential *

    If the setting use-service-account-credential is not configured in the
Kubernetes Controller Manager manifest file or it is set to \"false\", this is
a finding.
  "
  desc  'fix', "Edit the Kubernetes Controller Manager manifest file in the
/etc/kubernetes/manifests directory on the Kubernetes Master Node. Set the
value of \"use-service-account-credential\" to \"true\"."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000023-CTR-000055'
  tag gid: 'CNTR-K8-000220'
  tag rid: 'CNTR-K8-000220_rule'
  tag stig_id: 'CNTR-K8-000220'
  tag fix_id: 'F-CNTR-K8-000220_fix'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
