# encoding: UTF-8

control 'CNTR-K8-000910' do
  title 'Kubernetes Controller Manager must disable profiling.'
  desc  "Kubernetes profiling provides the ability to analyze and troubleshoot
Controller Manager events over a web interface on a host port. Enabling this
service can expose details about the Kubernetes architecture. This service must
not be enabled unless deemed necessary."
  desc  'rationale', ''
  desc  'check', "
    Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Master
Node. Run the command:

    grep -i profiling *

    If the setting \"profiling\" is not configured in the Kubernetes Controller
Manager manifest file or it is set to \"True\", this is a finding.
  "
  desc  'fix', "Edit the Kubernetes Controller Manager manifest file in the
/etc/kubernetes/manifests directory on the Kubernetes Master Node. Set the
argument \"--profiling value\" to \"false\"."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-CTR-000315'
  tag gid: 'CNTR-K8-000910'
  tag rid: 'CNTR-K8-000910_rule'
  tag stig_id: 'CNTR-K8-000910'
  tag fix_id: 'F-CNTR-K8-000910_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

