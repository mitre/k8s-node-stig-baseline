# encoding: UTF-8

control 'CNTR-K8-003230' do
  title "The Kubernetes kubelet config must have file permissions set to 644 or
more restrictive."
  desc  "The Kubernetes kubelet agent registers nodes with the API server and
performs health checks to containers within pods. If this file can be modified,
the information system would be unaware of pod or container degradation."
  desc  'rationale', ''
  desc  'check', "
    Review the permissions of the Kubernetes config.yaml by using the command:

    stat -c %a /var/lib/kubelet/config.yaml

    If any of the files are have permissions more permissive than \"644\", this
is a finding.
  "
  desc  'fix', "
    Change the permissions of the config.yaml to \"644\" by executing the
command:

    chown 644 /var/lib/kubelet/config.yaml
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001330'
  tag gid: 'CNTR-K8-003230'
  tag rid: 'CNTR-K8-003230_rule'
  tag stig_id: 'CNTR-K8-003230'
  tag fix_id: 'F-CNTR-K8-003230_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

