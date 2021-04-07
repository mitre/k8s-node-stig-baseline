# encoding: UTF-8

control 'CNTR-K8-001160' do
  title 'Secrets in Kubernetes must not be stored as environment variables.'
  desc  "Secrets, such as passwords, keys, tokens, and certificates should not
be stored as environment variables. These environment variables are accessible
inside Kubernetes by the \"Get Pod\" API call, and by any system, such as CI/CD
pipeline, which has access to the definition file of the container. Secrets
must be mounted from files or stored within password vaults."
  desc  'rationale', ''
  desc  'check', "
    On the Kubernetes Master node, run the following command:

    kubectl get all -o jsonpath='{range .items[?(@..secretKeyRef)]} {.kind}
{.metadata.name} {\"\
    \"}{end}' -A

    If any of the values returned reference environment variables, this is a
finding.
  "
  desc  'fix', "Any secrets stored as environment variables must be moved to
the secret files with the proper protections and enforcements or placed within
a password vault."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000171-CTR-000435'
  tag gid: 'CNTR-K8-001160'
  tag rid: 'CNTR-K8-001160_rule'
  tag stig_id: 'CNTR-K8-001160'
  tag fix_id: 'F-CNTR-K8-001160_fix'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end

