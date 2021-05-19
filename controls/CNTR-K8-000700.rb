# encoding: UTF-8

control 'V-242403' do
  title "Kubernetes API Server must generate audit records that identify what
type of event has occurred, identify the source of the event, contain the event
results, identify any users, and identify any containers associated with the
event."
  desc  "Within Kubernetes, audit data for all components is generated by the
API server. This audit data is important when there are issues, to include
security incidents that must be investigated. To make the audit data worthwhile
for the investigation of events, it is necessary to have the appropriate and
required data logged. To fully understand the event, it is important to
identify any users associated with the event.

    The API server policy file allows for the following levels of auditing:
          None - Do not log events that match the rule.
          Metadata - Log request metadata (requesting user, timestamp,
resource, verb, etc.) but not request or response body.
          Request - Log event metadata and request body but not response body.
          RequestResponse - Log event metadata, request, and response bodies.


  "
  desc  'rationale', ''
  desc  'check', "
    Change to the /etc/kubernetes/manifests directory on the Kubernetes Master
Node. Run the command:

    grep -i audit-policy-file

    If the audit-policy-file is not set, this is a finding.

    The file given is the policy file and defines what is audited and what
information is included with each event.

    The policy file must look like this:

    # Log all requests at the RequestResponse level.
    apiVersion: audit.k8s.io/vX (Where X is the latest apiVersion)
    kind: Policy
    rules:
    - level: RequestResponse

    If the audit policy file does not look like above, this is a finding.
  "
  desc 'fix', "
    Edit the Kubernetes API Server audit policy and set it to look like the
following:

    # Log all requests at the RequestResponse level.
    apiVersion: audit.k8s.io/vX (Where X is the latest apiVersion)
    kind: Policy
    rules:
    - level: RequestResponse
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000026-CTR-000070'
  tag satisfies: ['SRG-APP-000026-CTR-000070', 'SRG-APP-000027-CTR-000075',
                  'SRG-APP-000028-CTR-000080', 'SRG-APP-000101-CTR-000205',
                  'SRG-APP-000100-CTR-000200', 'SRG-APP-000100-CTR-000195',
                  'SRG-APP-000099-CTR-000190', 'SRG-APP-000098-CTR-000185',
                  'SRG-APP-000095-CTR-000170', 'SRG-APP-000096-CTR-000175',
                  'SRG-APP-000097-CTR-000180', 'SRG-APP-000507-CTR-001295',
                  'SRG-APP-000504-CTR-001280', 'SRG-APP-000503-CTR-001275',
                  'SRG-APP-000501-CTR-001265', 'SRG-APP-000500-CTR-001260',
                  'SRG-APP-000497-CTR-001245', 'SRG-APP-000496-CTR-001240',
                  'SRG-APP-000493-CTR-001225', 'SRG-APP-000492-CTR-001220',
                  'SRG-APP-000343-CTR-000780', 'SRG-APP-000381-CTR-000905']
  tag gid: 'V-242403'
  tag rid: 'SV-242403r712565_rule'
  tag stig_id: 'CNTR-K8-000700'
  tag fix_id: 'F-45636r712564_fix'
  tag cci: ['CCI-000018', 'CCI-000130', 'CCI-000131', 'CCI-000132',
            'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000172', 'CCI-001403',
            'CCI-001404', 'CCI-001487', 'CCI-001814', 'CCI-002234']
  tag nist: ['AC-2 (4)', 'AU-3', 'AU-3', 'AU-3', 'AU-3', 'AU-3', 'AU-3 (1)',
             'AU-12 c', 'AC-2 (4)', 'AC-2 (4)', 'AU-3', 'CM-5 (1)', 'AC-6 (9)']

  unless kube_apiserver.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes API Server process is not running on the target.'
  end

  describe kube_apiserver do
    its('audit-policy-file') { should_not be_nil }
  end

  if !kube_apiserver.params['audit-policy-file'].nil? &&
     file(kube_apiserver.params['audit-policy-file'].join).exist?

    describe yaml(kube_apiserver.params['audit-policy-file'].join) do
      its('rules') { should cmp [{ 'level' => 'RequestResponse' }] }
    end
  end
end
