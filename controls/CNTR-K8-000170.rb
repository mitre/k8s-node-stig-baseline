# encoding: UTF-8

control 'CNTR-K8-000170' do
  title "The Kubernetes API Server must use TLS 1.2, at a minimum, to protect
the confidentiality of sensitive data during electronic dissemination."
  desc  "The Kubernetes API Server will prohibit the use of SSL and
unauthorized versions of TLS protocols to properly secure communication.

    The use of unsupported protocol exposes vulnerabilities to the Kubernetes
by rogue traffic interceptions, man-in-the-middle attacks, and impersonation of
users or services from the container platform runtime, registry, and keystore.
To enable the minimum version of TLS to be used by the Kubernetes API Server,
the setting \"tls-min-version\" must be set.
  "
  desc  'rationale', ''
  desc  'check', "
    Change to the /etc/kubernetes/manifests directory on the Kubernetes Master
Node. Run the command:

    grep -i tls-min-version *

    If the setting \"tls-min-version\" is not configured in the Kubernetes API
Server manifest file or it is set to \"VersionTLS10\" or \"VersionTLS11\", this
is a finding.
  "
  desc 'fix', "Edit the Kubernetes API Server manifest file in the
/etc/kubernetes/manifests directory on the Kubernetes Master Node. Set the
value of \"--tls-min-version\" to \"VersionTLS12\" or higher."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000014-CTR-000040'
  tag gid: 'CNTR-K8-000170'
  tag rid: 'CNTR-K8-000170_rule'
  tag stig_id: 'CNTR-K8-000170'
  tag fix_id: 'F-CNTR-K8-000170_fix'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']

  unless kube_apiserver.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes API Server process is not running on the target.'
  end

  describe kube_apiserver do
    its('tls-min-version') { should_not be_nil }
    its('tls-min-version') { should_not cmp 'VersionTLS10' }
    its('tls-min-version') { should_not cmp 'VersionTLS11' }
  end
end
