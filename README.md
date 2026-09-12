# Kubernetes Node STIG Automated Compliance Validation Profile

This InSpec profile evaluates the node OS requirements of the DISA Kubernetes
Security Technical Implementation Guide (STIG), **Version 2 Release 6**. Run it
alongside the [Kubernetes Cluster profile](https://github.com/mitre/k8s-cluster-stig-baseline),
which assesses resources through the Kubernetes API. Run this node profile on
each control-plane and worker node.

## Requirements and setup

Use an audit runner with Git, Ruby, and Bundler. CI uses Ruby 3.1. Install the
Gemfile dependencies, including Cinc Auditor, the community distribution
compatible with InSpec profiles:

```sh
bundle install
bundle exec cinc-auditor version
```

Bundler creates a local `Gemfile.lock`; this repository does not track it. Keep
that file when you need to reproduce a local dependency resolution.

For SSH scans, the runner needs access to each node and an account able to read
its processes and configuration files, normally through sudo. Use another
supported node transport when SSH is disabled, as required by the worker-node
SSH controls. The Kind test suites use Docker transport.

## Profile inputs

[inspec.yml](inspec.yml) declares every input and default. Supply overrides as a
mapping in an input file. For example, save the following as `inputs.yml` and
set the role, version, and paths for the actual target:

```yaml
node_roles:
  - control-plane
# Example for Kubernetes 1.32; replace 32 with the target's actual minor version.
kubernetes_minor_version: 32
etcd_managed_on_node: true
manifests_path: /etc/kubernetes/manifests
etcd_data_dir: /var/lib/etcd
kubeadm_conf_path: /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
```

Use `node_roles: [worker]` for a worker and
`node_roles: [control-plane, worker]` for a dual-role node. This required input
has no default; provide the exact role names. Always set
`kubernetes_minor_version` to the actual target minor version. It is required
and has no default. InSpec enforces input types and required values. Basic
checks also reject unknown roles, invalid minor versions, missing or malformed
file modes, nonpositive thresholds, and empty configuration-file lists.

| Input | Default | Purpose |
|---|---|---|
| `node_roles` | Required; no default | `control-plane`, `worker`, or both. |
| `kubernetes_minor_version` | Required; no default | Selects version-specific checks; explicitly set the target's minor version. |
| `manifests_path` | `/etc/kubernetes/manifests` | Directory containing the node's static Pod manifests. |
| `etcd_managed_on_node` | `true` | Whether a control-plane node hosts the etcd instance being assessed. |
| `etcd_data_dir` | `/var/lib/etcd` | Local etcd data directory. |
| `pki_path` | `/etc/kubernetes/pki/` | Kubernetes PKI directory. |
| `kubeadm_conf_path` | `/etc/systemd/system/kubelet.service.d/10-kubeadm.conf` | Kubeadm-installed kubelet service drop-in, not the kubeadm executable. |
| `kubectl_path` | `/usr/local/bin/kubectl` | kubectl executable on the target node. |
| `kubectl_kubeconfig_path` | `/etc/kubernetes/admin.conf` | Target-node kubeconfig used for the API-server/client skew check. |
| `kubectl_minversion` | `1.12.9` | STIG minimum client version; not a general supported-version or skew check. |
| `kubernetes_conf_files` | `/etc/kubernetes/admin.conf`, `/etc/kubernetes/scheduler.conf`, `/etc/kubernetes/controller-manager.conf` | Files assessed for ownership and permissions. |
| `kubernetes_file_modes` | See below | Maximum allowed permission bits for each artifact category. |
| `audit_log_retention_days` | `30` | Minimum configured local audit-log retention. |
| `streaming_connection_idle_timeout_seconds` | `300` | Minimum configured kubelet streaming idle timeout. |

The etcd manifest and data controls apply to control-plane nodes where
`etcd_managed_on_node` is `true`. Set it to `false` only for external etcd and
arrange a separate assessment of that instance. The manifest controls expect
`etcd.yaml` under `manifests_path`. Paths refer to the target node's filesystem.

File-mode defaults enforce the unmodified STIG requirements. Overrides are
organizational tailoring. If overriding `kubernetes_file_modes`, supply the
complete mapping so every category retains a value:

```yaml
kubernetes_file_modes:
  manifest_files: '0644'
  kubelet_config_file: '0644'
  kube_proxy_kubeconfig_file: '0644'
  kubelet_client_ca_file: '0644'
  kubelet_kubeconfig_file: '0644'
  kubeadm_conf_file: '0644'
  etcd_data_files: '0644'
  kubernetes_conf_files: '0644'
  pki_certificate_files: '0644'
  pki_private_key_files: '0600'
```

## Run an assessment

Run commands from the profile directory. Replace the SSH target and private-key
path with the audit account's connection details.

```sh
# Run all controls and save results.
bundle exec cinc-auditor exec . -t ssh://AUDIT_USER@NODE --sudo \
  -i ~/.ssh/audit_key --input-file inputs.yml --show-progress \
  --reporter cli json:results.json

# Run one control.
bundle exec cinc-auditor exec . -t ssh://AUDIT_USER@NODE --sudo \
  -i ~/.ssh/audit_key --input-file inputs.yml --controls SV-242379 \
  --show-progress
```

The profile reads saved static Pod manifests for kube-apiserver,
kube-controller-manager, kube-scheduler, and etcd, plus kubelet/process evidence
and file ownership and permissions. Missing or malformed manifests fail on
applicable control-plane nodes. Distribution-specific deployments without these
manifests require an overlay that supplies equivalent evidence.

The `etcd_manifest` resource selects the etcd container, parses its arguments,
and reads a mounted etcd config file when configured. That file replaces flag
and environment settings. Referenced policy/configuration files are resolved
through the component's hostPath volume mounts, including different host and
container paths; inaccessible or unsupported mappings produce findings.

Node controls SV-254800, SV-274882, SV-254801, and SV-242443 now implement the
host-local portions delegated by the cluster profile: admission policy contents,
Secrets encryption configuration, kubelet PodSecurity settings, and version skew.
These IDs intentionally occur in both profiles with complementary checks;
retain both assessment results. Organizational least-privilege justification
still requires manual review. Run the skew check against every API-server
endpoint in an HA cluster using the appropriate `kubectl_kubeconfig_path`.

Node review evidence includes the actual PodSecurity configuration-file path,
including a separately referenced policy file. SV-245544 retains its required
certificate/key flag checks and adds organizational approval review with the
resolved file paths and public certificate subject, issuer, serial, and validity
period. It does not read or report private-key contents. Etcd TLS result labels
identify whether settings came from manifest arguments, environment variables,
or a mounted configuration file; environment values are not included in labels.

## Profile libraries

The three local libraries keep file parsing reusable: `kubernetes_manifest.rb`
reads static Pod settings and mounted files, `etcd_manifest.rb` applies etcd's
configuration precedence, and `kubernetes_arguments.rb` parses flags and durations.
Policy assertions stay in their controls. Cinc automatically loads the libraries;
controls call them directly. Basic input checks run once in `controls/00_inputs.rb`.

## Lint and validate

```sh
bundle exec cinc-auditor vendor . --overwrite
bundle exec rake pre_commit_checks
```

The vendor command replaces `vendor/`. Preserve any SAF delta output stored
there before running it. `pre_commit_checks` runs RuboCop and Cinc Auditor
profile validation; any failure returns a nonzero status. To run them
individually, use `bundle exec rake lint` and `bundle exec rake inspec:check`.
The latter retains its historical task name but invokes Cinc Auditor.

The lint configuration is based on the RHEL 9 sibling profile, targets Ruby
3.1, includes local resource libraries, and excludes vendored dependencies
and Kitchen artifacts. The lint workflow runs on
pull requests and pushes to `main`.

## Test Kitchen Kind suites

Both disposable suites require Docker Desktop (or Docker Engine), `kind`, and
`kubectl` in addition to Ruby and Bundler. Vendor the profile as shown above,
then run:

```sh
KITCHEN_LOCAL_YAML=kitchen.kind.yml bundle exec kitchen test --destroy=always vanilla
KITCHEN_LOCAL_YAML=kitchen.kind.yml bundle exec kitchen test --destroy=always hardened
```

The profile connects to the Kind control-plane container using Docker transport
so it can inspect the node's Linux processes and files. `vanilla` audits an
unmodified Kind v1.32.2 node. `hardened` adds an audit policy, retention settings,
TLS settings, admission and encryption policies, and kubelet timeout/kernel-protection settings.
Its encryption key is generated for each run and removed with the test cluster. These fixtures
exercise selected checks; they are not a production hardening procedure.

Suite inputs are in `kind.vanilla.inputs.yml` and `kind.hardened.inputs.yml`.
They point `kubeadm_conf_path` at Kind's installed
`/etc/systemd/system/kubelet.service.d/10-kubeadm.conf` service drop-in.
Use the actual drop-in path for other distributions.

Validate saved results with the suite's SAF threshold:

```sh
saf validate threshold -i results/kind_vanilla.json -T kind.vanilla.threshold.yml
saf validate threshold -i results/kind_hardened.json -T kind.hardened.threshold.yml
```

The vanilla threshold reflects 49 passing controls out of 73 applicable checks
on the pinned Kind image; absent admission/encryption configuration produces
expected findings. The hardened threshold remains 90%, and both require zero
profile errors.

Install the MITRE SAF CLI separately to use those commands. JSON assessment
results can also be opened in [Heimdall Lite](https://heimdall-lite.mitre.org/).
