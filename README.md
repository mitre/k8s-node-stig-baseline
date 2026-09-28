## Kubernetes Node STIG Automated Compliance Validation Profile

InSpec profile to validate the secure configuration of a Kubernetes node against [DISA's](https://public.cyber.mil/stigs/downloads/) Kubernetes Security Technical Implementation Guide (STIG) Version 2 Release 6.

## Getting Started

It is recommended that Cinc Auditor and this profile be run from a **runner** host, such as a DevOps orchestration server, administrative management system, or developer workstation, against each target node using the SSH transport.

The Kubernetes STIG includes requirements for both the cluster and the nodes that comprise it. This profile contains the node checks and is intended to be used with the [Kubernetes Cluster profile](https://github.com/mitre/k8s-cluster-stig-baseline).

### Requirements

#### Kubernetes Node

- Kubernetes platform deployment
- SSH access to each Kubernetes node
- An account with permission to perform the audit, normally through sudo

#### Required software on the runner

- Git
- Ruby and Bundler

### Set up the runner

Install the profile dependencies, including Cinc Auditor:

```sh
bundle install
bundle exec cinc-auditor version
```

### Profile input values

Profile inputs and their defaults are defined in [inspec.yml](inspec.yml). Create an `inputs.yml` file with the target node's role and Kubernetes minor version, which are required and do not have defaults:

```yaml
node_roles:
  - control-plane
kubernetes_minor_version: 32
```

Use `worker` for a worker node or include both `control-plane` and `worker` for a dual-role node. Replace `32` with the target's actual Kubernetes minor version. Override other paths or settings in the same file only when the defaults in `inspec.yml` do not match the target.

### How to execute this profile

Run the node profile on each control-plane and worker node. Run these commands from the profile directory and replace the connection values with those for the audit account.

#### Execute a single control

```sh
bundle exec cinc-auditor exec . \
  -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo \
  -i PATH_TO_PRIVATE_KEY --input-file inputs.yml \
  --controls SV-242379 --show-progress
```

#### Execute all controls

```sh
bundle exec cinc-auditor exec . \
  -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo \
  -i PATH_TO_PRIVATE_KEY --input-file inputs.yml --show-progress
```

#### Execute all controls and save the results as JSON

```sh
bundle exec cinc-auditor exec . \
  -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo \
  -i PATH_TO_PRIVATE_KEY --input-file inputs.yml --show-progress \
  --reporter cli json:results.json
```

## Check overview

This profile evaluates the following Kubernetes components:

- kube-apiserver
- kube-controller-manager
- kube-scheduler
- kubelet
- kube-proxy
- etcd

If these components are deployed differently or use nonstandard configuration paths, override the applicable inputs or adapt the profile for the target distribution using an [InSpec profile overlay](https://docs.chef.io/inspec/profiles/).
