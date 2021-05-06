## Kubernetes Node STIG Automated Compliance Validation Profile

<b>Kubernetes Node</b> STIG Automated Compliance Validation Profile works with Chef InSpec to perform automated compliance checks of <b>Kubernetes Nodes</b>. It is to be used in conjunction with <b>[Kubernetes Cluster](https://gitlab.dsolab.io/scv-content/inspec/kubernetes/k8s-cluster-stig-baseline)</b> profile that validates perform automated compliance checks of <b>Kubernetes Cluster</b>

This automated Security Technical Implementation Guide (STIG) validator was developed to reduce the time it takes to perform a security check based upon STIG Guidance from DISA. These check results should provide information needed to receive a secure authority to operate (ATO) certification for the applicable technology.

<b>Kubernetes Node Profile</b> uses [Chef InSpec](https://github.com/chef/inspec), which provides an open source compliance, security and policy testing framework that dynamically extracts system configuration information.

## Kubernetes STIG Overview

The <b>Kubernetes</b> STIG (https://public.cyber.mil/stigs/) by the United States Defense Information Systems Agency (DISA) offers a comprehensive compliance guide for the configuration and operation of various technologies.
DISA has created and maintains a set of security guidelines for applications, computer systems or networks connected to the DoD. These guidelines are the primary security standards used by many DoD agencies. In addition to defining security guidelines, the STIG also stipulates how security training should proceed and when security checks should occur. Organizations must stay compliant with these guidelines or they risk having their access to the DoD terminated.

[STIG](https://en.wikipedia.org/wiki/Security_Technical_Implementation_Guide)s are the configuration standards for United States Department of Defense (DoD) Information Assurance (IA) and IA-enabled devices/systems published by the United States Defense Information Systems Agency (DISA). Since 1998, DISA has played a critical role enhancing the security posture of DoD's security systems by providing the STIGs. The STIGs contain technical guidance to "lock down" information systems/software that might otherwise be vulnerable to a malicious computer attack.

The requirements associated with the <b>Kubernetes</b> STIG are derived from the [National Institute of Standards and Technology](https://en.wikipedia.org/wiki/National_Institute_of_Standards_and_Technology) (NIST) [Special Publication (SP) 800-53, Revision 4](https://en.wikipedia.org/wiki/NIST_Special_Publication_800-53) and related documents.

While the Kubernetes STIG automation profile check was developed to provide technical guidance to validate information with security systems such as applications, the guidance applies to all organizations that need to meet internal security as well as compliance standards.

### This STIG Automated Compliance Validation Profile was developed based upon:
- Kubernetes Security Technical Implementation Guide
### Update History 
| Guidance Name  | Guidance Version | Guidance Location                            | Profile Version | Profile Release Date | STIG EOL    | Profile EOL |
|---------------------------------------|------------------|--------------------------------------------|-----------------|----------------------|-------------|-------------|
| Kubernetes STIG  | v1r1 | https://public.cyber.mil/stigs/downloads/  |         1.0.0          |                   | NA | NA |


## Getting Started

### Requirements

#### Kubernetes Cluster
- Kubernetes Platform deployment
- Access to the Kubernetes Node over ssh
- Account providing appropriate permissions to perform audit scan


#### Required software on the InSpec Runner
- git
- [InSpec](https://www.chef.io/products/chef-inspec/)

### Setup Environment on the InSpec Runner
#### Install InSpec
Goto https://www.inspec.io/downloads/ and consult the documentation for your Operating System to download and install InSpec.


#### Ensure InSpec version is at least 4.23.10 
```sh
inspec --version
```
### Update Profile Input Values
Update the following `Inputs` in `inspec.yml` if the default values differ in your platform.

```yml
  - name: manifests_path
    description: 'Path to Kubernetes manifest files on the target node'
    type: string
    value: '/etc/kubernetes/manifests'
    required: true

  - name: pki_path
    description: 'Path to Kubernetes PKI files on the target node'
    type: string
    value: '/etc/kubernetes/pki/'
    required: true

  - name: kubeadm_path
    description: 'Path to kubeadm file on the target node'
    type: string
    value: '/usr/local/bin/kubeadm'
    required: true

  - name: kubectl_path
    description: 'Path to kubectl on the target node'
    type: string
    value: '/usr/local/bin/kubectl'
    required: true

  - name: kubernetes_conf_files
    description: 'Path to Kubernetes conf files on the target node'
    type: array
    value:
        - /etc/kubernetes/admin.conf
        - /etc/kubernetes/scheduler.conf
        - /etc/kubernetes/controller-manager.conf
    required: true

```

### How to execute this instance  
(See: https://www.inspec.io/docs/reference/cli/

**Execute the Kubernates Node profile on each node in the cluster. The profile will adapt its checks based on the Kubernetes components located on the node.**

#### Execute a single Control in the Profile 
**Note**: Replace the profile's directory name - e.g. - `<Profile>` with `.` if currently in the profile's root directory.

```sh
inspec exec <Profile> -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo -i <your_PEM_KEY> --controls=<control_id> --show-progress
```

#### Execute a Single Control and save results as JSON 
```sh
inspec exec <Profile> -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo -i <your_PEM_KEY> --controls=<control_id> --show-progress --reporter json:results.json
```

#### Execute All Controls in the Profile 
```sh
inspec exec <Profile>  -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo -i <your_PEM_KEY> --show-progress
```

#### Execute all the Controls in the Profile and save results as JSON 
```sh
inspec exec <Profile> -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo -i <your_PEM_KEY> --show-progress  --reporter json:results.json
```

## Check Overview

**Normal Checks**

These checks will follow the normal automation process and will report accurate STIG compliance PASS/FAIL.

| Check Number | Description                                                                                                                                                                                                               |
|--------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|CNTR-K8-000150| The Kubernetes Controller Manager must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination.|
|CNTR-K8-000160| The Kubernetes Scheduler must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination.|
|CNTR-K8-000170| The Kubernetes API Server must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination.|
|CNTR-K8-000180| The Kubernetes etcd must use TLS to protect the confidentiality of sensitive data during electronic dissemination.|
|CNTR-K8-000190| The Kubernetes etcd must use TLS to protect the confidentiality of sensitive data during electronic dissemination.|
|CNTR-K8-000220| The Kubernetes Controller Manager must create unique service accounts for each work payload.|
|CNTR-K8-000270| The Kubernetes API Server must enable Node,RBAC as the authorization mode.|
|CNTR-K8-000300| The Kubernetes Scheduler must have secure binding.|
|CNTR-K8-000310| The Kubernetes Controller Manager must have secure binding.|
|CNTR-K8-000320| The Kubernetes API server must have the insecure port flag disabled.|
|CNTR-K8-000330| The Kubernetes Kubelet must have the read-only port flag disabled.|
|CNTR-K8-000340| The Kubernetes API server must have the insecure bind address not set.|
|CNTR-K8-000350| The Kubernetes API server must have the secure port set.|
|CNTR-K8-000360| The Kubernetes API server must have anonymous authentication disabled.|
|CNTR-K8-000370| The Kubernetes Kubelet must have anonymous authentication disabled.|
|CNTR-K8-000380| The Kubernetes kubelet must enable explicit authorization.|
|CNTR-K8-000400| Kubernetes Worker Nodes must not have sshd service running.|
|CNTR-K8-000410| Kubernetes Worker Nodes must not have the sshd service enabled.|
|CNTR-K8-000430| Kubernetes Kubectl cp command must give expected access and results.|
|CNTR-K8-000440| The Kubernetes kubelet static PodPath must not enable static pods.|
|CNTR-K8-000450| Kubernetes DynamicAuditing must not be enabled.|
|CNTR-K8-000460| Kubernetes DynamicKubeletConfig must not be enabled.|
|CNTR-K8-000470| The Kubernetes API server must have Alpha APIs disabled.|
|CNTR-K8-000600| The Kubernetes API Server must have an audit policy set.|
|CNTR-K8-000610| The Kubernetes API Server must have an audit log path set.|
|CNTR-K8-000700| Kubernetes API Server must generate audit records that identify what type of event has occurred, identify the source of the event, contain the event results, identify any users, and identify any containers associated with the event.|
|CNTR-K8-000850| Kubernetes Kubelet must deny hostname override.|
|CNTR-K8-000860| The Kubernetes manifests must be owned by root.|
|CNTR-K8-000880| The Kubernetes kubelet configuration file must be owned by root.|
|CNTR-K8-000890| The Kubernetes kubelet configuration file must be owned by root.|
|CNTR-K8-000900| The Kubernetes manifests must have least privileges.|
|CNTR-K8-000910| Kubernetes Controller Manager must disable profiling.|
|CNTR-K8-001300| Kubernetes Kubelet must not disable timeouts.|
|CNTR-K8-001400| The Kubernetes API server must use approved cipher suites.|
|CNTR-K8-001410| Kubernetes API Server must have the SSL Certificate Authority set.|
|CNTR-K8-001420| Kubernetes Kubelet must have the SSL Certificate Authority set.|
|CNTR-K8-001430| Kubernetes Controller Manager must have the SSL Certificate Authority set.|
|CNTR-K8-001440| Kubernetes API Server must have a certificate for communication.|
|CNTR-K8-001450| Kubernetes etcd must enable client authentication to secure service.|
|CNTR-K8-001460| Kubernetes Kubelet must enable tls-private-key-file for client authentication to secure service.|
|CNTR-K8-001470| Kubernetes Kubelet must enable tls-cert-file for client authentication to secure service.|
|CNTR-K8-001480| Kubernetes etcd must enable client authentication to secure service.|
|CNTR-K8-001490| Kubernetes etcd must have a key file for secure communication.|
|CNTR-K8-001500| Kubernetes etcd must have a certificate for communication.|
|CNTR-K8-001510| Kubernetes etcd must have the SSL Certificate Authority set.|
|CNTR-K8-001520| Kubernetes etcd must have a certificate for communication.|
|CNTR-K8-001530| Kubernetes etcd must have a key file for secure communication.|
|CNTR-K8-001540| Kubernetes etcd must have peer-cert-file set for secure communication.|
|CNTR-K8-001550| Kubernetes etcd must have a peer-key-file set for secure communication.|
|CNTR-K8-001620| Kubernetes Kubelet must enable kernel protection.|
|CNTR-K8-001990| Kubernetes must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures or the installation of patches and updates.|
|CNTR-K8-002000| The Kubernetes API server must have the ValidatingAdmissionWebhook enabled.|
|CNTR-K8-002600| Kubernetes API Server must configure timeouts to limit attack surface.|
|CNTR-K8-002620| Kubernetes API Server must disable basic authentication to protect information in transit.|
|CNTR-K8-002630| Kubernetes API Server must disable token authentication to protect information in transit.|
|CNTR-K8-002640| Kubernetes endpoints must use approved organizational certificate and key pair to protect information in transit.|
|CNTR-K8-003110| The Kubernetes component manifests must be owned by root.|
|CNTR-K8-003120| The Kubernetes component etcd must be owned by etcd.|
|CNTR-K8-003130| The Kubernetes conf files must be owned by root.|
|CNTR-K8-003140| The Kubernetes Kube Proxy must have file permissions set to 644 or more restrictive.|
|CNTR-K8-003150| The Kubernetes Kube Proxy must be owned by root.|
|CNTR-K8-003160| The Kubernetes Kubelet certificate authority file must have file permissions set to 644 or more restrictive.|
|CNTR-K8-003170| The Kubernetes Kubelet certificate authority must be owned by root.|
|CNTR-K8-003180| The Kubernetes component PKI must be owned by root.|
|CNTR-K8-003190| The Kubernetes kubelet config must have file permissions set to 644 or more restrictive.|
|CNTR-K8-003200| The Kubernetes kubelet config must be owned by root.|
|CNTR-K8-003210| The Kubernetes kubeadm must be owned by root.|
|CNTR-K8-003220| The Kubernetes kubelet service must have file permissions set to 644 or more restrictive.|
|CNTR-K8-003230| The Kubernetes kubelet config must have file permissions set to 644 or more restrictive.|
|CNTR-K8-003240| The Kubernetes kubelet config must be owned by root.|
|CNTR-K8-003250| The Kubernetes API Server must have file permissions set to 644 or more restrictive.|
|CNTR-K8-003260| The Kubernetes etcd must have file permissions set to 644 or more restrictive.|
|CNTR-K8-003270| The Kubernetes admin.conf must have file permissions set to 644 or more restrictive.|
|CNTR-K8-003280| Kubernetes API Server audit logs must be enabled.|
|CNTR-K8-003290| The Kubernetes API Server must be set to audit log max size.|
|CNTR-K8-003300| The Kubernetes API Server must be set to audit log maximum backup.|
|CNTR-K8-003310| The Kubernetes API Server audit log retention must be set.|
|CNTR-K8-003320| The Kubernetes API Server audit log path must be set.|
|CNTR-K8-003330| The Kubernetes PKI CRT must have file permissions set to 644 or more restrictive.|
|CNTR-K8-003340| The Kubernetes PKI keys must have file permissions set to 600 or more restrictive.|
|CNTR-K8-003350| The Kubernetes API Server must prohibit communication using TLS version 1.0 and 1.1, and SSL 2.0 and 3.0.|

## Authors

Defense Information Systems Agency (DISA) https://www.disa.mil/

STIG support by DISA Risk Management Team and Cyber Exchange https://public.cyber.mil/

## Legal Notices

Copyright © 2020 Defense Information Systems Agency (DISA)
