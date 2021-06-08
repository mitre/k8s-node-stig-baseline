## Kubernetes Node STIG Automated Compliance Validation Profile

<b>Kubernetes Node</b> STIG Automated Compliance Validation Profile that works with Chef InSpec to perform automated compliance checks of <b>Kubernetes Nodes</b>. It is to be used in conjunction with the <b>[Kubernetes Cluster](https://gitlab.dsolab.io/scv-content/inspec/kubernetes/k8s-cluster-stig-baseline)</b> profile that performs automated compliance checks of the <b>Kubernetes Cluster</b>.

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

**Execute the Kubernetes Node profile on each node in the cluster. The profile will adapt its checks based on the Kubernetes components located on the node.**

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

**Kubernetes Components**

This profile evaluates the STIG compliance of the following Kubernetes Components by evaluating their process configuration:

- kube-apiserver
- kube-controller-manager
- kube-scheduler
- kubelet
- kube-proxy
- etcd

If these components are not in use in the target cluster or named differently, the profile has to be adapted for the target K8S distribution using an [InSpec Profile Overlay](https://blog.chef.io/understanding-inspec-profile-inheritance)

**Normal Checks**

These checks will follow the normal automation process and will report accurate STIG compliance PASS/FAIL.

| Check Number | Description                                                                                                                                                                                                               |
|--------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|V-242376| The Kubernetes Controller Manager must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination.|
|V-242377| The Kubernetes Scheduler must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination.|
|V-242378| The Kubernetes API Server must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination.|
|V-242379| The Kubernetes etcd must use TLS to protect the confidentiality of sensitive data during electronic dissemination.|
|V-242380| The Kubernetes etcd must use TLS to protect the confidentiality of sensitive data during electronic dissemination.|
|V-242381| The Kubernetes Controller Manager must create unique service accounts for each work payload.|
|V-242382| The Kubernetes API Server must enable Node,RBAC as the authorization mode.|
|V-242384| The Kubernetes Scheduler must have secure binding.|
|V-242385| The Kubernetes Controller Manager must have secure binding.|
|V-242386| The Kubernetes API server must have the insecure port flag disabled.|
|V-242387| The Kubernetes Kubelet must have the read-only port flag disabled.|
|V-242388| The Kubernetes API server must have the insecure bind address not set.|
|V-242389| The Kubernetes API server must have the secure port set.|
|V-242390| The Kubernetes API server must have anonymous authentication disabled.|
|V-242391| The Kubernetes Kubelet must have anonymous authentication disabled.|
|V-242392| The Kubernetes kubelet must enable explicit authorization.|
|V-242393| Kubernetes Worker Nodes must not have sshd service running.|
|V-242394| Kubernetes Worker Nodes must not have the sshd service enabled.|
|V-242396| Kubernetes Kubectl cp command must give expected access and results.|
|V-242397| The Kubernetes kubelet static PodPath must not enable static pods.|
|V-242398| Kubernetes DynamicAuditing must not be enabled.|
|V-242399| Kubernetes DynamicKubeletConfig must not be enabled.|
|V-242400| The Kubernetes API server must have Alpha APIs disabled.|
|V-242401| The Kubernetes API Server must have an audit policy set.|
|V-242402| The Kubernetes API Server must have an audit log path set.|
|V-242403| Kubernetes API Server must generate audit records that identify what type of event has occurred, identify the source of the event, contain the event results, identify any users, and identify any containers associated iththe event.|"
|V-242404| Kubernetes Kubelet must deny hostname override.|
|V-242405| The Kubernetes manifests must be owned by root.|
|V-242406| The Kubernetes kubelet configuration file must be owned by root.|
|V-242407| The Kubernetes kubelet configuration file permissions set to 644 or  more restrictive.|
|V-242408| The Kubernetes manifests must have least privileges.|
|V-242409| Kubernetes Controller Manager must disable profiling.|
|V-242416| Kubernetes Kubelet must not disable timeouts.|
|V-242418| The Kubernetes API server must use approved cipher suites.|
|V-242419| Kubernetes API Server must have the SSL Certificate Authority set.|
|V-242420| Kubernetes Kubelet must have the SSL Certificate Authority set.|
|V-242421| Kubernetes Controller Manager must have the SSL Certificate Authority set.|
|V-242422| Kubernetes API Server must have a certificate for communication.|
|V-242423| Kubernetes etcd must enable client authentication to secure service.|
|V-242424| Kubernetes Kubelet must enable tls-private-key-file for client authentication to secure service.|
|V-242425| Kubernetes Kubelet must enable tls-cert-file for client authentication to secure service.|
|V-242426| Kubernetes etcd must enable client authentication to secure service.|
|V-242427| Kubernetes etcd must have a key file for secure communication.|
|V-242428| Kubernetes etcd must have a certificate for communication.|
|V-242429| Kubernetes etcd must have the SSL Certificate Authority set.|
|V-242430| Kubernetes etcd must have a certificate for communication.|
|V-242431| Kubernetes etcd must have a key file for secure communication.|
|V-242432| Kubernetes etcd must have peer-cert-file set for secure communication.|
|V-242433| Kubernetes etcd must have a peer-key-file set for secure communication.|
|V-242434| Kubernetes Kubelet must enable kernel protection.|
|V-242435| Kubernetes must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures or the installation of patches andpdates.|
|V-242436| The Kubernetes API server must have the ValidatingAdmissionWebhook enabled.|
|V-242438| Kubernetes API Server must configure timeouts to limit attack surface.|
|V-242439| Kubernetes API Server must disable basic authentication to protect information in transit.|
|V-242440| Kubernetes API Server must disable token authentication to protect information in transit.|
|V-242441| Kubernetes endpoints must use approved organizational certificate and key pair to protect information in transit.|
|V-242444| The Kubernetes component manifests must be owned by root.|
|V-242445| The Kubernetes component etcd must be owned by etcd.|
|V-242446| The Kubernetes conf files must be owned by root.|
|V-242447| The Kubernetes Kube Proxy must have file permissions set to 644 or more restrictive.|
|V-242448| The Kubernetes Kube Proxy must be owned by root.|
|V-242449| The Kubernetes Kubelet certificate authority file must have file permissions set to 644 or more restrictive.|
|V-242450| The Kubernetes Kubelet certificate authority must be owned by root.|
|V-242451| The Kubernetes component PKI must be owned by root.|
|V-242452| The Kubernetes kubelet config must have file permissions set to 644 or more restrictive.|
|V-242453| The Kubernetes kubelet config must be owned by root.|
|V-242454| The Kubernetes kubeadm must be owned by root.|
|V-242455| The Kubernetes  kubeadm.conf must have file permissions set to 644 or more restrictive.|
|V-242456| The Kubernetes kubelet config must have file permissions set to 644 or more restrictive.|
|V-242457| The Kubernetes kubelet config must be owned by root.|
|V-242458| The Kubernetes API Server must have file permissions set to 644 or more restrictive.|
|V-242459| The Kubernetes etcd must have file permissions set to 644 or more restrictive.|
|V-242460| The Kubernetes admin.conf must have file permissions set to 644 or more restrictive.|
|V-242461| Kubernetes API Server audit logs must be enabled.|
|V-242462| The Kubernetes API Server must be set to audit log max size.|
|V-242463| The Kubernetes API Server must be set to audit log maximum backup.|
|V-242464| The Kubernetes API Server audit log retention must be set.|
|V-242465| The Kubernetes API Server audit log path must be set.|
|V-242466| The Kubernetes PKI CRT must have file permissions set to 644 or more restrictive.|
|V-242467| The Kubernetes PKI keys must have file permissions set to 600 or more restrictive.|
|V-242468| The Kubernetes API Server must prohibit communication using TLS version 1.0 and 1.1, and SSL 2.0 and 3.0.|

## Authors

Defense Information Systems Agency (DISA) https://www.disa.mil/

STIG support by DISA Risk Management Team and Cyber Exchange https://public.cyber.mil/

## Legal Notices

Copyright © 2020 Defense Information Systems Agency (DISA)
