# K8S Resources to validate K8S Node checks

Local inspec resources for K8S Inspec profile.

- kubernetes (https://github.com/dev-sec/cis-kubernetes-benchmark)
- kube_apiserver
- kube_controller_manager
- kube_scheduler
- kubelet
- kubelet_config_file
- process_env_var (https://github.com/dev-sec/cis-kubernetes-benchmark)


## Inspecting Kubernetes API Server

Kubernetes API Server options are placed by flags on the `kube-apiserver` process.

Resouces used: 
- kube_apiserver: checks `kube_apiserver` process flags.


Inspec tests:
```
    describe kube_apiserver do
      its('allow-privileged') { should_not cmp 'true' }
    end
```

Results:
```
  Process arguments for kube-apiserver
     ×  allow-privileged is expected not to cmp == "true"

     expected: true
          got: ["true"]

     (compared using `cmp` matcher)

```

## Inspecting Kubernetes Scheduler

Kubernetes Scheduler options are validated by flags on the `kube-scheduler` process.

Resouces used: 
- kube_scheduler: checks `kube_scheduler` process flags.

Inspec tests:
```
    describe kube_scheduler do
      its('bind-address') { should_not cmp '127.0.0.1' }
    end
    
```
Results:
```
  Process arguments for kube-scheduler
     ✔  bind-address is expected not to cmp == "127.0.0.1"
```

## Inspecting Kubernetes Controller Manager

Kubernetes Controller Manager options are validated by flags on the `kube-controller-manager` process.

Resouces used: 
- kube_controller_manager: checks `kube_controller_manager` process flags.

Inspec tests:
```
    describe kube_controller_manager do
      its('root-ca-file') { should_not be_nil }
    end
```
Results:
```
  Process arguments for kube-controller-manager
     ✔  root-ca-file is expected not to be nil

```
## Inspecting Kubelet

Kubelet options are validated by flags on the `kubelet` process or kubelet config file.

Resouces used: 
- kubelet: checks `kubelet` process flags.
- kubelet_config_file: checks kubelet config file yaml/json.
- 
Inspec tests:
```
describe.one do
  describe kubelet do
    its('anonymous-auth') { should cmp 'false' }
  end
  
  describe kubelet_config_file do
    its(['authentication','anonymous','enabled']) { should cmp false }
  end
end

```
Results:
```
  Kubelet Config File /etc/kubernetes/kubelet-config.yaml
     ✔  ["authentication", "anonymous", "enabled"] is expected to cmp == false
```
## Inspecting etcd

etcd options are validated by flags on the `etcd` process or etcd process enviroment vars.

Resouces used: 
- etcd: checks `etcd` process flags.
- process_env_var: checks process enviroment vars.

Inspec tests:
```
describe.one do
  describe etcd do
    its('cert-file') { should_not be_nil }
  end

  describe process_env_var('etcd') do
    its(:ETCD_CERT_FILE) { should_not be_nil }
  end
end

```
Results:
```
  Environment variables for Processes etcd
     ✔  ETCD_CERT_FILE is expected not to be nil
```








