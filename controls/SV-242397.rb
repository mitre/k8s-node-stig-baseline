control 'SV-242397' do
  title 'The Kubernetes kubelet static PodPath must not enable static pods.'
  desc 'Allowing kubelet to set a staticPodPath gives containers with root access permissions to traverse the hosting filesystem. The danger comes when the container can create a manifest file within the /etc/kubernetes/manifests directory. When a manifest is created within this directory, containers are entirely governed by the Kubelet not the API Server. The container is not susceptible to admission control at all. Any containers or pods instantiated in this manner are called "static pods" and are meant to be used for pods such as the API server, scheduler, controller, etc., not workload pods that need to be governed by the API Server.'
  desc 'check', 'If staticPodPath is missing in the Kubelet config and in the systemd arguments, the node does not support static pods.

1. To find the staticPodPath setting on Kubernetes worker nodes, follow these steps:

 a. On the Worker nodes, run the command:
     ps -ef | grep kubelet

b. Note the path to the Kubelet configuration file (identified by --config).
    (ls /var/lib/kubelet/config.yaml is the common location.)

c. Run the command:
    grep -i staticPodPath <path_to_config_file>

If any of the Worker nodes return a value for "staticPodPath", this is a finding.

If staticPodPath is not in the config file, check if it is set as a command-line argument.

2. Check Kubelet Systemd Service Arguments.

a. Run the following command to check the Kubelet service:
    sudo systemctl cat kubelet | grep pod-manifest-path

If there is no output, staticPodPath is not set in systemd arguments.

If there is any return, this is a finding.

(Example Return:ExecStart=/usr/bin/kubelet --pod-manifest-path=/etc/kubernetes/manifests
This means static pods are defined in /etc/kubernetes/manifests.)'
  desc 'fix', '1. Remove staticPodPath setting on Kubernetes worker nodes:

a. On each Worker node, run the command:
    ps -ef | grep kubelet

b. Note the path to the config file (identified by --config).

c. Edit the Kubernetes kubelet file in the --config directory on the Worker nodes. Remove the setting "staticPodPath".

d. Restart the kubelet service using the following command:
    systemctl daemon-reload && systemctl restart kubelet

2. Remove Kubelet Systemd Service Arguments:

a. Modify the systemd Service File. Run the command:
    sudo systemctl edit --full kubelet

(Example Return:ExecStart=/usr/bin/kubelet --pod-manifest-path=/etc/kubernetes/manifests)

b. Find and remove --pod-manifest-path.

c. Save and exit the editor.

d. Restart the kubelet service using the following command:
    systemctl daemon-reload && systemctl restart kubelet'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000033-CTR-000090'
  tag gid: 'V-242397'
  tag rid: 'SV-242397r1137638_rule'
  tag stig_id: 'CNTR-K8-000440'
  tag fix_id: 'F-45630r1069463_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  describe kubelet do
    its('pod-manifest-path') { should be_nil }
  end

  describe kubelet_config_file do
    its('staticPodPath') { should be_nil }
  end
end
