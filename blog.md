Since my last [blog post](http://www.greenhills.co.uk/2015/05/22/projectcalico-experiments.html) and [Project Calico](http://www.projectcalico.org/),
Docker gained a new plugin architecture for networking in 1.7/1.8, and [Calico-docker 0.5.2](https://github.com/Metaswitch/calico-docker/releases/tag/v0.5.2) was released to use that.
In this blog post I explore how that changes things compared to last time.
I used [this Vagrant example](https://github.com/Metaswitch/calico-ubuntu-vagrant) as a guide, but install to bare metal, similar to my previous post. I made some optimisations:

- I automated my cluster OS re-installation, so I can easily
start with a completely clean slate, without tedious keyboard entry. See
[ubuntu-custom-iso repo](https://github.com/makuk66/ubuntu-custom-iso). Now
I can just insert the USB stick, reboot, hit F11, select the USB stick to boot from,
and hit return to start the automatic installation. Which is a big help, but if I'm going
to test this regularly I'll swtich to some resettable VMs.

- I use [Fabric](http://www.fabfile.org) to automate the
docker/calico installation. This way I can run commands directly from my laptop,
and introduce some scripting to determine dynamic values.

So let's get started.
You can follow along in [the fabfile](https://github.com/makuk66/docker-calico-fabric/blob/master/fabfile.py) if you want to see code.
In the output below "crab" is my laptop hostname, and trinity10/trinity20/trinity30 are cluster nodes.
If you see "..." I've discarded output noise.

Checking out the repo:

```
PS1='crab$ '

crab$ git clone git@github.com:makuk66/docker-calico-fabric.git
Cloning into 'docker-calico-fabric'...
remote: Counting objects: 5, done.
remote: Total 5 (delta 0), reused 0 (delta 0), pack-reused 5
Receiving objects: 100% (5/5), 4.61 KiB | 0 bytes/s, done.
Checking connectivity... done.

crab$ cd docker-calico-fabric
crab$ git rev-parse HEAD
a3f24478250df20f6474b13eca3a82da2ea0c712

crab$ cat README.md 
# docker-calico-fabric
Deploy Docker with Calico to my test cluster

virtualenv venv
source venv/bin/activate
pip install -r requirements.txt 

Based on https://github.com/Metaswitch/calico-ubuntu-vagrant

```

Setting up python:

```
crab$ virtualenv venv
New python executable in venv/bin/python2.7
Also creating executable in venv/bin/python
Installing setuptools, pip...done.

crab$ source venv/bin/activate

crab 499 docker-calico-fabric [master] $ PS1='crab$ '

crab$ pip install -r requirements.txt
...
Successfully installed ecdsa-0.13 fabric-1.10.2 jinja2-2.7.3 markupsafe-0.23 paramiko-1.15.2 pycrypto-2.6.1
```

Checking fabric on my laptop can talk to the cluster:

```
crab$ fab info
[trinity10] Executing task 'info'
[trinity10] run: cat /etc/lsb-release
[trinity10] out: DISTRIB_ID=Ubuntu
[trinity10] out: DISTRIB_RELEASE=14.04
[trinity10] out: DISTRIB_CODENAME=trusty
[trinity10] out: DISTRIB_DESCRIPTION="Ubuntu 14.04.2 LTS"
[trinity10] out: 

[trinity20] Executing task 'info'
[trinity20] run: cat /etc/lsb-release
[trinity20] out: DISTRIB_ID=Ubuntu
[trinity20] out: DISTRIB_RELEASE=14.04
[trinity20] out: DISTRIB_CODENAME=trusty
[trinity20] out: DISTRIB_DESCRIPTION="Ubuntu 14.04.2 LTS"
[trinity20] out: 

[trinity30] Executing task 'info'
[trinity30] run: cat /etc/lsb-release
[trinity30] out: DISTRIB_ID=Ubuntu
[trinity30] out: DISTRIB_RELEASE=14.04
[trinity30] out: DISTRIB_CODENAME=trusty
[trinity30] out: DISTRIB_DESCRIPTION="Ubuntu 14.04.2 LTS"
[trinity30] out: 


Done.
Disconnecting from trinity30... done.
Disconnecting from trinity10... done.
Disconnecting from trinity20... done.
```

Prepping ssh and sudo:

```
crab$ fab copy_ssh_key setup_sudoers
[trinity10] Executing task 'copy_ssh_key'
[trinity10] put: /Users/mak/.ssh/id_dsa.pub -> tmpkey.pem
[trinity10] sudo: mkdir -p ~mak/.ssh
[trinity10] out: sudo password: 

[trinity10] out: 
[trinity10] sudo: cat ~mak/tmpkey.pem >> ~mak/.ssh/authorized_keys
[trinity10] out: sudo password:
[trinity10] out: 
[trinity10] sudo: chown mak:mak ~mak/.ssh
[trinity10] out: sudo password:
[trinity10] out: 
[trinity10] sudo: chown mak:mak ~mak/.ssh/authorized_keys
[trinity10] out: sudo password:
[trinity10] out: 
[trinity10] sudo: rm ~mak/tmpkey.pem
[trinity10] out: sudo password:
[trinity10] out: 
[trinity20] Executing task 'copy_ssh_key'
[trinity20] put: /Users/mak/.ssh/id_dsa.pub -> tmpkey.pem
[trinity20] sudo: mkdir -p ~mak/.ssh
[trinity20] out: sudo password:
[trinity20] out: 
[trinity20] sudo: cat ~mak/tmpkey.pem >> ~mak/.ssh/authorized_keys
[trinity20] out: sudo password:
[trinity20] out: 
[trinity20] sudo: chown mak:mak ~mak/.ssh
[trinity20] out: sudo password:
[trinity20] out: 
[trinity20] sudo: chown mak:mak ~mak/.ssh/authorized_keys
[trinity20] out: sudo password:
[trinity20] out: 
[trinity20] sudo: rm ~mak/tmpkey.pem
[trinity20] out: sudo password:
[trinity20] out: 
[trinity30] Executing task 'copy_ssh_key'
[trinity30] put: /Users/mak/.ssh/id_dsa.pub -> tmpkey.pem
[trinity30] sudo: mkdir -p ~mak/.ssh
[trinity30] out: sudo password:
[trinity30] out: 
[trinity30] sudo: cat ~mak/tmpkey.pem >> ~mak/.ssh/authorized_keys
[trinity30] out: sudo password:
[trinity30] out: 
[trinity30] sudo: chown mak:mak ~mak/.ssh
[trinity30] out: sudo password:
[trinity30] out: 
[trinity30] sudo: chown mak:mak ~mak/.ssh/authorized_keys
[trinity30] out: sudo password:
[trinity30] out: 
[trinity30] sudo: rm ~mak/tmpkey.pem
[trinity30] out: sudo password:
[trinity30] out: 
[trinity10] Executing task 'setup_sudoers'
[trinity10] sudo: echo 'mak  ALL=(ALL) NOPASSWD:ALL' >> "$(echo /etc/sudoers)"
[trinity10] out: sudo password:
[trinity10] out: 
[trinity20] Executing task 'setup_sudoers'
[trinity20] sudo: echo 'mak  ALL=(ALL) NOPASSWD:ALL' >> "$(echo /etc/sudoers)"
[trinity20] out: sudo password:
[trinity20] out: 
[trinity30] Executing task 'setup_sudoers'
[trinity30] sudo: echo 'mak  ALL=(ALL) NOPASSWD:ALL' >> "$(echo /etc/sudoers)"
[trinity30] out: sudo password:
[trinity30] out: 
```

Configure the OS kernel modules for IPv6 and IP sets, switch on forwarding,
and add some utility packages we'll need.
I only show the output for trinity10; the same happens on trinity20/trinity30:

```
crab$ fab install_prerequisites
[trinity10] Executing task 'install_prerequisites'
[trinity10] sudo: modprobe ip6_tables
[trinity10] sudo: echo 'ip6_tables' >> "$(echo /etc/modules)"
[trinity10] sudo: modprobe xt_set
[trinity10] sudo: echo 'xt_set' >> "$(echo /etc/modules)"
[trinity10] sudo: sysctl -w net.ipv6.conf.all.forwarding=1
[trinity10] out: net.ipv6.conf.all.forwarding = 1
[trinity10] out: 

[trinity10] sudo: echo net.ipv6.conf.all.forwarding=1 > /etc/sysctl.d/60-ipv6-forwarding.conf
[trinity10] sudo: apt-get install -y unzip curl
...
```

Now we're getting to the fun bit.
I install the experimental docker, as recommeded by Docker Inc., to make sure it does the appropriate package things.
Then I replace the docker command with the one Calico's example uses, for compatibility.
Once 1.8 is released I expect that won't be needed.

```
crab$ fab install_experimental_docker
[trinity10] Executing task 'install_experimental_docker'
[trinity10] run: docker version | grep '^Server version: ' | sed 's/^.* //'
[trinity10] out: /bin/bash: docker: command not found
[trinity10] out: 

[trinity10] sudo: wget -qO- https://experimental.docker.com/ | sh
[trinity10] out: apparmor is enabled in the kernel and apparmor utils were already installed
[trinity10] out: + [ https://get.docker.com/ = https://experimental.docker.com/ ]
[trinity10] out: + [ https://test.docker.com/ = https://experimental.docker.com/ ]
[trinity10] out: + [ https://experimental.docker.com/ = https://experimental.docker.com/ ]
[trinity10] out: + sh -c apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys E33FF7BF5C91D50A6F91FFFD4CC38D40F9A96B49
[trinity10] out: Executing: gpg --ignore-time-conflict --no-options --no-default-keyring --homedir /tmp/tmp.cEOdTlpu1W --no-auto-check-trustdb --trust-model always --keyring /etc/apt/trusted.gpg --primary-keyring /etc/apt/trusted.gpg --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys E33FF7BF5C91D50A6F91FFFD4CC38D40F9A96B49
[trinity10] out: gpg: requesting key F9A96B49 from hkp server p80.pool.sks-keyservers.net
[trinity10] out: gpg: key F9A96B49: public key "Docker Release Tool (releasedocker) <docker@docker.com>" imported
[trinity10] out: gpg: Total number processed: 1
[trinity10] out: gpg:               imported: 1  (RSA: 1)
[trinity10] out: + sh -c mkdir -p /etc/apt/sources.list.d
[trinity10] out: + sh -c echo deb https://experimental.docker.com/ubuntu docker main > /etc/apt/sources.list.d/docker.list
[trinity10] out: + sh -c sleep 3; apt-get update; apt-get install -y -q lxc-docker
...
[trinity10] out: The following NEW packages will be installed
[trinity10] out:   aufs-tools cgroup-lite lxc-docker lxc-docker-1.8.0-dev
...
[trinity10] out: + sh -c docker version
[trinity10] out: Client:
[trinity10] out:  Version:      1.8.0-dev
[trinity10] out:  API version:  1.20
[trinity10] out:  Go version:   go1.4.2
[trinity10] out:  Git commit:   8c7cd78
[trinity10] out:  Built:        Tue Jul 14 23:47:18 UTC 2015
[trinity10] out:  OS/Arch:      linux/amd64
[trinity10] out:  Experimental: true
[trinity10] out: 
[trinity10] out: Server:
[trinity10] out:  Version:      1.8.0-dev
[trinity10] out:  API version:  1.20
[trinity10] out:  Go version:   go1.4.2
[trinity10] out:  Git commit:   8c7cd78
[trinity10] out:  Built:        Tue Jul 14 23:47:18 UTC 2015
[trinity10] out:  OS/Arch:      linux/amd64
[trinity10] out:  Experimental: true
...
[trinity10] sudo: usermod -aG docker mak
Disconnecting from trinity10... done.
[trinity10] run: rm -f docker
[trinity10] run: wget https://github.com/Metaswitch/calico-docker/releases/download/v0.5.2/docker > /dev/null 2>&1
[trinity10] run: chmod a+x docker
[trinity10] sudo: stop docker || echo oh well
[trinity10] out: docker stop/waiting
[trinity10] out: 

[trinity10] run: which docker||true
[trinity10] out: /usr/bin/docker
[trinity10] out: 

[trinity10] sudo: mv docker /usr/bin/docker
[trinity10] sudo: start docker
[trinity10] out: docker start/running, process 2681
[trinity10] out: 

[trinity10] run: docker version
[trinity10] out: Client:
[trinity10] out:  Version:      1.8.0-dev
[trinity10] out:  API version:  1.20
[trinity10] out:  Go version:   go1.4.2
[trinity10] out:  Git commit:   3ee15ac
[trinity10] out:  Built:        Tue Jul 21 18:03:50 UTC 2015
[trinity10] out:  OS/Arch:      linux/amd64
[trinity10] out:  Experimental: true
[trinity10] out: 
[trinity10] out: Server:
[trinity10] out:  Version:      1.8.0-dev
[trinity10] out:  API version:  1.20
[trinity10] out:  Go version:   go1.4.2
[trinity10] out:  Git commit:   3ee15ac
[trinity10] out:  Built:        Tue Jul 21 18:03:50 UTC 2015
[trinity10] out:  OS/Arch:      linux/amd64
[trinity10] out:  Experimental: true
```

Again, the same happens on the other nodes, which you can verify with `fab docker_version`.

Next, we pull the docker images we'll use later into all nodes.
This takes a while.
You should really use a local registry for the nodes to share, but that's for another day.

```
crab$ date; fab pull_docker_images; date
Wed 22 Jul 2015 21:39:08 BST
[trinity10] Executing task 'pull_docker_images'
[trinity10] run: docker pull makuk66/docker-solr:5.2-no-expose
...
[trinity10] run: docker pull jplock/zookeeper
...
[trinity10] run: docker pull busybox:latest
...
[trinity10] run: docker pull ubuntu:latest
...
[trinity10] run: docker pull quay.io/coreos/etcd:v2.0.11
...
[trinity10] run: docker pull calico/node:v0.5.2
...
Wed 22 Jul 2015 21:58:16 BST
```

Next, get Calico. This installs as `calicoctl` in the home directory.
Probably not the best place, but it will do for the purpose here.

```
crab$ fab install_calico
[trinity10] Executing task 'install_calico'
[trinity10] run: wget -nv https://github.com/Metaswitch/calico-docker/releases/download/v0.5.2/calicoctl
[trinity10] out: 2015-07-22 22:09:31 URL:https://s3.amazonaws.com/github-cloud/releases/29629333/c15d78d0-2fc7-11e5-8737-7260d623d9bb?response-content-disposition=attachment%3B%20filename%3Dcalicoctl&response-content-type=application/octet-stream&AWSAccessKeyId=AKIAISTNZFOVBIJMK3TQ&Expires=1437599427&Signature=QpxeAbHPI1bkY5zwsAE6VbKteN0%3D [6157075/6157075] -> "calicoctl" [1]
[trinity10] out: 

[trinity10] run: chmod +x calicoctl
[trinity10] sudo: docker pull calico/node:v0.5.2
...
[trinity10] sudo: docker pull quay.io/coreos/etcd:v2.0.11
...
```

Next, setup Consul and Etcd. It's kinda odd we need two distributed discovery databases; hopefully that will get simplified.
On #calico smc_calico says "we'd like to add support for consul; libnetwork uses libkv so, eventually, they'll have support for etcd too (but libkv's etcd support is patchy right now)").

The fabric code is written to only install the Consul server to one host (trinity10), and configures the docker daemons on all machines to point to it.

```
crab$ fab install_consul
[trinity10] Executing task 'install_consul'
[trinity10] run: rm -f consul.zip consul
[trinity10] run: curl -L --silent https://dl.bintray.com/mitchellh/consul/0.5.2_linux_amd64.zip -o consul.zip
[trinity10] run: unzip consul.zip
[trinity10] out: Archive:  consul.zip
[trinity10] out:   inflating: consul                  
[trinity10] out: 

[trinity10] run: chmod +x consul
[trinity10] sudo: mv consul /usr/bin/consul
[trinity10] run: rm -f consul.zip
[trinity10] run: ip -4 addr show dev eth0 | grep inet | awk '{print $2}' | sed -e 's,/.*,,'
[trinity10] out: 192.168.77.10
[trinity10] out: 

[trinity10] put: <file obj> -> /etc/init/consul.conf
[trinity10] sudo: service consul start
[trinity10] out: consul start/running, process 3160
[trinity10] out: 

[trinity10] sudo: echo 'DOCKER_OPTS="--kv-store=consul:192.168.77.10:8500"' >> "$(echo /etc/default/docker)"
[trinity10] sudo: service docker restart
[trinity10] out: docker stop/waiting
[trinity10] out: docker start/running, process 3216
[trinity10] out: 

[trinity20] Executing task 'install_consul'
[trinity20] sudo: echo 'DOCKER_OPTS="--kv-store=consul:192.168.77.10:8500"' >> "$(echo /etc/default/docker)"
[trinity20] sudo: service docker restart
[trinity20] out: docker stop/waiting
[trinity20] out: docker start/running, process 3139
[trinity20] out: 

[trinity30] Executing task 'install_consul'
[trinity30] sudo: echo 'DOCKER_OPTS="--kv-store=consul:192.168.77.10:8500"' >> "$(echo /etc/default/docker)"
[trinity30] sudo: service docker restart
[trinity30] out: docker stop/waiting
[trinity30] out: docker start/running, process 3088
```

Next, etcd. It is configured to be a 3-node cluster on trinity10/trinity20/trinity30, using their fixed known IP addresses.
For large deployments you probably want to run this on separate small machines.

```
[trinity10] Executing task 'run_etcd'
[trinity10] run: ip -4 addr show dev eth0 | grep inet | awk '{print $2}' | sed -e 's,/.*,,'
[trinity10] out: 192.168.77.10
[trinity10] out: 

[trinity10] run: docker pull quay.io/coreos/etcd:v2.0.11
[trinity10] out: Pulling repository quay.io/coreos/etcd
[trinity10] out: c02fd8670851: Pulling image (v2.0.11) from quay.io/coreos/etcd
[trinity10] out: c02fd8670851: Pulling image (v2.0.11) from quay.io/coreos/etcd, endpoint: https://quay.io/v1/
[trinity10] out: c02fd8670851: Pulling dependent layers
[trinity10] out: 8093db4276d5: Download complete
[trinity10] out: f9c3a06edd7a: Download complete
[trinity10] out: 546a4b0d3153: Download complete
[trinity10] out: 9caa77989e25: Download complete
[trinity10] out: c02fd8670851: Download complete
[trinity10] out: c02fd8670851: Download complete
[trinity10] out: Status: Image is up to date for quay.io/coreos/etcd:v2.0.11
[trinity10] out: 

[trinity10] run: docker run -d -p 4001:4001 -p 7001:7001 --name quay.io-coreos-etcd quay.io/coreos/etcd --name etcd-trinity10 --advertise-client-urls http://192.168.77.10:4001 --listen-client-urls http://0.0.0.0:4001 --initial-advertise-peer-urls http://192.168.77.10:7001 --listen-peer-urls http://0.0.0.0:7001 --initial-cluster-token etcd-cluster-2123 --initial-cluster etcd-trinity10=http://192.168.77.10:7001,etcd-trinity20=http://192.168.77.20:7001,etcd-trinity30=http://192.168.77.30:7001 --initial-cluster-state new
...
```

We can check the cluster is happy:

```
crab$ fab check_etcd
[trinity10] Executing task 'check_etcd'
[trinity10] run: curl -L http://localhost:4001/version
[trinity10] out: {"etcdserver":"2.1.1","etcdcluster":"2.1.0"}
[trinity10] run: curl -L http://localhost:4001/v2/machines
[trinity10] out: http://192.168.77.10:4001, http://192.168.77.20:4001, http://192.168.77.30:4001
[trinity20] Executing task 'check_etcd'
[trinity20] run: curl -L http://localhost:4001/version
[trinity20] out: {"etcdserver":"2.1.1","etcdcluster":"2.1.0"}
[trinity20] run: curl -L http://localhost:4001/v2/machines
[trinity20] out: http://192.168.77.10:4001, http://192.168.77.20:4001, http://192.168.77.30:4001
[trinity30] Executing task 'check_etcd'
[trinity30] run: curl -L http://localhost:4001/version
[trinity30] out: {"etcdserver":"2.1.1","etcdcluster":"2.1.0"}
[trinity30] run: curl -L http://localhost:4001/v2/machines
[trinity30] out: http://192.168.77.10:4001, http://192.168.77.20:4001, http://192.168.77.30:4001
```

Now all the bits are in place, and we can start the Calico containers.
We pass the specific IP address for it to use; in a future version that should not be required.

```
crab$ fab start_calico_containers
[trinity10] Executing task 'start_calico_containers'
[trinity10] run: docker ps --filter=name=calico-node | tail -n +2
[trinity10] run: ip -4 addr show dev eth0 | grep inet | awk '{print $2}' | sed -e 's,/.*,,'
[trinity10] out: 192.168.77.10
[trinity10] out: 

creating and starting calico-node
[trinity10] sudo: ./calicoctl node --ip=192.168.77.10
[trinity10] out: Calico node is running with id: bfb0b9a60cebf0f8d3b5e5c705210bade4c6e52077b942043fc4d584afc49661
[trinity10] out: 

[trinity20] Executing task 'start_calico_containers'
[trinity20] run: docker ps --filter=name=calico-node | tail -n +2
[trinity20] run: ip -4 addr show dev eth0 | grep inet | awk '{print $2}' | sed -e 's,/.*,,'
[trinity20] out: 192.168.77.20
[trinity20] out: 

creating and starting calico-node
[trinity20] sudo: ./calicoctl node --ip=192.168.77.20
[trinity20] out: Calico node is running with id: 853229b4f85f417c8eb79064546da9c6d1fb31ea831c125801a5b73e8dc52394
[trinity20] out: 

[trinity30] Executing task 'start_calico_containers'
[trinity30] run: docker ps --filter=name=calico-node | tail -n +2
[trinity30] run: ip -4 addr show dev eth0 | grep inet | awk '{print $2}' | sed -e 's,/.*,,'
[trinity30] out: 192.168.77.30
[trinity30] out: 

creating and starting calico-node
[trinity30] sudo: ./calicoctl node --ip=192.168.77.30
[trinity30] out: Calico node is running with id: 5aca9e4f8058ad71e00eecaa1baa771c9771a576c01f84df1a6809a50acc196a
[trinity30] out: 
```

Next we'll create two test networks, 'netalphabeta' and 'netsolr':

```
crab$ fab create_networks
[trinity10] Executing task 'create_networks'
[trinity10] run: docker network create --driver=calico netalphabeta
[trinity10] out: f25828680cf78bdcb7c8c1b95889ff3794b7ff61b492b0d315bda8abdd29c43a
[trinity10] out: 

[trinity10] run: docker network create --driver=calico netsolr
[trinity10] out: fab2fd58e4414f4c5cd745999aa0a81f62250fd6086a37ecca37584804f5dbb5
[trinity10] out: 

[trinity10] run: docker network ls
[trinity10] out: NETWORK ID          NAME                TYPE
[trinity10] out: f6b228d08f27        none                null                
[trinity10] out: c3b70951f594        host                host                
[trinity10] out: c2ebde929f99        bridge              bridge              
[trinity10] out: f25828680cf7        netalphabeta        calico              
[trinity10] out: fab2fd58e441        netsolr             calico              
```

and configure Calico's profiles (think AWS security groups or router iptables) for them.
This syntax is new too; nice.

The fabric code figures out the profile name for the specific network.
There might be a better way to do this.

Note that I add tcp port 8983 to netsolr.

```
crab$ fab configure_network_profiles
[trinity10] Executing task 'configure_network_profiles'
[trinity10] run: docker network ls
[trinity10] out: NETWORK ID          NAME                TYPE
[trinity10] out: c3b70951f594        host                host                
[trinity10] out: c2ebde929f99        bridge              bridge              
[trinity10] out: f25828680cf7        netalphabeta        calico              
[trinity10] out: fab2fd58e441        netsolr             calico              
[trinity10] out: f6b228d08f27        none                null                
[trinity10] out: 

[trinity10] run: ./calicoctl profile show
[trinity10] out: +------------------------------------------------------------------+
[trinity10] out: |                               Name                               |
[trinity10] out: +------------------------------------------------------------------+
[trinity10] out: | f25828680cf78bdcb7c8c1b95889ff3794b7ff61b492b0d315bda8abdd29c43a |
[trinity10] out: | fab2fd58e4414f4c5cd745999aa0a81f62250fd6086a37ecca37584804f5dbb5 |
[trinity10] out: +------------------------------------------------------------------+
[trinity10] out: 

[trinity10] run: ./calicoctl profile f25828680cf78bdcb7c8c1b95889ff3794b7ff61b492b0d315bda8abdd29c43a rule add inbound allow icmp
[trinity10] run: docker network ls
[trinity10] out: NETWORK ID          NAME                TYPE
[trinity10] out: c2ebde929f99        bridge              bridge              
[trinity10] out: f25828680cf7        netalphabeta        calico              
[trinity10] out: fab2fd58e441        netsolr             calico              
[trinity10] out: f6b228d08f27        none                null                
[trinity10] out: c3b70951f594        host                host                
[trinity10] out: 

[trinity10] run: ./calicoctl profile show
[trinity10] out: +------------------------------------------------------------------+
[trinity10] out: |                               Name                               |
[trinity10] out: +------------------------------------------------------------------+
[trinity10] out: | f25828680cf78bdcb7c8c1b95889ff3794b7ff61b492b0d315bda8abdd29c43a |
[trinity10] out: | fab2fd58e4414f4c5cd745999aa0a81f62250fd6086a37ecca37584804f5dbb5 |
[trinity10] out: +------------------------------------------------------------------+
[trinity10] out: 

[trinity10] run: ./calicoctl profile fab2fd58e4414f4c5cd745999aa0a81f62250fd6086a37ecca37584804f5dbb5 rule add inbound allow icmp
[trinity10] run: ./calicoctl profile fab2fd58e4414f4c5cd745999aa0a81f62250fd6086a37ecca37584804f5dbb5 rule add inbound allow tcp to ports 8983
```

Next we need to create an address pool for Calico to assign to the containers.

```
crab$ fab calicoctl_pool
[trinity10] Executing task 'calicoctl_pool'
[trinity10] run: ./calicoctl pool show
[trinity10] out: +----------------+---------+
[trinity10] out: |   IPv4 CIDR    | Options |
[trinity10] out: +----------------+---------+
[trinity10] out: | 192.168.0.0/16 |         |
[trinity10] out: +----------------+---------+
[trinity10] out: +--------------------------+---------+
[trinity10] out: |        IPv6 CIDR         | Options |
[trinity10] out: +--------------------------+---------+
[trinity10] out: | fd80:24e2:f998:72d6::/64 |         |
[trinity10] out: +--------------------------+---------+
[trinity10] out: 

[trinity10] run: ./calicoctl pool add 192.168.89.0/24
[trinity10] run: ./calicoctl pool remove 192.168.0.0/16
[trinity10] run: ./calicoctl pool add 192.168.89.0/24
[trinity10] run: ./calicoctl pool show
[trinity10] out: +-----------------+---------+
[trinity10] out: |    IPv4 CIDR    | Options |
[trinity10] out: +-----------------+---------+
[trinity10] out: | 192.168.89.0/24 |         |
[trinity10] out: +-----------------+---------+
[trinity10] out: +--------------------------+---------+
[trinity10] out: |        IPv6 CIDR         | Options |
[trinity10] out: +--------------------------+---------+
[trinity10] out: | fd80:24e2:f998:72d6::/64 |         |
[trinity10] out: +--------------------------+---------+
```

At last, we're ready to try some containers.

First container "alpha", on trinity10, and inspect its network configuration from docker,
and from within the container.
Note the network name in the `publish-service` argument in the `docker run`.
And note the `cali0` device that has the IP address for this container, and has the default route.

```
crab$ fab create_test_container_alpha
[trinity10] Executing task 'create_test_container_alpha'
[trinity10] run: docker pull busybox:latest
[trinity10] out: latest: Pulling from library/busybox
[trinity10] out: cf2616975b4a: Already exists
[trinity10] out: 6ce2e90b0bc7: Already exists
[trinity10] out: 8c2e06607696: Already exists
[trinity10] out: 8c2e06607696: Already exists
[trinity10] out: Digest: sha256:38a203e1986cf79639cfb9b2e1d6e773de84002feea2d4eb006b52004ee8502d
[trinity10] out: Status: Image is up to date for busybox:latest
[trinity10] out: 

[trinity10] run: docker run --publish-service srvalpha.netalphabeta.calico --name c-alpha -tid busybox:latest
[trinity10] out: e1629ce1ba916dfd65249ae60f20945cc1328b6f410d52b24dfbe6c141d12a5d
[trinity10] out: 

[trinity10] run: docker inspect --format '{{.Id}}' e1629ce1ba916dfd65249ae60f20945cc1328b6f410d52b24dfbe6c141d12a5d
[trinity10] out: e1629ce1ba916dfd65249ae60f20945cc1328b6f410d52b24dfbe6c141d12a5d
[trinity10] out: 

[trinity10] run: docker inspect --format '{{.Name}}' e1629ce1ba916dfd65249ae60f20945cc1328b6f410d52b24dfbe6c141d12a5d
[trinity10] out: /c-alpha
[trinity10] out: 

[trinity10] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' e1629ce1ba916dfd65249ae60f20945cc1328b6f410d52b24dfbe6c141d12a5d
[trinity10] out: 192.168.89.1
[trinity10] out: 

container_id=e1629ce1ba916dfd65249ae60f20945cc1328b6f410d52b24dfbe6c141d12a5d, container_name=c-alpha, ip_address=192.168.89.1
[trinity10] run: docker exec -i e1629ce1ba916dfd65249ae60f20945cc1328b6f410d52b24dfbe6c141d12a5d hostname
[trinity10] out: e1629ce1ba91
[trinity10] out: 

[trinity10] run: docker exec -i e1629ce1ba916dfd65249ae60f20945cc1328b6f410d52b24dfbe6c141d12a5d ls -l /sys/devices/virtual/net/
[trinity10] out: total 0
[trinity10] out: drwxr-xr-x    5 root     root             0 Jul 22 21:16 cali0
[trinity10] out: drwxr-xr-x    5 root     root             0 Jul 22 21:16 lo
[trinity10] out: drwxr-xr-x    5 root     root             0 Jul 22 21:16 tunl0
[trinity10] out: 

[trinity10] run: docker exec -i e1629ce1ba916dfd65249ae60f20945cc1328b6f410d52b24dfbe6c141d12a5d ip link list
[trinity10] out: 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default 
[trinity10] out:     link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
[trinity10] out: 2: tunl0@NONE: <NOARP> mtu 1480 qdisc noop state DOWN mode DEFAULT group default 
[trinity10] out:     link/ipip 0.0.0.0 brd 0.0.0.0
[trinity10] out: 10: cali0: <NO-CARRIER,BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state DOWN mode DEFAULT group default qlen 1000
[trinity10] out:     link/ether ee:ee:ee:ee:ee:ee brd ff:ff:ff:ff:ff:ff
[trinity10] out: 

[trinity10] run: docker exec -i e1629ce1ba916dfd65249ae60f20945cc1328b6f410d52b24dfbe6c141d12a5d ip addr list
[trinity10] out: 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
[trinity10] out:     link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
[trinity10] out:     inet 127.0.0.1/8 scope host lo
[trinity10] out:        valid_lft forever preferred_lft forever
[trinity10] out: 


Warning: run() received nonzero return code 139 while executing 'docker exec -i e1629ce1ba916dfd65249ae60f20945cc1328b6f410d52b24dfbe6c141d12a5d ip addr list'!

[trinity10] run: docker exec -i e1629ce1ba916dfd65249ae60f20945cc1328b6f410d52b24dfbe6c141d12a5d ip route list
[trinity10] out: default via 192.168.77.10 dev cali0 
[trinity10] out: 192.168.77.10 dev cali0  scope link 
```

Notice how that `ip addr list` there crashed busybox.
I've seen a [bug report at calico](https://github.com/Metaswitch/calico-docker/issues/4) about that, which was closed as an upstream bug.
I [filed one there](https://bugs.busybox.net/show_bug.cgi?id=8231).

So now container "alpha" is using address 192.168.89.1, and running on trinity10.

Next, container "beta", on trinity20, in the same way:

```
crab$ fab create_test_container_beta
[trinity20] Executing task 'create_test_container_beta'
[trinity20] run: docker pull busybox:latest
[trinity20] out: latest: Pulling from library/busybox
[trinity20] out: cf2616975b4a: Already exists
[trinity20] out: 6ce2e90b0bc7: Already exists
[trinity20] out: 8c2e06607696: Already exists
[trinity20] out: 8c2e06607696: Already exists
[trinity20] out: Digest: sha256:38a203e1986cf79639cfb9b2e1d6e773de84002feea2d4eb006b52004ee8502d
[trinity20] out: Status: Image is up to date for busybox:latest
[trinity20] out: 

[trinity20] run: docker run --publish-service srvbeta.netalphabeta.calico --name c-beta -tid busybox:latest
[trinity20] out: a77b8e11851549c639418d5b9f09ba3a6d99c3894a343113d5c2a5e92325b6da
[trinity20] out: 

[trinity20] run: docker inspect --format '{{.Id}}' a77b8e11851549c639418d5b9f09ba3a6d99c3894a343113d5c2a5e92325b6da
[trinity20] out: a77b8e11851549c639418d5b9f09ba3a6d99c3894a343113d5c2a5e92325b6da
[trinity20] out: 

[trinity20] run: docker inspect --format '{{.Name}}' a77b8e11851549c639418d5b9f09ba3a6d99c3894a343113d5c2a5e92325b6da
[trinity20] out: /c-beta
[trinity20] out: 

[trinity20] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' a77b8e11851549c639418d5b9f09ba3a6d99c3894a343113d5c2a5e92325b6da
[trinity20] out: 192.168.89.2
[trinity20] out: 

container_id=a77b8e11851549c639418d5b9f09ba3a6d99c3894a343113d5c2a5e92325b6da, container_name=c-beta, ip_address=192.168.89.2
[trinity20] run: docker exec -i a77b8e11851549c639418d5b9f09ba3a6d99c3894a343113d5c2a5e92325b6da hostname
[trinity20] out: a77b8e118515
[trinity20] out: 

[trinity20] run: docker exec -i a77b8e11851549c639418d5b9f09ba3a6d99c3894a343113d5c2a5e92325b6da ls -l /sys/devices/virtual/net/
[trinity20] out: total 0
[trinity20] out: drwxr-xr-x    5 root     root             0 Jul 22 21:17 cali0
[trinity20] out: drwxr-xr-x    5 root     root             0 Jul 22 21:17 lo
[trinity20] out: drwxr-xr-x    5 root     root             0 Jul 22 21:17 tunl0
[trinity20] out: 

[trinity20] run: docker exec -i a77b8e11851549c639418d5b9f09ba3a6d99c3894a343113d5c2a5e92325b6da ip link list
[trinity20] out: 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default 
[trinity20] out:     link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
[trinity20] out: 2: tunl0@NONE: <NOARP> mtu 1480 qdisc noop state DOWN mode DEFAULT group default 
[trinity20] out:     link/ipip 0.0.0.0 brd 0.0.0.0
[trinity20] out: 10: cali0: <NO-CARRIER,BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state DOWN mode DEFAULT group default qlen 1000
[trinity20] out:     link/ether ee:ee:ee:ee:ee:ee brd ff:ff:ff:ff:ff:ff
[trinity20] out: 

[trinity20] run: docker exec -i a77b8e11851549c639418d5b9f09ba3a6d99c3894a343113d5c2a5e92325b6da ip addr list
[trinity20] out: 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
[trinity20] out:     link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
[trinity20] out:     inet 127.0.0.1/8 scope host lo
[trinity20] out:        valid_lft forever preferred_lft forever
[trinity20] out: 


Warning: run() received nonzero return code 139 while executing 'docker exec -i a77b8e11851549c639418d5b9f09ba3a6d99c3894a343113d5c2a5e92325b6da ip addr list'!

[trinity20] run: docker exec -i a77b8e11851549c639418d5b9f09ba3a6d99c3894a343113d5c2a5e92325b6da ip route list
[trinity20] out: default via 192.168.77.20 dev cali0 
[trinity20] out: 192.168.77.20 dev cali0  scope link 
```

So container "beta" is using address 192.168.89.2 and running on trinity20.

The big question is -- can they talk to eachother?

```
crab$ fab ping_test_containers
[trinity10] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' c-alpha
[trinity10] out: 192.168.89.1
[trinity10] out: 

[trinity20] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' c-beta
[trinity20] out: 192.168.89.2
[trinity20] out: 

[trinity10] run: docker exec -i c-alpha ping -c 1 192.168.89.2
[trinity10] out: PING 192.168.89.2 (192.168.89.2): 56 data bytes
[trinity10] out: 64 bytes from 192.168.89.2: seq=0 ttl=62 time=0.425 ms
[trinity10] out: 
[trinity10] out: --- 192.168.89.2 ping statistics ---
[trinity10] out: 1 packets transmitted, 1 packets received, 0% packet loss
[trinity10] out: round-trip min/avg/max = 0.425/0.425/0.425 ms
[trinity10] out: 

[trinity20] run: docker exec -i c-beta ping -c 1 192.168.89.1
[trinity20] out: PING 192.168.89.1 (192.168.89.1): 56 data bytes
[trinity20] out: 64 bytes from 192.168.89.1: seq=0 ttl=62 time=0.415 ms
[trinity20] out: 
[trinity20] out: --- 192.168.89.1 ping statistics ---
[trinity20] out: 1 packets transmitted, 1 packets received, 0% packet loss
[trinity20] out: round-trip min/avg/max = 0.415/0.415/0.415 ms
```

They sure can. Sweet!



BGP
---

So, next, BGP routing so I can talk to them from my machine.
The command has changed slightly:

```
crab$ fab add_bgp_peer
[trinity10] Executing task 'add_bgp_peer'
[trinity10] run: ./calicoctl bgp peer add 192.168.77.1 as 64511
```

On the Mikrotik side I used the same config as before,
I see routes for the containers, and I can ping from my laptop:

```
crab$ ping -c 1 192.168.89.1
PING 192.168.89.1 (192.168.89.1): 56 data bytes
64 bytes from 192.168.89.1: icmp_seq=0 ttl=61 time=1.175 ms

--- 192.168.89.1 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 1.175/1.175/1.175/0.000 ms
crab$ ping -c 1 192.168.89.2
PING 192.168.89.2 (192.168.89.2): 56 data bytes
64 bytes from 192.168.89.2: icmp_seq=0 ttl=61 time=0.841 ms

--- 192.168.89.2 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 0.841/0.841/0.841/0.000 ms
```


Solr
----

Pinging is all very well, but let's try a real application: Solr.

I have a [makuk66/docker-solr](https://github.com/makuk66/docker-solr) image on the
Docker registry (60 stars, whoo!). But I can't use that as-is because it has an
EXPOSE that causes a problem in libnetwork. See [calico-docker issue 341](https://github.com/Metaswitch/calico-docker/issues/341)
and [libnetwork issue 401](https://github.com/docker/libnetwork/issues/401).
So as a temporary hack I've created another image without that EXPOSE: `makuk66/docker-solr:5.2-no-expose`.


First zookeeper. I'll just put it on single container:

```
(venv)crab:docker-calico-fabric mak$ fab create_test_zookeeper
crab$ fab create_test_zookeeper
[trinity10] Executing task 'create_test_zookeeper'
[trinity10] run: docker pull jplock/zookeeper
[trinity10] out: Pulling repository docker.io/jplock/zookeeper
...
[trinity10] run: docker run --publish-service zookeeper.netsolr.calico --name zookeeper3 -tid jplock/zookeeper
[trinity10] out: 239b5a133a4a9be7eb4314d8357bbacf0feb897703bde3eecb8c42c3c38796cd
[trinity10] out: 

[trinity10] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' 239b5a133a4a9be7eb4314d8357bbacf0feb897703bde3eecb8c42c3c38796cd
[trinity10] out: 192.168.89.3
```

Next, a Solr container on a different machine, configured to talk to ZooKeeper:

```
[trinity10] Executing task 'create_test_solr1'
[trinity10] run: docker pull makuk66/docker-solr:5.2-no-expose
[trinity10] out: 5.2-no-expose: Pulling from makuk66/docker-solr
...
[trinity10] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' zookeeper3
[trinity10] out: 192.168.89.3
[trinity10] out: 

[trinity10] run: docker run --publish-service solr1.netsolr.calico --name solr1 -tid makuk66/docker-solr:5.2-no-expose bash -c '/opt/solr/bin/solr start -f -z 192.168.89.3:2181'
[trinity10] out: 17a8320108cfb79d34c91e6806b824aba19f03dde50acc1f2f5c8c0cd18bcee6
[trinity10] out: 

[trinity10] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' 17a8320108cfb79d34c91e6806b824aba19f03dde50acc1f2f5c8c0cd18bcee6
[trinity10] out: 192.168.89.4
[trinity10] out: 

[trinity10] run: docker logs 17a8320108cfb79d34c91e6806b824aba19f03dde50acc1f2f5c8c0cd18bcee6
[trinity10] out: 
[trinity10] out: 
[trinity10] out: Starting Solr in SolrCloud mode on port 8983 from /opt/solr/server
[trinity10] out: 
[trinity10] out: 
[trinity10] out: 
[trinity10] out: 0    [main] INFO  org.eclipse.jetty.util.log  [   ] – Logging initialized @515ms
[trinity10] out: 
[trinity10] out: 326  [main] INFO  org.eclipse.jetty.server.Server  [   ] – jetty-9.2.10.v20150310
[trinity10] out: 
[trinity10] out: 361  [main] WARN  org.eclipse.jetty.server.handler.RequestLogHandler  [   ] – !RequestLog
[trinity10] out: 
[trinity10] out: 366  [main] INFO  org.eclipse.jetty.deploy.providers.ScanningAppProvider  [   ] – Deployment monitor [file:/opt/solr-5.2.1/server/contexts/] at interval 0
[trinity10] out: 
[trinity10] out: 3254 [main] INFO  org.eclipse.jetty.webapp.StandardDescriptorProcessor  [   ] – NO JSP Support for /solr, did not find org.apache.jasper.servlet.JspServlet
[trinity10] out: 
[trinity10] out: 3294 [main] WARN  org.eclipse.jetty.security.SecurityHandler  [   ] – ServletContext@o.e.j.w.WebAppContext@18be83e4{/solr,file:/opt/solr-5.2.1/server/solr-webapp/webapp/,STARTING}{/solr.war} has uncovered http methods for path: /
[trinity10] out: 
[trinity10] out: 3337 [main] INFO  org.apache.solr.servlet.SolrDispatchFilter  [   ] – SolrDispatchFilter.init()WebAppClassLoader=2009787198@77caeb3e
[trinity10] out: 
[trinity10] out: 3362 [main] INFO  org.apache.solr.core.SolrResourceLoader  [   ] – JNDI not configured for solr (NoInitialContextEx)
[trinity10] out: 
[trinity10] out: 3362 [main] INFO  org.apache.solr.core.SolrResourceLoader  [   ] – using system property solr.solr.home: /opt/solr/server/solr
[trinity10] out: 
[trinity10] out: 3364 [main] INFO  org.apache.solr.core.SolrResourceLoader  [   ] – new SolrResourceLoader for directory: '/opt/solr/server/solr/'
[trinity10] out: 
[trinity10] out: 3601 [main] INFO  org.apache.solr.core.SolrXmlConfig  [   ] – Loading container configuration from /opt/solr/server/solr/solr.xml
[trinity10] out: 
[trinity10] out: 3720 [main] INFO  org.apache.solr.core.CoresLocator  [   ] – Config-defined core root directory: /opt/solr/server/solr
[trinity10] out: 
[trinity10] out: 3764 [main] INFO  org.apache.solr.core.CoreContainer  [   ] – New CoreContainer 60292059
[trinity10] out: 
[trinity10] out: 3765 [main] INFO  org.apache.solr.core.CoreContainer  [   ] – Loading cores into CoreContainer [instanceDir=/opt/solr/server/solr/]
[trinity10] out: 
[trinity10] out: 3766 [main] INFO  org.apache.solr.core.CoreContainer  [   ] – loading shared library: /opt/solr/server/solr/lib
[trinity10] out: 
[trinity10] out: 3766 [main] WARN  org.apache.solr.core.SolrResourceLoader  [   ] – Can't find (or read) directory to add to classloader: lib (resolved as: /opt/solr/server/solr/lib).
[trinity10] out: 
[trinity10] out: 3804 [main] INFO  org.apache.solr.handler.component.HttpShardHandlerFactory  [   ] – created with socketTimeout : 600000,connTimeout : 60000,maxConnectionsPerHost : 20,maxConnections : 10000,corePoolSize : 0,maximumPoolSize : 2147483647,maxThreadIdleTime : 5,sizeOfQueue : -1,fairnessPolicy : false,useRetries : false,
[trinity10] out: 
[trinity10] out: 4062 [main] INFO  org.apache.solr.update.UpdateShardHandler  [   ] – Creating UpdateShardHandler HTTP client with params: socketTimeout=600000&connTimeout=60000&retry=true
[trinity10] out: 
[trinity10] out: 4066 [main] INFO  org.apache.solr.logging.LogWatcher  [   ] – SLF4J impl is org.slf4j.impl.Log4jLoggerFactory
[trinity10] out: 
[trinity10] out: 4068 [main] INFO  org.apache.solr.logging.LogWatcher  [   ] – Registering Log Listener [Log4j (org.slf4j.impl.Log4jLoggerFactory)]
[trinity10] out: 
[trinity10] out: 4071 [main] INFO  org.apache.solr.core.CoreContainer  [   ] – Node Name: 
[trinity10] out: 
[trinity10] out: 4071 [main] INFO  org.apache.solr.core.ZkContainer  [   ] – Zookeeper client=192.168.89.3:2181
[trinity10] out: 
[trinity10] out: 4144 [main] INFO  org.apache.solr.common.cloud.ConnectionManager  [   ] – Waiting for client to connect to ZooKeeper
[trinity10] out: 
[trinity10] out: 4327 [zkCallback-2-thread-1-processing-{node_name=192.168.89.4:8983_solr}] INFO  org.apache.solr.common.cloud.ConnectionManager  [   ] – Watcher org.apache.solr.common.cloud.ConnectionManager@796e389e name:ZooKeeperConnection Watcher:192.168.89.3:2181 got event WatchedEvent state:SyncConnected type:None path:null path:null type:None
[trinity10] out: 
[trinity10] out: 4328 [main] INFO  org.apache.solr.common.cloud.ConnectionManager  [   ] – Client is connected to ZooKeeper
[trinity10] out: 
[trinity10] out: 4376 [main] INFO  org.apache.solr.common.cloud.SolrZkClient  [   ] – makePath: /overseer/queue
[trinity10] out: 
[trinity10] out: 4404 [main] INFO  org.apache.solr.common.cloud.SolrZkClient  [   ] – makePath: /overseer/collection-queue-work
[trinity10] out: 
[trinity10] out: 4426 [main] INFO  org.apache.solr.common.cloud.SolrZkClient  [   ] – makePath: /overseer/collection-map-running
[trinity10] out: 
[trinity10] out: 4444 [main] INFO  org.apache.solr.common.cloud.SolrZkClient  [   ] – makePath: /overseer/collection-map-completed
[trinity10] out: 
[trinity10] out: 4464 [main] INFO  org.apache.solr.common.cloud.SolrZkClient  [   ] – makePath: /overseer/collection-map-failure
[trinity10] out: 
[trinity10] out: 4493 [main] INFO  org.apache.solr.common.cloud.SolrZkClient  [   ] – makePath: /live_nodes
[trinity10] out: 
[trinity10] out: 4502 [main] INFO  org.apache.solr.common.cloud.SolrZkClient  [   ] – makePath: /collections
[trinity10] out: 
[trinity10] out: 4512 [main] INFO  org.apache.solr.common.cloud.SolrZkClient  [   ] – makePath: /aliases.json
[trinity10] out: 
[trinity10] out: 4524 [main] INFO  org.apache.solr.common.cloud.SolrZkClient  [   ] – makePath: /clusterstate.json
[trinity10] out: 
[trinity10] out: 4534 [main] INFO  org.apache.solr.cloud.ZkController  [   ] – Register node as live in ZooKeeper:/live_nodes/192.168.89.4:8983_solr
[trinity10] out: 
[trinity10] out: 4543 [main] INFO  org.apache.solr.common.cloud.SolrZkClient  [   ] – makePath: /live_nodes/192.168.89.4:8983_solr
[trinity10] out: 
[trinity10] out: 4555 [main] INFO  org.apache.solr.common.cloud.SolrZkClient  [   ] – makePath: /overseer_elect
[trinity10] out: 
[trinity10] out: 4568 [main] INFO  org.apache.solr.common.cloud.SolrZkClient  [   ] – makePath: /overseer_elect/election
[trinity10] out: 
[trinity10] out: 4579 [main] INFO  org.apache.solr.cloud.Overseer  [   ] – Overseer (id=null) closing
[trinity10] out: 
[trinity10] out: 4611 [main] INFO  org.apache.solr.cloud.ElectionContext  [   ] – I am going to be the leader 192.168.89.4:8983_solr
[trinity10] out: 
[trinity10] out: 4617 [main] INFO  org.apache.solr.common.cloud.SolrZkClient  [   ] – makePath: /overseer_elect/leader
[trinity10] out: 
[trinity10] out: 4628 [main] INFO  org.apache.solr.cloud.Overseer  [   ] – Overseer (id=94214553063587840-192.168.89.4:8983_solr-n_0000000000) starting
[trinity10] out: 
[trinity10] out: 4652 [main] INFO  org.apache.solr.common.cloud.SolrZkClient  [   ] – makePath: /overseer/queue-work
[trinity10] out: 
[trinity10] out: 4738 [main] INFO  org.apache.solr.cloud.OverseerAutoReplicaFailoverThread  [   ] – Starting OverseerAutoReplicaFailoverThread autoReplicaFailoverWorkLoopDelay=10000 autoReplicaFailoverWaitAfterExpiration=30000 autoReplicaFailoverBadNodeExpiration=60000
[trinity10] out: 
[trinity10] out: 4785 [main] INFO  org.apache.solr.common.cloud.ZkStateReader  [   ] – Updating cluster state from ZooKeeper... 
[trinity10] out: 
[trinity10] out: 4785 [OverseerCollectionProcessor-94214553063587840-192.168.89.4:8983_solr-n_0000000000] INFO  org.apache.solr.cloud.OverseerCollectionProcessor  [   ] – Process current queue of collection creations
[trinity10] out: 
[trinity10] out: 4809 [OverseerStateUpdate-94214553063587840-192.168.89.4:8983_solr-n_0000000000] INFO  org.apache.solr.cloud.Overseer  [   ] – Starting to work on the main queue
[trinity10] out: 
[trinity10] out: 4815 [main] INFO  org.apache.solr.core.CoreContainer  [   ] – No authentication plugin used.
[trinity10] out: 
[trinity10] out: 4817 [main] INFO  org.apache.solr.core.CoreContainer  [   ] – Security conf doesn't exist. Skipping setup for authorization module.
[trinity10] out: 
[trinity10] out: 4858 [main] INFO  org.apache.solr.core.CoresLocator  [   ] – Looking for core definitions underneath /opt/solr/server/solr
[trinity10] out: 
[trinity10] out: 4875 [main] INFO  org.apache.solr.core.CoresLocator  [   ] – Found 0 core definitions
[trinity10] out: 
[trinity10] out: 4879 [main] INFO  org.apache.solr.servlet.SolrDispatchFilter  [   ] – user.dir=/opt/solr-5.2.1/server
[trinity10] out: 
[trinity10] out: 4880 [main] INFO  org.apache.solr.servlet.SolrDispatchFilter  [   ] – SolrDispatchFilter.init() done
[trinity10] out: 
[trinity10] out: 4901 [main] INFO  org.eclipse.jetty.server.handler.ContextHandler  [   ] – Started o.e.j.w.WebAppContext@18be83e4{/solr,file:/opt/solr-5.2.1/server/solr-webapp/webapp/,AVAILABLE}{/solr.war}
[trinity10] out: 
[trinity10] out: 4914 [main] INFO  org.eclipse.jetty.server.ServerConnector  [   ] – Started ServerConnector@353352b6{HTTP/1.1}{0.0.0.0:8983}
[trinity10] out: 
[trinity10] out: 4915 [main] INFO  org.eclipse.jetty.server.Server  [   ] – Started @5433ms
```

and a second Solr container on a different machine:

```
crab$ fab create_test_solr2
[trinity20] Executing task 'create_test_solr2'
[trinity20] run: docker pull makuk66/docker-solr:5.2-no-expose
[trinity20] out: 5.2-no-expose: Pulling from makuk66/docker-solr
[trinity20] out: 902b87aaaec9: Already exists
[trinity20] out: 9a61b6b1315e: Already exists
[trinity20] out: 1ff9f26f09fb: Already exists
[trinity20] out: 607e965985c1: Already exists
[trinity20] out: 682b997ad926: Already exists
[trinity20] out: a594f78c2a03: Already exists
[trinity20] out: 8859a87b6160: Already exists
[trinity20] out: 9dd7ba0ee3fe: Already exists
[trinity20] out: 93934c1ae19e: Already exists
[trinity20] out: 2262501f7b5a: Already exists
[trinity20] out: bfb63b0f4db1: Already exists
[trinity20] out: 49ebfec495e1: Already exists
[trinity20] out: 7ac88cfffb65: Already exists
[trinity20] out: 966a676b855d: Already exists
[trinity20] out: 9e7fc36f6081: Already exists
[trinity20] out: 63377b58a48e: Already exists
[trinity20] out: 6ddf7b813291: Already exists
[trinity20] out: 936d0b17f07c: Already exists
[trinity20] out: ba1c96a3a99c: Already exists
[trinity20] out: 353e503b33b2: Already exists
[trinity20] out: 353e503b33b2: Already exists
[trinity20] out: Digest: sha256:bf7f74ffa55ac474455ad8ffbb7f63bb2993fd7c42c214be7440e559ca986f91
[trinity20] out: Status: Image is up to date for makuk66/docker-solr:5.2-no-expose
[trinity20] out: 

[trinity10] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' zookeeper3
[trinity10] out: 192.168.89.3
[trinity10] out: 

[trinity20] run: docker run --publish-service solr2.netsolr.calico --name solr2 -tid makuk66/docker-solr:5.2-no-expose bash -c '/opt/solr/bin/solr start -f -z 192.168.89.3:2181'
[trinity20] out: 135b62c4c50d9a82b6aaaeeb5771e3666ea8882af27a231b3083c7e8d172c257
[trinity20] out: 

[trinity20] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' 135b62c4c50d9a82b6aaaeeb5771e3666ea8882af27a231b3083c7e8d172c257
[trinity20] out: 192.168.89.5
[trinity20] out: 
...
[trinity20] out: 5828 [main] INFO  org.eclipse.jetty.server.ServerConnector  [   ] – Started ServerConnector@63376bed{HTTP/1.1}{0.0.0.0:8983}
[trinity20] out: 
[trinity20] out: 5836 [main] INFO  org.eclipse.jetty.server.Server  [   ] – Started @6387ms
```

and let's see if a web client in a container can talk to them:

```
crab$ fab create_test_solrclient
[trinity30] Executing task 'create_test_solrclient'
[trinity10] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' solr1
[trinity10] out: 192.168.89.4
[trinity10] out: 

[trinity30] run: docker run --publish-service solrclient-HKB988.netsolr.calico --name solrclient-HKB988 -i makuk66/docker-solr:5.2-no-expose curl -sSL http://192.168.89.4:8983/
...   
[trinity30] out:   <title>Solr Admin</title>
...
[trinity20] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' solr2
[trinity20] out: 192.168.89.5
[trinity20] out: 

[trinity30] run: docker run --publish-service solrclient-HG93A3.netsolr.calico --name solrclient-HG93A3 -i makuk66/docker-solr:5.2-no-expose curl -sSL http://192.168.89.5:8983/
...
[trinity30] out:   <title>Solr Admin</title>
```

Yes, it can.

Let's create a collection:

```
crab$ fab solr_collection 
[trinity10] Executing task 'solr_collection'
[trinity10] run: docker exec -i -t solr1 /opt/solr/bin/solr create_collection -c books -shards 2 -p 8983
[trinity10] out: Connecting to ZooKeeper at 192.168.89.3:2181
[trinity10] out: 
[trinity10] out: Uploading /opt/solr/server/solr/configsets/data_driven_schema_configs/conf for config books to ZooKeeper at 192.168.89.3:2181
[trinity10] out: 
[trinity10] out: 
[trinity10] out: 
[trinity10] out: Creating new collection 'books' using command:
[trinity10] out: 
[trinity10] out: http://192.168.89.5:8983/solr/admin/collections?action=CREATE&name=books&numShards=2&replicationFactor=1&maxShardsPerNode=1&collection.configName=books
[trinity10] out: 
[trinity10] out: 
[trinity10] out: 
[trinity10] out: {
[trinity10] out: 
[trinity10] out:   "responseHeader":{
[trinity10] out: 
[trinity10] out:     "status":0,
[trinity10] out: 
[trinity10] out:     "QTime":2596},
[trinity10] out: 
[trinity10] out:   "success":{"":{
[trinity10] out: 
[trinity10] out:       "responseHeader":{
[trinity10] out: 
[trinity10] out:         "status":0,
[trinity10] out: 
[trinity10] out:         "QTime":2373},
[trinity10] out: 
[trinity10] out:       "core":"books_shard2_replica1"}}}
```

and load some data into it:

```
crab$ fab solr_data
[trinity10] Executing task 'solr_data'
[trinity10] run: docker exec -it --user=solr solr1 bin/post -c books /opt/solr/example/exampledocs/books.json
[trinity10] out: java -classpath /opt/solr-5.2.1/dist/solr-core-5.2.1.jar -Dauto=yes -Dc=books -Ddata=files org.apache.solr.util.SimplePostTool /opt/solr/example/exampledocs/books.json
[trinity10] out: 
[trinity10] out: SimplePostTool version 5.0.0
[trinity10] out: 
[trinity10] out: Posting files to [base] url http://localhost:8983/solr/books/update...
[trinity10] out: 
[trinity10] out: Entering auto mode. File endings considered are xml,json,csv,pdf,doc,docx,ppt,pptx,xls,xlsx,odt,odp,ods,ott,otp,ots,rtf,htm,html,txt,log
[trinity10] out: 
[trinity10] out: POSTing file books.json (application/json) to [base]
[trinity10] out: 
[trinity10] out: 1 files indexed.
[trinity10] out: 
[trinity10] out: COMMITting Solr index changes to http://localhost:8983/solr/books/update...
[trinity10] out: 
[trinity10] out: Time spent: 0:00:00.806
```

So I should be able to get to a Solr admin interface on http://192.168.89.5:8983 from my laptop... and indeed I can:

<img class="photo" src="/img/blog/books-query.png">
<img class="photo" src="/img/blog/books-select.png">
<img class="photo" src="/img/blog/books-shards.png">
<img class="photo" src="/img/blog/books-shard1.png">
<img class="photo" src="/img/blog/books-shard2.png">


Conclusion
----------

Calico and Docker's libnetwork work -- nice!

Kudos to the Calico folks: quite a lot seems to have changed in a short time, and I'm looking forward to further improvements.
The authors and community on `#calico` have been responsive and helpful -- thanks!

I still have many questions about ongoing management of such networks, and their interaction with orchestration tools.
But it's certainly exciting times...
