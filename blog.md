
Since my last [blog post](http://www.greenhills.co.uk/2015/05/22/projectcalico-experiments.html) and [Project Calico](http://www.projectcalico.org/),
Docker gained a new plugin architecture for networking in 1.7/1.8.
In this blog post I explore how that changes things.
I used [this Vagrant example](https://github.com/Metaswitch/calico-ubuntu-vagrant) as a guide, but install to bare metal, similar to my previous post. I made some optimisations:

- I automated my cluster OS re-installation, so I can easily
start with a completely clean slate, without tedious keyboard entry. See
[ubuntu-custom-iso repo](https://github.com/makuk66/ubuntu-custom-iso). Now
I can just insert the USB stick, reboot, hit F11, select the USB stick to boot from,
and hit return to start the automatic installation.

- I use [Fabric](http://www.fabfile.org) to automate the
docker/calico installation.

So let's get started.
You can follow along in [the fabfile](https://github.com/makuk66/docker-calico-fabric/blob/master/fabfile.py) if you want to see code.
In the output below "crab" is my laptop hostname, and trinity10/trinity20/trinity30 are cluster nodes.
If you see "..." I've discarded output noise.

Checking out the repo:

```
crab:makuk66 mak$ pwd
/Users/mak/github/makuk66

crab:makuk66 mak$ git clone git@github.com:makuk66/docker-calico-fabric.git
Cloning into 'docker-calico-fabric'...
remote: Counting objects: 5, done.
remote: Total 5 (delta 0), reused 0 (delta 0), pack-reused 5
Receiving objects: 100% (5/5), 4.61 KiB | 0 bytes/s, done.
Checking connectivity... done.

crab:makuk66 mak$ cd docker-calico-fabric
mak@crab 503 docker-calico-fabric [master] $ git log
commit 61ff0e442d57d9ba1d95b316209982a0062c0a96
Author: Martijn Koster <mak-github@greenhills.co.uk>
Date:   Thu Jun 25 14:15:25 2015 +0100

    Initial commit

crab:docker-calico-fabric mak$ cat README.md 
# docker-calico-fabric
Deploy Docker with Calico to my test cluster

virtualenv venv
source venv/bin/activate
pip install -r requirements.txt 

Based on https://github.com/Metaswitch/calico-ubuntu-vagrant

```

Setting up python:

```
crab:docker-calico-fabric mak$ virtualenv venv
New python executable in venv/bin/python2.7
Also creating executable in venv/bin/python
Installing setuptools, pip...done.
crab:docker-calico-fabric mak$ source venv/bin/activate
(venv)crab:docker-calico-fabric mak$ pip install -r requirements.txt
...
Successfully installed ecdsa-0.13 fabric-1.10.2 jinja2-2.7.3 markupsafe-0.23 paramiko-1.15.2 pycrypto-2.6.1
```

Checking fabric on my laptop can talk to the cluster:

```
(venv)crab:docker-calico-fabric mak$ fab info
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
(venv)crab:docker-calico-fabric mak$ fab copy_ssh_key setup_sudoers
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

Done.
Disconnecting from trinity30... done.
Disconnecting from trinity10... done.
Disconnecting from trinity20... done.
```

Installing OS pre-requisites. I only show the output for trinity10; the same happens on trinity20/trinity30:

```
(venv)crab:docker-calico-fabric mak$ fab install_prerequisites
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
In due course I expect I can just install the official docker version 1.8 or later.

```
(venv)crab:docker-calico-fabric mak$  fab install_experimental_docker
[trinity10] Executing task 'install_experimental_docker'
[trinity10] run: docker version | grep '^Server version: ' | sed 's/^.* //'
[trinity10] out: /bin/bash: docker: command not found
[trinity10] out: 

[trinity10] sudo: wget -qO- https://experimental.docker.com/ | sh
...
[trinity10] out: The following extra packages will be installed:
[trinity10] out:   aufs-tools cgroup-lite lxc-docker-1.8.0-
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
[trinity10] run: rm -f docker-1.8.0-dev.gz docker-1.8.0-dev.gz.[0-9]+
[trinity10] run: wget https://github.com/Metaswitch/calico-docker/releases/download/v0.5.0/docker-1.8.0-dev.gz > /dev/null 2>&1
[trinity10] run: gunzip -c docker-1.8.0-dev.gz > docker-1.8.0-dev
[trinity10] run: chmod a+x docker-1.8.0-dev
[trinity10] sudo: stop docker || echo oh well
[trinity10] out: docker stop/waiting
[trinity10] out: 

[trinity10] run: which docker||true
[trinity10] out: /usr/bin/docker
[trinity10] out: 

[trinity10] sudo: mv docker-1.8.0-dev /usr/bin/docker
[trinity10] sudo: start docker
[trinity10] out: docker start/running, process 2903
[trinity10] out: 

[trinity10] run: docker version
[trinity10] out: Client:
[trinity10] out:  Version:      1.8.0-dev
[trinity10] out:  API version:  1.20
[trinity10] out:  Go version:   go1.4.2
[trinity10] out:  Git commit:   22a5f5b
[trinity10] out:  Built:        Tue Jul  7 21:12:21 UTC 2015
[trinity10] out:  OS/Arch:      linux/amd64
[trinity10] out:  Experimental: true
[trinity10] out: 
[trinity10] out: Server:
[trinity10] out:  Version:      1.8.0-dev
[trinity10] out:  API version:  1.20
[trinity10] out:  Go version:   go1.4.2
[trinity10] out:  Git commit:   22a5f5b
[trinity10] out:  Built:        Tue Jul  7 21:12:21 UTC 2015
[trinity10] out:  OS/Arch:      linux/amd64
[trinity10] out:  Experimental: true
...
```

Again, the same happens on the other nodes, which you can verify with `fab docker_version`.

Next, we pull the docker images we'll use later into all nodes.
This takes a while.
You should really use a local registry for the nodes to share, but that's for another day.

```
(venv)crab:docker-calico-fabric mak$ fab pull_docker_images
[trinity10] Executing task 'pull_docker_images'
[trinity10] run: docker pull makuk66/docker-calico-devices:latest
...
[trinity10] run: docker pull jplock/zookeeper
...
[trinity10] run: docker pull busybox:latest
...
[trinity10] run: docker pull ubuntu:latest

```

By the way, that `makuk66/docker-calico-devices` image is a temporary hack;
it should be `makuk66/docker-solr` once I figure out a [problem with its EXPOSE](https://github.com/Metaswitch/calico-docker/issues/341).


Next, get Calico. This installs as `calicoctl` in the home directory.
Probably not the best place, but it will do for the purpose here.

```
[trinity10] Executing task 'install_calico'
[trinity10] run: wget -nv https://github.com/Metaswitch/calico-docker/releases/download/v0.5.0/calicoctl
[trinity10] out: 2015-07-20 13:10:49 URL:https://s3.amazonaws.com/github-cloud/releases/29629333/2f1d8098-2589-11e5-9fe5-c8c56982d6af?response-content-disposition=attachment%3B%20filename%3Dcalicoctl&response-content-type=application/octet-stream&AWSAccessKeyId=AKIAISTNZFOVBIJMK3TQ&Expires=1437394305&Signature=xCHjBT8UvLko6bY0EChqQZPuWug%3D [6151378/6151378] -> "calicoctl" [1]
[trinity10] out: 

[trinity10] run: chmod +x calicoctl
[trinity10] sudo: docker pull calico/node:libnetwork
...
[trinity10] sudo: docker pull quay.io/coreos/etcd:v2.0.11
```

Next, setup Consul and Etcd. It's kinda odd we need two distributed discovery databases; hopefully that will get simplified.
On #calico smc_calico says "we'd like to add support for consul; libnetwork uses libkv so, eventually, they'll have support for etcd too (but libkv's etcd support is patchy right now)").

The fabric code is written to only install the Consul server to one host (trinity10), and configures the docker daemons on all machines to point to it.

```
(venv)crab:docker-calico-fabric mak$ fab install_consul
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
[trinity10] out: consul start/running, process 3409
[trinity10] out: 

[trinity10] sudo: echo 'DOCKER_OPTS="--kv-store=consul:192.168.77.10:8500"' >> "$(echo /etc/default/docker)"
[trinity10] sudo: service docker restart
[trinity10] out: docker stop/waiting
[trinity10] out: docker start/running, process 3465
[trinity10] out: 

[trinity20] Executing task 'install_consul'
[trinity20] sudo: echo 'DOCKER_OPTS="--kv-store=consul:192.168.77.10:8500"' >> "$(echo /etc/default/docker)"
[trinity20] sudo: service docker restart
[trinity20] out: docker stop/waiting
[trinity20] out: docker start/running, process 3393
[trinity20] out: 

[trinity30] Executing task 'install_consul'
[trinity30] sudo: echo 'DOCKER_OPTS="--kv-store=consul:192.168.77.10:8500"' >> "$(echo /etc/default/docker)"
[trinity30] sudo: service docker restart
[trinity30] out: docker stop/waiting
[trinity30] out: docker start/running, process 3480
[trinity30] out: 
```

Next, etcd. It is configured to be a 3-node cluster on trinity10/trinity20/trinity30, using their fixed known IP addresses.
For large deployments you probably want to run this on separate small machines.

```
(venv)crab:docker-calico-fabric mak$  fab run_etcd
[trinity10] Executing task 'run_etcd'
[trinity10] run: ip -4 addr show dev eth0 | grep inet | awk '{print $2}' | sed -e 's,/.*,,'
[trinity10] out: 192.168.77.10
[trinity10] out: 

[trinity10] run: docker run -d -p 4001:4001 -p 7001:7001 --name quay.io-coreos-etcd quay.io/coreos/etcd --name etcd-trinity10 --advertise-client-urls http://192.168.77.10:4001 --listen-client-urls http://0.0.0.0:4001 --initial-advertise-peer-urls http://192.168.77.10:7001 --listen-peer-urls http://0.0.0.0:7001 --initial-cluster-token etcd-cluster-2123 --initial-cluster etcd-trinity10=http://192.168.77.10:7001,etcd-trinity20=http://192.168.77.20:7001,etcd-trinity30=http://192.168.77.30:7001 --initial-cluster-state new
[trinity10] out: Unable to find image 'quay.io/coreos/etcd:latest' locally
[trinity10] out: Pulling repository quay.io/coreos/etcd
...
```

We can check the cluster is happy:

```
(venv)crab:docker-calico-fabric mak$ fab check_etcd
[trinity10] Executing task 'check_etcd'
[trinity10] run: curl -L http://localhost:4001/version
[trinity10] out: etcd 2.0.13
[trinity10] run: curl -L http://localhost:4001/v2/machines
[trinity10] out: http://192.168.77.10:4001, http://192.168.77.20:4001, http://192.168.77.30:4001
[trinity20] Executing task 'check_etcd'
[trinity20] run: curl -L http://localhost:4001/version
[trinity20] out: etcd 2.0.13
[trinity20] run: curl -L http://localhost:4001/v2/machines
[trinity20] out: http://192.168.77.10:4001, http://192.168.77.20:4001, http://192.168.77.30:4001
[trinity30] Executing task 'check_etcd'
[trinity30] run: curl -L http://localhost:4001/version
[trinity30] out: etcd 2.0.13
[trinity30] run: curl -L http://localhost:4001/v2/machines
[trinity30] out: http://192.168.77.10:4001, http://192.168.77.20:4001, http://192.168.77.30:4001

Done.
```

Now all the bits are in place, and we can start the Calico containers:

```
(venv)crab:docker-calico-fabric mak$ fab start_calico_containers
[trinity10] Executing task 'start_calico_containers'
[trinity10] run: docker ps --filter=name=calico-node | tail -n +2
[trinity10] run: ip -4 addr show dev eth0 | grep inet | awk '{print $2}' | sed -e 's,/.*,,'
[trinity10] out: 192.168.77.10
[trinity10] out: 

creating and starting calico-node
[trinity10] sudo: ./calicoctl node --ip=192.168.77.10
[trinity10] out: Calico node is running with id: c82d2c984d20a1ce9da58233a62e15bfef8f2c7c3a5b1ad646ee715b0d8566e3
[trinity10] out: 

[trinity20] Executing task 'start_calico_containers'
[trinity20] run: docker ps --filter=name=calico-node | tail -n +2
[trinity20] run: ip -4 addr show dev eth0 | grep inet | awk '{print $2}' | sed -e 's,/.*,,'
[trinity20] out: 192.168.77.20
[trinity20] out: 

creating and starting calico-node
[trinity20] sudo: ./calicoctl node --ip=192.168.77.20
[trinity20] out: Calico node is running with id: f9c0c07379bf36639720276e36fa103e1549fe20f614b7ed43e84ed814715e2b
[trinity20] out: 

[trinity30] Executing task 'start_calico_containers'
[trinity30] run: docker ps --filter=name=calico-node | tail -n +2
[trinity30] run: ip -4 addr show dev eth0 | grep inet | awk '{print $2}' | sed -e 's,/.*,,'
[trinity30] out: 192.168.77.30
[trinity30] out: 

creating and starting calico-node
[trinity30] sudo: ./calicoctl node --ip=192.168.77.30
[trinity30] out: Calico node is running with id: 9a989bdf4d48a9eb8862f9bd290265714f99aade7286178430b0d992149c2fac
[trinity30] out: 


Done.
```

Next we'll create two test networks, 'anetab' and 'anetsolr':

```
(venv)crab:docker-calico-fabric mak$ fab create_networks
[trinity10] Executing task 'create_networks'
[trinity10] run: docker network create --driver=calico anetab
[trinity10] out: 239571e5772ef29890a1102894a02aad763b418c567ea61eb9abb8e0e3bae6a2
[trinity10] out: 

[trinity10] run: docker network create --driver=calico anetsolr
[trinity10] out: b454ec5c2f4c1a5cf8ffb9ca20392f6698a30a993a5b3be7109236a442b70901
[trinity10] out: 

[trinity10] run: docker network ls
[trinity10] out: NETWORK ID          NAME                TYPE
[trinity10] out: 074f25ce96c1        none                null                
[trinity10] out: 4d57c4c3ea4c        host                host                
[trinity10] out: 60aac8fc0aa3        bridge              bridge              
[trinity10] out: 239571e5772e        anetab              calico              
[trinity10] out: b454ec5c2f4c        anetsolr            calico              
[trinity10] out: 
```

and create an address pool.
I wish I could control that range better, and use e.g. 192.168.89.10-200. to leave some room for other hosts.
There is a [enhancement request](https://github.com/Metaswitch/calico-docker/issues/340) for that.


```
(venv)crab:docker-calico-fabric mak$ fab calicoctl_pool
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
[trinity10] run: ./calicoctl pool add 192.168.89.0/24 --nat-outgoing
[trinity10] run: ./calicoctl pool show
[trinity10] out: +-----------------+--------------+
[trinity10] out: |    IPv4 CIDR    |   Options    |
[trinity10] out: +-----------------+--------------+
[trinity10] out: | 192.168.89.0/24 | nat-outgoing |
[trinity10] out: +-----------------+--------------+
[trinity10] out: +--------------------------+---------+
[trinity10] out: |        IPv6 CIDR         | Options |
[trinity10] out: +--------------------------+---------+
[trinity10] out: | fd80:24e2:f998:72d6::/64 |         |
[trinity10] out: +--------------------------+---------+
[trinity10] out: 


Done.
Disconnecting from trinity10... done.
```

At last, we're ready to try some containers.

First container A, on trinity10:

```
(venv)crab:docker-calico-fabric mak$ fab create_test_containerA
[trinity10] Executing task 'create_test_containerA'
[trinity10] run: docker pull busybox:latest
[trinity10] out: latest: Pulling from busybox
[trinity10] out: cf2616975b4a: Already exists
[trinity10] out: 6ce2e90b0bc7: Already exists
[trinity10] out: 8c2e06607696: Already exists
[trinity10] out: 8c2e06607696: Already exists
[trinity10] out: Digest: sha256:38a203e1986cf79639cfb9b2e1d6e773de84002feea2d4eb006b52004ee8502d
[trinity10] out: Status: Image is up to date for busybox:latest
[trinity10] out: 

[trinity10] run: docker run --publish-service srvA.anetab.calico --name c-A -tid busybox:latest
[trinity10] out: 71b55622a021b7e939210934c6c952567e9f5aaa92dff7f34562098b94e0d4f7
[trinity10] out: 

[trinity10] run: docker inspect --format '{{.Id}}' 71b55622a021b7e939210934c6c952567e9f5aaa92dff7f34562098b94e0d4f7
[trinity10] out: 71b55622a021b7e939210934c6c952567e9f5aaa92dff7f34562098b94e0d4f7
[trinity10] out: 

[trinity10] run: docker inspect --format '{{.Name}}' 71b55622a021b7e939210934c6c952567e9f5aaa92dff7f34562098b94e0d4f7
[trinity10] out: /c-A
[trinity10] out: 

[trinity10] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' 71b55622a021b7e939210934c6c952567e9f5aaa92dff7f34562098b94e0d4f7
[trinity10] out: 192.168.89.1
[trinity10] out: 

container_id=71b55622a021b7e939210934c6c952567e9f5aaa92dff7f34562098b94e0d4f7, container_name=c-A, ip_address=192.168.89.1
[trinity10] run: docker exec -i 71b55622a021b7e939210934c6c952567e9f5aaa92dff7f34562098b94e0d4f7 hostname
[trinity10] out: 71b55622a021
[trinity10] out: 

[trinity10] run: docker exec -i 71b55622a021b7e939210934c6c952567e9f5aaa92dff7f34562098b94e0d4f7 ls -l /sys/devices/virtual/net/
[trinity10] out: total 0
[trinity10] out: drwxr-xr-x    5 root     root             0 Jul 21 12:58 cali0
[trinity10] out: drwxr-xr-x    5 root     root             0 Jul 21 12:58 lo
[trinity10] out: drwxr-xr-x    5 root     root             0 Jul 21 12:58 tunl0
[trinity10] out: 

[trinity10] run: docker exec -i 71b55622a021b7e939210934c6c952567e9f5aaa92dff7f34562098b94e0d4f7 ip link list
[trinity10] out: 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default 
[trinity10] out:     link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
[trinity10] out: 2: tunl0@NONE: <NOARP> mtu 1480 qdisc noop state DOWN mode DEFAULT group default 
[trinity10] out:     link/ipip 0.0.0.0 brd 0.0.0.0
[trinity10] out: 10: cali0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
[trinity10] out:     link/ether ee:ee:ee:ee:ee:ee brd ff:ff:ff:ff:ff:ff
[trinity10] out: 

[trinity10] run: docker exec -i 71b55622a021b7e939210934c6c952567e9f5aaa92dff7f34562098b94e0d4f7 ip addr list
[trinity10] out: 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
[trinity10] out:     link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
[trinity10] out:     inet 127.0.0.1/8 scope host lo
[trinity10] out:        valid_lft forever preferred_lft forever
[trinity10] out: 


Warning: run() received nonzero return code 139 while executing 'docker exec -i 71b55622a021b7e939210934c6c952567e9f5aaa92dff7f34562098b94e0d4f7 ip addr list'!

[trinity10] run: docker exec -i 71b55622a021b7e939210934c6c952567e9f5aaa92dff7f34562098b94e0d4f7 ip route list
[trinity10] out: default via 192.168.77.10 dev cali0 
[trinity10] out: 192.168.77.10 dev cali0  scope link 
[trinity10] out: 
```

Notice how that `ip addr list` there crashed busybox.
I've seen a [bug report at calico](https://github.com/Metaswitch/calico-docker/issues/4) about that, which was closed as an upstream bug.
I [filed one there](https://bugs.busybox.net/show_bug.cgi?id=8231).

Container A is running on 192.168.89.1.

Next, container B, on trinity20:

```
(venv)crab:docker-calico-fabric mak$ fab create_test_containerB
[trinity20] Executing task 'create_test_containerB'
[trinity20] run: docker pull busybox:latest
[trinity20] out: latest: Pulling from busybox
[trinity20] out: cf2616975b4a: Already exists
[trinity20] out: 6ce2e90b0bc7: Already exists
[trinity20] out: 8c2e06607696: Already exists
[trinity20] out: 8c2e06607696: Already exists
[trinity20] out: Digest: sha256:38a203e1986cf79639cfb9b2e1d6e773de84002feea2d4eb006b52004ee8502d
[trinity20] out: Status: Image is up to date for busybox:latest
[trinity20] out: 

[trinity20] run: docker run --publish-service srvB.anetab.calico --name c-B -tid busybox:latest
[trinity20] out: 4bb33ae29ff80340601f261dda70726f755d71f3d0e30e300db0a54d647f2942
[trinity20] out: 

[trinity20] run: docker inspect --format '{{.Id}}' 4bb33ae29ff80340601f261dda70726f755d71f3d0e30e300db0a54d647f2942
[trinity20] out: 4bb33ae29ff80340601f261dda70726f755d71f3d0e30e300db0a54d647f2942
[trinity20] out: 

[trinity20] run: docker inspect --format '{{.Name}}' 4bb33ae29ff80340601f261dda70726f755d71f3d0e30e300db0a54d647f2942
[trinity20] out: /c-B
[trinity20] out: 

[trinity20] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' 4bb33ae29ff80340601f261dda70726f755d71f3d0e30e300db0a54d647f2942
[trinity20] out: 192.168.89.2
[trinity20] out: 

container_id=4bb33ae29ff80340601f261dda70726f755d71f3d0e30e300db0a54d647f2942, container_name=c-B, ip_address=192.168.89.2
[trinity20] run: docker exec -i 4bb33ae29ff80340601f261dda70726f755d71f3d0e30e300db0a54d647f2942 hostname
[trinity20] out: 4bb33ae29ff8
[trinity20] out: 

[trinity20] run: docker exec -i 4bb33ae29ff80340601f261dda70726f755d71f3d0e30e300db0a54d647f2942 ls -l /sys/devices/virtual/net/
[trinity20] out: total 0
[trinity20] out: drwxr-xr-x    5 root     root             0 Jul 21 12:58 cali0
[trinity20] out: drwxr-xr-x    5 root     root             0 Jul 21 12:58 lo
[trinity20] out: drwxr-xr-x    5 root     root             0 Jul 21 12:58 tunl0
[trinity20] out: 

[trinity20] run: docker exec -i 4bb33ae29ff80340601f261dda70726f755d71f3d0e30e300db0a54d647f2942 ip link list
[trinity20] out: 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default 
[trinity20] out:     link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
[trinity20] out: 2: tunl0@NONE: <NOARP> mtu 1480 qdisc noop state DOWN mode DEFAULT group default 
[trinity20] out:     link/ipip 0.0.0.0 brd 0.0.0.0
[trinity20] out: 14: cali0: <NO-CARRIER,BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state DOWN mode DEFAULT group default qlen 1000
[trinity20] out:     link/ether ee:ee:ee:ee:ee:ee brd ff:ff:ff:ff:ff:ff
[trinity20] out: 

[trinity20] run: docker exec -i 4bb33ae29ff80340601f261dda70726f755d71f3d0e30e300db0a54d647f2942 ip addr list
[trinity20] out: 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
[trinity20] out:     link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
[trinity20] out:     inet 127.0.0.1/8 scope host lo
[trinity20] out:        valid_lft forever preferred_lft forever
[trinity20] out: 


Warning: run() received nonzero return code 139 while executing 'docker exec -i 4bb33ae29ff80340601f261dda70726f755d71f3d0e30e300db0a54d647f2942 ip addr list'!

[trinity20] run: docker exec -i 4bb33ae29ff80340601f261dda70726f755d71f3d0e30e300db0a54d647f2942 ip route list
[trinity20] out: default via 192.168.77.20 dev cali0 
[trinity20] out: 192.168.77.20 dev cali0  scope link 
[trinity20] out: 
```

Container B is running 192.168.89.2.

So... can they talk to eachother?

```
(venv)crab:docker-calico-fabric mak$ fab pingAB
[trinity10] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' c-A
[trinity10] out: 192.168.89.1
[trinity10] out: 

[trinity20] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' c-B
[trinity20] out: 192.168.89.2
[trinity20] out: 

[trinity10] run: docker exec -i c-A ping -c 1 192.168.89.2
[trinity10] out: PING 192.168.89.2 (192.168.89.2): 56 data bytes
[trinity10] out: 64 bytes from 192.168.89.2: seq=0 ttl=62 time=0.486 ms
[trinity10] out: 
[trinity10] out: --- 192.168.89.2 ping statistics ---
[trinity10] out: 1 packets transmitted, 1 packets received, 0% packet loss
[trinity10] out: round-trip min/avg/max = 0.486/0.486/0.486 ms
[trinity10] out: 

[trinity20] run: docker exec -i c-B ping -c 1 192.168.89.1
[trinity20] out: PING 192.168.89.1 (192.168.89.1): 56 data bytes
[trinity20] out: 64 bytes from 192.168.89.1: seq=0 ttl=62 time=0.430 ms
[trinity20] out: 
[trinity20] out: --- 192.168.89.1 ping statistics ---
[trinity20] out: 1 packets transmitted, 1 packets received, 0% packet loss
[trinity20] out: round-trip min/avg/max = 0.430/0.430/0.430 ms
[trinity20] out: 


Done.
Disconnecting from trinity10... done.
Disconnecting from trinity20... done.
```

They sure can. Sweet!

Next, I want to try and run a Solr cluster.
That's a work in progress, but let's see how far we get.

First zookeeper. I'll just put it on single container for now:

```
(venv)crab:docker-calico-fabric mak$ fab create_test_zookeeper
[trinity10] Executing task 'create_test_zookeeper'
[trinity10] run: docker pull jplock/zookeeper
[trinity10] out: Pulling repository jplock/zookeeper

[trinity10] out: 9ce81845fa8f: Pulling image (latest) from jplock/zookeeper 
...

[trinity10] run: docker run --publish-service zookeeper.anetsolr.calico --name zookeeper3 -tid jplock/zookeeper
[trinity10] out: 04d7bf4e1a00554f6d8e2912cd8f95e607bcfec7adb1f81e019ef9ead8c1cccc
[trinity10] out: 

[trinity10] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' 04d7bf4e1a00554f6d8e2912cd8f95e607bcfec7adb1f81e019ef9ead8c1cccc
[trinity10] out: 192.168.89.3
[trinity10] out: 


Done.
Disconnecting from trinity10... done.
```

Next, Solr on a different machine:

```
(venv)crab:docker-calico-fabric mak$ fab create_test_solr1
[trinity10] Executing task 'create_test_solr1'
[trinity10] run: docker pull makuk66/docker-calico-devices:latest
[trinity10] out: latest: Pulling from makuk66/docker-calico-devices
...

[trinity10] out: 3a6af43a1167: Already exists 
[trinity10] out: Digest: sha256:a6b64057e1be409eec0fcf95e351b60338d6d89352cc0339b1d4b269dbc4c14a
[trinity10] out: Status: Image is up to date for makuk66/docker-calico-devices:latest
[trinity10] out: 

[trinity10] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' zookeeper3
[trinity10] out: 192.168.89.3
[trinity10] out: 

[trinity10] run: docker run --publish-service solr1.anetsolr.calico --name solr1 -tid makuk66/docker-calico-devices:latest bash -c '/opt/solr/bin/solr start -f -z 192.168.89.3:2181'
[trinity10] out: 4b4dd769c588ea44d41c1bbd4560419681005263caeeda493b5854951ecbba7d
[trinity10] out: 

[trinity10] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' 4b4dd769c588ea44d41c1bbd4560419681005263caeeda493b5854951ecbba7d
[trinity10] out: 192.168.89.4
[trinity10] out: 

```

and a second one:

```
(venv)crab:docker-calico-fabric mak$ fab create_test_solr2
[trinity20] Executing task 'create_test_solr2'
[trinity20] run: docker pull makuk66/docker-calico-devices:latest
[trinity20] out: latest: Pulling from makuk66/docker-calico-devices
[trinity20] out: 
...
[trinity10] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' zookeeper3
[trinity10] out: 192.168.89.3
[trinity10] out: 

[trinity20] run: docker run --publish-service solr2.anetsolr.calico --name solr2 -tid makuk66/docker-calico-devices:latest bash -c '/opt/solr/bin/solr start -f -z 192.168.89.3:2181'
[trinity20] out: 4a4cf249dcee670d13fb475b3be4a47e2a9d5a8a183bc62cc2627e6dc0762f22
[trinity20] out: 

[trinity20] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' 4a4cf249dcee670d13fb475b3be4a47e2a9d5a8a183bc62cc2627e6dc0762f22
[trinity20] out: 192.168.89.5
[trinity20] out: 
```

and let's see if a client can talk to them:

```
(venv)crab:docker-calico-fabric mak$ fab create_test_solrclient
[trinity30] Executing task 'create_test_solrclient'
[trinity10] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' solr1
[trinity10] out: 192.168.89.4
[trinity10] out: 

...   
[trinity30] out:   <title>Solr Admin</title>
...
[trinity20] run: docker inspect --format '{{ .NetworkSettings.IPAddress }}' solr2
[trinity20] out: 192.168.89.5
[trinity20] out: 

[trinity30] run: docker run --publish-service solrclient-OXLNA8.anetsolr.calico --name solrclient-OXLNA8 -i makuk66/docker-calico-devices:latest curl -sSL http://192.168.89.4:8983/
...
[trinity30] out:   <title>Solr Admin</title>
>
[trinity30] out: 


Done.
Disconnecting from trinity30... done.
Disconnecting from trinity10... done.
Disconnecting from trinity20... done.
(venv)crab:docker-calico-fabric mak$ 
```

Yes, it can.

So, next:
- routing so I can talk to them from my machine
- do a solrcloud example that shows the servers talk together






