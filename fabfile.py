"""

Fabric script to deploy Calico to my Trinity cluster,
try some inter-container/cross-host connectivity,
and deploy solr.

Work in progress.

"""
from fabric.api import env, run, sudo, execute, settings, roles
from fabric.contrib.files import exists, append, put, upload_template
from fabric.network import disconnect_all
import time, os, re, string, random

# define cluster IPs
env.cluster_addresss = {
    'trinity10': '192.168.77.10',
    'trinity20': '192.168.77.20',
    'trinity30': '192.168.77.30'
}

env.roledefs = {
    'all': sorted(env.cluster_addresss.keys()),
    'docker_cli': ['trinity10'],
    'alpha_dockerhost': ['trinity10'],
    'beta_dockerhost': ['trinity20'],
    'zookeeperdockerhost': ['trinity10'],
    'solr1dockerhost': ['trinity10'],
    'solr2dockerhost': ['trinity20'],
    'solrclientdockerhost': ['trinity30'],
}
env.consul_host = "trinity10"
env.etcd_cluster_token = "etcd-cluster-2123"
env.user = "mak"

CALICO_VERSION = "0.5.2"
CALICOCTL_URL = "https://github.com/Metaswitch/calico-docker/releases/download/v{}/calicoctl".format(CALICO_VERSION)
DOCKER_URL = "https://github.com/Metaswitch/calico-docker/releases/download/v{}/docker".format(CALICO_VERSION)
CONSUL_URL = "https://dl.bintray.com/mitchellh/consul/0.5.2_linux_amd64.zip"

SOLR_IMAGE = 'makuk66/docker-calico-devices:latest'
#SOLR_IMAGE='makuk66/docker-solr'
ZOOKEEPER_IMAGE = 'jplock/zookeeper'
ZOOKEEPER_NAME = 'zookeeper3'

BUSYBOX_IMAGE = 'busybox:latest'
UBUNTU_IMAGE = 'ubuntu:latest'
CALICO_IMAGE = "calico/node:v{}".format(CALICO_VERSION)
ETCD_IMAGE = "quay.io/coreos/etcd:v2.0.11"

# Use "a" prefix per https://github.com/docker/libnetwork/issues/401 workaround
# not that that actually seems to work
NET_AB = "anetab"
NET_SOLR = "anetsolr"

TEST_ALPHA = "alpha"
TEST_BETA = "beta"

env.etcd_client_port = 4001
env.etcd_peer_port = 7001

TEMPLATES = 'templates'

def get_docker_host_for_role(role):
    """ get the docker host for a container role """
    return env.roledefs[role][0]

@roles('all')
def info():
    """ Show machine information """
    run('cat /etc/lsb-release')

@roles('all')
def ping():
    """ Ping all the hosts in the cluster from this host """
    for name in sorted(env.cluster_addresss.keys()):
        run("ping -c 3 {}".format(env.cluster_addresss[name]))

@roles('all')
def copy_ssh_key(ssh_pub_key="~/.ssh/id_dsa.pub", user=env.user):
    """ Copy the local ssh key to the cluster machines """
    ssh_pub_key_path = os.path.expanduser(ssh_pub_key)
    remote = "tmpkey.pem"
    put(ssh_pub_key_path, remote)
    sudo("mkdir -p ~{}/.ssh".format(user))
    sudo("cat ~{}/{} >> ~{}/.ssh/authorized_keys".format(user, remote, user))
    sudo("chown {}:{} ~{}/.ssh".format(user, user, user))
    sudo("chown {}:{} ~{}/.ssh/authorized_keys".format(user, user, user))
    sudo("rm ~{}/{}".format(user, remote))

@roles('all')
def setup_sudoers():
    """ Add the user to sudoers, allowing password-less sudo """
    append("/etc/sudoers", "{0}  ALL=(ALL) NOPASSWD:ALL".format(env.user), use_sudo=True)

@roles('all')
def install_experimental_docker():
    """ Execute the exerimental docker recipe, then replace the binary with
        a specific Calico version
    """
    current_docker_version = run("docker version | grep '^Server version: ' | sed 's/^.* //'")
    if "command not found" in current_docker_version:
        sudo('wget -qO- https://experimental.docker.com/ | sh')
        sudo('usermod -aG docker {}'.format(env.user))
        disconnect_all()
    # per https://github.com/Metaswitch/calico-docker/releases/tag/v0.5.2 release notes,
    # use a pre-release version of docker
    filename = "docker"
    run("rm -f {}".format(filename)) # remove old downloads
    run("wget {} > /dev/null 2>&1".format(DOCKER_URL))
    run("chmod a+x {}".format(filename))
    if exists('/etc/init/docker.conf'):
        sudo("stop docker || echo oh well")
    docker_location = run("which docker||true")
    if docker_location == "":
        docker_location = '/usr/bin/docker'
    sudo("mv {} {}".format(filename, docker_location))
    sudo("start docker")
    time.sleep(1)
    run("docker version")

@roles('all')
def docker_version():
    """ display docker version and status """
    run('docker version')
    run('status docker')

@roles('all')
def install_prerequisites():
    """ install OS pre-requisites """
    sudo("modprobe ip6_tables")
    append("/etc/modules", "ip6_tables", use_sudo=True)
    sudo("modprobe xt_set")
    append("/etc/modules", "xt_set", use_sudo=True)
    sudo("sysctl -w net.ipv6.conf.all.forwarding=1")
    sudo("echo net.ipv6.conf.all.forwarding=1 > /etc/sysctl.d/60-ipv6-forwarding.conf")
    sudo("apt-get install -y unzip curl")

@roles('all')
def install_calico():
    """ Install Calico, inspired by https://github.com/Metaswitch/calico-ubuntu-vagrant """
    # TODO: we want to install Calico somewhere more suitable
    if not exists("calicoctl"):
        run("wget -nv {}".format(CALICOCTL_URL))
        run("chmod +x calicoctl")

    sudo("docker pull {}".format(CALICO_IMAGE), pty=False)
    sudo("docker pull {}".format(ETCD_IMAGE), pty=False)

def get_addressv4_address():
    """ utility method to return the ip address for the current host """
    ipv4_address = run("ip -4 addr show dev eth0 | "
                       "grep inet | awk '{print $2}' | sed -e 's,/.*,,'")
    if not re.match(r'^\d+\.\d+\.\d+\.\d+', ipv4_address):
        raise Exception("cannot get IP address")
    return ipv4_address

@roles('all')
def install_consul():
    """ install Consul """
    if env.host == env.consul_host and not exists("/usr/bin/consul"):
        run("rm -f consul.zip consul")
        run("curl -L --silent {} -o consul.zip".format(CONSUL_URL))
        run("unzip consul.zip")
        run("chmod +x consul")
        sudo("mv consul /usr/bin/consul")
        run("rm -f consul.zip")

        ipv4_address = get_addressv4_address()
        ctx = {
            "consul_dir": '/usr/bin',
            "ip_address": ipv4_address
        }
        upload_template(filename='consul.conf', destination='/etc/init/consul.conf',
                        template_dir=TEMPLATES, context=ctx, use_sudo=True, use_jinja=True)

        sudo("service consul start")
        time.sleep(2)

    consul_address = env.cluster_addresss[env.consul_host]
    append("/etc/default/docker",
           'DOCKER_OPTS="--kv-store=consul:{}:8500"'.format(consul_address),
           use_sudo=True)

    sudo("service docker restart")
    time.sleep(5)

@roles('all')
def run_etcd():
    """ Run etcd """
    my_name = "etcd-{}".format(env.host)
    initial_cluster_members = []
    for name in sorted(env.cluster_addresss.keys()):
        ipv4_address = env.cluster_addresss[name]
        initial_cluster_members.append("etcd-{}=http://{}:7001".format(name, ipv4_address))
    initial_cluster = ",".join(initial_cluster_members)
    ipv4_address = get_addressv4_address()
    run('docker pull {}'.format(ETCD_IMAGE), pty=False)
    run("docker run -d "
        "-p {etcd_client_port}:{etcd_client_port} -p {etcd_peer_port}:{etcd_peer_port} "
        "--name quay.io-coreos-etcd "
        "quay.io/coreos/etcd "
        "--name {my_name} "
        "--advertise-client-urls http://{ipv4_address}:{etcd_client_port} "
        "--listen-client-urls http://0.0.0.0:{etcd_client_port} "
        "--initial-advertise-peer-urls http://{ipv4_address}:{etcd_peer_port} "
        "--listen-peer-urls http://0.0.0.0:{etcd_peer_port} "
        "--initial-cluster-token {etcd_cluster_token} "
        "--initial-cluster {initial_cluster} "
        "--initial-cluster-state new".format(ipv4_address=ipv4_address,
                                             my_name=my_name,
                                             etcd_cluster_token=env.etcd_cluster_token,
                                             initial_cluster=initial_cluster,
                                             etcd_peer_port=env.etcd_peer_port,
                                             etcd_client_port=env.etcd_client_port))
    time.sleep(2)

@roles('all')
def docker_clean():
    """ remove containers that have exited """
    run("docker rm `docker ps --no-trunc --all --quiet --filter=status=exited`")

@roles('all')
def check_etcd():
    """ check etcd """
    run("curl -L http://localhost:4001/version")
    run("curl -L http://localhost:4001/v2/machines")

@roles('all')
def start_calico_containers():
    """ start Calico """
    existing = run("docker ps --filter=name=calico-node | tail -n +2")
    if existing == "":
        ipv4_address = get_addressv4_address()
        print "creating and starting calico-node"
        sudo("./calicoctl node --ip={}".format(ipv4_address))
    elif "Up" in existing:
        print "calico-node already running"
        return
    else:
        print "starting existing calico-node"
        run("docker start calico-node")

@roles('docker_cli')
def create_networks():
    """ create two example networks """
    run("docker network create --driver=calico " + NET_AB)
    run("docker network create --driver=calico " + NET_SOLR)
    run("docker network ls")

def get_profile_for_network(wanted_name):
    """ get the profile ID for a named network """
    # there must be a better way to get profiles for named networks.
    networks = run("docker network ls")
    found_network_id = None
    for line in networks.splitlines():
        if line.startswith("NETWORK ID"):
            continue # skip header
        (network_id, name, _) = line.split()
        if name == wanted_name:
            found_network_id = network_id
    if found_network_id == None:
        raise Exception("network {} not found".format(wanted_name))
    # the network ID is a short one like 6df57a08bc98. find the long version in the profiles
    profiles = run("./calicoctl profile show")
    for profile_line in profiles.splitlines():
        print "checking {} for {}".format(found_network_id, profile_line)
        match = re.search(r'\s({}\S+)'.format(found_network_id), profile_line)
        if match is not None:
            return match.group(1)
    raise Exception("no profile found for network {}".format(found_network_id))


@roles('docker_cli')
def configure_network_profiles():
    """ configure network profiles """
    net_ab_profile = get_profile_for_network(NET_AB)
    run("./calicoctl profile {} rule add inbound allow icmp".format(net_ab_profile))

    net_solr_profile = get_profile_for_network(NET_SOLR)
    run("./calicoctl profile {} rule add inbound allow icmp".format(net_solr_profile))
    run("./calicoctl profile {} rule add inbound allow tcp to ports 8983".format(net_solr_profile))

@roles('docker_cli')
def calicoctl_pool():
    """ configure the Calico address pool """
    run("./calicoctl pool show")
    run("./calicoctl pool add 192.168.89.0/24")
    run("./calicoctl pool remove 192.168.0.0/16")
    run("./calicoctl pool add 192.168.89.0/24")
    run("./calicoctl pool show")

@roles('alpha_dockerhost')
def create_test_container_alpha():
    """ create first test container """
    create_test_container(TEST_ALPHA)

@roles('beta_dockerhost')
def create_test_container_beta():
    """ create second test container """
    create_test_container(TEST_BETA)

@roles('alpha_dockerhost')
def create_test_container_dcd():
    """ experimental image to try and get solr working. TODO: remove """
    image = "makuk66/docker-calico-devices:latest"
    name = id_generator()
    container_name = 'c-' + name
    service_name = 'srv{}'.format(name)
    full_service_name = '{}.{}.calico'.format(service_name, NET_SOLR)
    run("docker pull {}".format(image), pty=False)
    container_id = run("docker run --publish-service {} --name {} -tid {}".format(
        full_service_name, container_name, image))
    inspect_container(container_id)
    container_name = run("docker inspect --format '{{.Name}}' " + container_id)[1:]
    print "connect with: fab --host {} -- docker exec -it {} /bin/bash".format(
        env.host, container_name)

# http://stackoverflow.com/questions/2257441/random-string-generation-with-upper-case-letters-and-digits-in-python
def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    """ return a random identifier """
    return ''.join(random.choice(chars) for _ in range(size))

def create_test_container(name='', image=BUSYBOX_IMAGE):
    """ create a test container """
    service_name = 'srv{}'.format(name)
    full_service_name = '{}.{}.calico'.format(service_name, NET_AB)
    container_name = 'c-' + name
    container_id = run("docker pull {}".format(image), pty=False)
    container_id = run("docker run --publish-service {} --name {} -tid {}".format(
        full_service_name, container_name, image))
    inspect_container(container_id)

def inspect_container(container_name_or_id=''):
    """ e.g. fab --host trinity10 inspect_container:container_name_or_id=... """
    container_id = run("docker inspect --format '{{.Id}}' " + container_name_or_id)
    container_name = run("docker inspect --format '{{.Name}}' " + container_name_or_id)
    if container_name[0] == '/':
        container_name = container_name[1:]
    ip_address = run("docker inspect --format '{{ .NetworkSettings.IPAddress }}' " + container_id)
    print "container_id={}, container_name={}, ip_address={}".format(
        container_id, container_name, ip_address)
    run("docker exec -i {} hostname".format(container_id))

    with settings(warn_only=True):
        run("docker exec -i {} ls -l /sys/devices/virtual/net/".format(container_id))
        run("docker exec -i {} ip link list".format(container_id))
        run("docker exec -i {} ip addr list".format(container_id))
        run("docker exec -i {} ip route list".format(container_id))

def ping_test_containers():
    """ see if containers A and B can ping eachother """
    alpha_name = 'c-' + TEST_ALPHA
    beta_name = 'c-B' + TEST_BETA
    alpha_address = None
    beta_address = None
    with settings(host_string=get_docker_host_for_role('container_alpha_dockerhost')):
        alpha_address = run("docker inspect --format '{{ .NetworkSettings.IPAddress }}' " + alpha_name)
    with settings(host_string=get_docker_host_for_role('container_beta_dockerhost')):
        beta_address = run("docker inspect --format '{{ .NetworkSettings.IPAddress }}' " + beta_name)
    with settings(host_string=get_docker_host_for_role('container_alpha_dockerhost')):
        run("docker exec -i {} ping -c 1 {}".format(alpha_name, beta_address))
    with settings(host_string=get_docker_host_for_role('container_beta_dockerhost')):
        run("docker exec -i {} ping -c 1 {}".format(beta_name, alpha_address))

@roles('zookeeperdockerhost')
def create_test_zookeeper():
    """ create zookeeper container """
    run("docker pull {}".format(ZOOKEEPER_IMAGE), pty=False)
    container_id = run("docker run --publish-service zookeeper.{}.calico --name {} -tid {}".format(
        NET_SOLR, ZOOKEEPER_NAME, ZOOKEEPER_IMAGE))
    run("docker inspect --format '{{ .NetworkSettings.IPAddress }}' " + container_id)

@roles('all')
def pull_docker_images():
    """ pull images we'll use """
    for image in [SOLR_IMAGE, ZOOKEEPER_IMAGE, BUSYBOX_IMAGE, UBUNTU_IMAGE,
                  ETCD_IMAGE, CALICO_IMAGE]:
        run("docker pull {}".format(image), pty=False)

@roles('solr1dockerhost')
def create_test_solr1():
    """ create a first Solr container """
    create_test_solr("solr1")

@roles('solr2dockerhost')
def create_test_solr2():
    """ create a second Solr container """
    create_test_solr("solr2")

def create_test_solr(name):
    """ create a container running solr """
    run("docker pull {}".format(SOLR_IMAGE), pty=False)
    with settings(host_string=get_docker_host_for_role('zookeeperdockerhost')):
        zookeeper_address = run("docker inspect --format '{{ .NetworkSettings.IPAddress }}' " + ZOOKEEPER_NAME)
    container_id = run("docker run --publish-service {}.{}.calico --name {} -tid {} bash -c '/opt/solr/bin/solr start -f -z {}:2181'".format(
        name, NET_SOLR, name, SOLR_IMAGE, zookeeper_address))
    run("docker inspect --format '{{ .NetworkSettings.IPAddress }}' " + container_id)

    time.sleep(15)

    run("docker logs {}".format(container_id))

    return container_id

@roles('solrclientdockerhost')
def create_test_solrclient():
    """ talk to both solr nodes from a container """
    solr1_ip_address = None
    with settings(host_string=get_docker_host_for_role('solr1dockerhost')):
        solr1_ip_address = run("docker inspect --format '{{ .NetworkSettings.IPAddress }}' solr1")
    name = 'solrclient-' + id_generator()
    run("docker run --publish-service {}.{}.calico --name {} -i {} "
        "curl -sSL http://{}:8983/".format(name, NET_SOLR, name, SOLR_IMAGE, solr1_ip_address))

    solr2_ip_address = None
    with settings(host_string=get_docker_host_for_role('solr2dockerhost')):
        solr2_ip_address = run("docker inspect --format '{{ .NetworkSettings.IPAddress }}'' solr2")
    name = 'solrclient-' + id_generator()
    run("docker run --publish-service {}.{}.calico --name {} -i {} "
        "curl -sSL http://{}:8983/".format(name, NET_SOLR, name, SOLR_IMAGE, solr2_ip_address))

@roles('solr1dockerhost')
def solr_data():
    """ load test data into solr """
    run("docker exec -i -t solr1 /opt/solr/bin/solr "
        "create_collection c collection1 -shards 2 -p 8983")

@roles('docker_cli')
def add_bgp_peer():
    """ configure BGP peer """
    run("./calicoctl bgp peer add 192.168.77.1 as 64511")

@roles('all')
def docker_ps():
    """ run docker ps """
    run('docker ps')

def install():
    """ install the cluster """
    execute(info)
    execute(copy_ssh_key)
    execute(setup_sudoers)
    execute(install_prerequisites)
    execute(install_experimental_docker)
    execute(docker_version)
    execute(pull_docker_images)
    execute(install_calico)
    execute(install_consul)
    execute(run_etcd)
    execute(check_etcd)
    execute(start_calico_containers)
    execute(calicoctl_pool)
    execute(create_networks)
    execute(configure_network_profiles)

    execute(create_test_container_alpha)
    execute(create_test_container_beta)
    execute(ping_test_containers)

    execute(add_bgp_peer)

    execute(create_test_zookeeper)
    execute(create_test_solr1)
    execute(create_test_solr2)

    execute(create_test_solrclient)
    execute(solr_data)
