# Ceph Luminous - Quick Install (Community)

## Ceph Lab Environment

- 1 client; also used for `ceph-ansible`
- 3 nodes (MON+OSD+MGR); 4 disks.
- Vagrant + libvirt
  - CentOS 7.6 box
  - Custom provision scripts
    - Ceph user (default):
      - username: `cephuser`
      - password:`cephuser`
- `ceph-ansible` community

### Vagrantfile

- Ceph lab:
  
  ```ruby
  # -*- mode: ruby -*-
  # vi: set ft=ruby :
  
  Vagrant.configure("2") do |config|
    config.vm.box = "centos76"
    config.vm.provision :shell, :path => "scripts/setup_ssh.sh"
    config.vm.provision :shell, :path => "scripts/ceph_preflight.sh", :args => "repos", :privileged => true
    config.vm.provision :shell, :path => "scripts/ceph_preflight.sh", :args => "cephuser", :privileged => true
    config.vm.define "client" do |client|
      client.vm.hostname = "client"
      client.vm.provision :shell, :path => "scripts/ceph_preflight.sh", :args => "admpkg", :privileged => true
      client.vm.provision :shell, :path => "scripts/ceph_preflight.sh", :args => "admin_sshkey", :privileged => true
      config.vm.provider :libvirt do |domain|
        domain.memory = 1024
        domain.cpus = 1
      end
    end
    (1..3).each do |i|
      config.vm.define "node#{i}" do |config|
        config.vm.hostname = "node#{i}"
        config.vm.provision :shell, :path => "scripts/ceph_preflight.sh", :args => "nodepkg", :privileged => true
        config.vm.provider :libvirt do |domain|
          domain.memory = 1024
          domain.cpus = 1
          domain.storage :file, :size => '30G', :type => 'qcow2', :serial => 'abcde001'
          domain.storage :file, :size => '30G', :type => 'qcow2', :serial => 'abcde002'
          domain.storage :file, :size => '30G', :type => 'qcow2', :serial => 'abcde003'
          domain.storage :file, :size => '30G', :type => 'qcow2', :serial => 'abcde004'
        end
      end
    end
  # RGW (RADOS Gateway) and MDS (CephFS Metadata Server)
    config.vm.define "node4" do |node4|
      node4.vm.hostname = "node4"
      config.vm.provision :shell, :path => "scripts/ceph_preflight.sh", :args => "nodepkg", :privileged => true
      config.vm.provider :libvirt do |domain|
        domain.memory = 1024
        domain.cpus = 1
      end
    end
  end
  ```

### Provision Scripts

- `ceph_preflight.sh`
  
  ```bash
  #!/bin/bash
  # From: http://docs.ceph.com/docs/mimic/start/quick-start-preflight/#ceph-deploy-setup
  # Variables
  CEPH_USER_NAME="cephuser"
  CEPH_USER_GROUP="cephuser"
  CEPH_USER_PASSWD="cephuser"
  CEPH_USER_HOME="/home/$CEPH_USER_NAME"
  CEPH_USER_SSH_HOME="$CEPH_USER_HOME/.ssh"
  CEPH_USER_AUTHORIZED_KEYS="$CEPH_USER_SSH_HOME/authorized_keys"
  
  ceph_repos(){
  yum-config-manager --enable centosplus extras
  yum install -y -q https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
  yum install -y -q yum-plugin-priorities
  
  #Ceph Luminous repository
  cat << EOM > /etc/yum.repos.d/ceph.repo
  [ceph]
  name=Ceph packages for x86_64
  baseurl=https://download.ceph.com/rpm-luminous/el7/x86_64
  enabled=1
  priority=2
  gpgcheck=1
  gpgkey=https://download.ceph.com/keys/release.asc
  
  [ceph-noarch]
  name=Ceph noarch packages
  baseurl=https://download.ceph.com/rpm-luminous/el7/noarch
  enabled=1
  priority=2
  gpgcheck=1
  gpgkey=https://download.ceph.com/keys/release.asc
  
  [ceph-source]
  name=Ceph source packages
  baseurl=https://download.ceph.com/rpm-luminous/el7/SRPMS
  enabled=0
  priority=2
  gpgcheck=1
  gpgkey=https://download.ceph.com/keys/release.asc
  EOM
  }
  
  ceph_pkg_admin_node() {
    yum install -y -q ceph-deploy ansible sshpass python2-pip.noarch git
  }
  
  ceph_pkg_nodes() {
    yum install -y -q chrony python sshpass
    yum remove -y -q ntpd ntpdate
    systemctl enable chronyd && systemctl start chronyd
  }
  
  ceph_user_create() {
  # Add user without a password
  adduser -s /bin/bash -d "$CEPH_USER_HOME" -c "$CEPH_USER_NAME user" $CEPH_USER_NAME
  echo "$CEPH_USER_NAME:$CEPH_USER_PASSWD" | chpasswd
  
  # Add sudoers to the user's group
  echo "%"$CEPH_USER_GROUP" ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/"$CEPH_USER_NAME"
  sed -i "s/^.*requiretty/#Defaults requiretty/" /etc/sudoers
  
  sed -i 's/SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config
  setenforce 0
  }
  
  ceph_sshkey_admin_node() {
  # Setup keys for custom user
  mkdir -m 0700 -p $CEPH_USER_SSH_HOME
  echo -e 'n\n' | ssh-keygen -q -C "$CEPH_USER_NAME ssh key" -f "$CEPH_USER_SSH_HOME/id_rsa" -q -N ""
  cat "$CEPH_USER_SSH_HOME/id_rsa.pub" >> "$CEPH_USER_AUTHORIZED_KEYS"
  chmod 644 "$CEPH_USER_AUTHORIZED_KEYS"
  
  # OpenSSH client configuration
  cat << EOF > "$CEPH_USER_SSH_HOME"/config
  Host *
     User $CEPH_USER_NAME
     UserKnownHostsFile /dev/null
     StrictHostKeyChecking no
     PasswordAuthentication no
     IdentityFile $CEPH_USER_SSH_HOME/id_rsa
     IdentitiesOnly yes
     LogLevel FATAL
     ForwardAgent yes
  EOF
  
  chown -R "$CEPH_USER_NAME:$CEPH_USER_NAME" "$CEPH_USER_SSH_HOME"
  }
  
  ceph_monitors_firewall() {
    firewall-cmd --zone=public --add-service=ceph-mon --permanent
    firewall-cmd --reload
  }
  
  ceph_osd_mds_firewall() {
    sudo firewall-cmd --zone=public --add-service=ceph --permanent
    firewall-cmd --reload
  }
  
  case $1 in
    repos) ceph_repos ;;
    admpkg) ceph_pkg_admin_node;;
    nodepkg) ceph_pkg_nodes ;;
    cephuser) ceph_user_create ;;
    admin_sshkey) ceph_sshkey_admin_node ;;
    fw_mon) ceph_monitors_firewall ;;
    fw_osd_mon) ceph_osd_mds_firewall ;;
    *) "Options:
        repos) ceph_repos
        admpkg) ceph_pkg_admin_node
        nodepkg) ceph_pkg_nodes
        cephuser) ceph_user_privileges
        admin_sshkey) ceph_sshkey_admin_node
        fw_mon) ceph_monitors_firewall
        fw_osd_mon) ceph_osd_mds_firewall";;
  esac
  ```

- `setup_ssh.sh`
  
  ```bash
  #!/bin/bash
  # Script: setup_ssh.sh
  # Create ssh keys on the provisioned system.
  # Variables
  ROOT_HOME="/root"
  ROOT_SSH_HOME="$ROOT_HOME/.ssh"
  ROOT_AUTHORIZED_KEYS="$ROOT_SSH_HOME/authorized_keys"
  VAGRANT_HOME="/home/vagrant"
  VAGRANT_SSH_HOME="$VAGRANT_HOME/.ssh"
  VAGRANT_AUTHORIZED_KEYS="$VAGRANT_SSH_HOME/authorized_keys"
  
  #sudo sed -i -e 's/^\(#\)\?PermitRootLogin\s\+\(yes\|no\)/PermitRootLogin yes/' \
  #  -e 's/^\(#\)\?PasswordAuthentication\s\+\(yes\|no\)/PasswordAuthentication yes/' \
  #  -e 's/^\(#\)\?UseDNS\s\+\(yes\|no\)/UseDNS yes/' /etc/ssh/sshd_config
  
  # Setup keys for root user.
  echo -e 'n\n' | ssh-keygen -q -C "root ssh key" -f "$ROOT_SSH_HOME/id_rsa" -q -N ""
  cat "$ROOT_SSH_HOME/id_rsa.pub" >> "$ROOT_AUTHORIZED_KEYS"
  chmod 644 "$ROOT_AUTHORIZED_KEYS"
  # OpenSSH client configuration
  cat << EOF > "$CUSTOM_USER_SSH_HOME"/config
  Host *
     UserKnownHostsFile /dev/null
     StrictHostKeyChecking no
     PasswordAuthentication yes
     IdentitiesOnly yes
     LogLevel FATAL
     ForwardAgent yes
  EOF
  chown -R root:root "$ROOT_SSH_HOME"
  
  # Setup keys for vagrant user.
  echo -e 'n\n' | ssh-keygen -q -C "root ssh key" -f "$VAGRANT_SSH_HOME/id_rsa" -q -N ""
  cat "$VAGRANT_SSH_HOME/id_rsa.pub" >> "$ROOT_AUTHORIZED_KEYS"
  cat "$VAGRANT_SSH_HOME/id_rsa.pub" >> "$VAGRANT_AUTHORIZED_KEYS"
  chmod 644 "$VAGRANT_AUTHORIZED_KEYS"
  # OpenSSH client configuration
  cat << EOF > "$CUSTOM_USER_SSH_HOME"/config
  Host *
     UserKnownHostsFile /dev/null
     StrictHostKeyChecking no
     PasswordAuthentication yes
     IdentitiesOnly yes
     LogLevel FATAL
     ForwardAgent yes
  EOF
  chown -R vagrant:vagrant "$VAGRANT_SSH_HOME"
  ```

- `copy_ssh.sh`
  
  ```bash
  #!/bin/bash
  # Script: copy_ssh.sh
  case $1 in
  hosts)
    'ls' -1 /vagrant/.vagrant/machines/ > /vagrant/scripts/hosts.txt
  ;;
  
  copy)
  echo 'Input Password:';
  read -s SSHPASS;
  export SSHPASS
   for NODE in $(cat /vagrant/scripts/hosts.txt); do
     sshpass -e ssh-copy-id -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o PasswordAuthentication=yes $NODE;
   done
  export SSHPASS=''
  ;;
  esac
  ```

## Deploy Ceph Lab

### Vagrant

- Deploy virtual machines
  
  ```
  # vagrant up
  ```

### Client (deployment node)

- SSH keys copy
  
  ```
  $ vagrant ssh client
  [vagrant@client]$ su - cephuser
  [cephuser@client]$ /vagrant/scripts/copy_ssh.sh hosts
  [cephuser@client]$ /vagrant/scripts/copy_ssh.sh copy
  ```

- `ceph-ansible` download
  
  ```
  [cephuser@client]$ cd ~
  [cephuser@client]$ git clone https://github.com/ceph/ceph-ansible.git
  [cephuser@client ceph-ansible]$ cd ~/ceph-ansible
  [cephuser@client ceph-ansible]$ git checkout stable-3.2
  [cephuser@client ceph-ansible]$ git status
  # On branch stable-3.2
  ...
  ```

### ceph-ansible baseline configuration

- Ansible: dependency
  
  ```
  [cephuser@client ceph-ansible]$ cd ~/ceph-ansible
  [cephuser@client ceph-ansible]$ sudo pip install -r requirements.txt
  ```

- Ansible: edit `ansible.cfg` and create log directory
  
  ```bash
  [cephuser@client ceph-ansible]$ cat ansible.cfg
  [defaults]
  ...
  log_path = ./log/ansible.log
  inventory = ./hosts
  ...
  
  [cephuser@client ceph-ansible]$ mkdir ~/ceph-ansible/log
  ```

- Ansible: `hosts` file content
  
  ```
  [cephuser@client ceph-ansible]$ cat hosts
  [mons]
  node[1:3]
  
  [osds]
  node[1:3]
  
  [mgrs]
  node[1:3]
  
  [rgws]
  node4
  
  [mdss]
  node4
  
[clients]
  client
  ```
  
- Ansible: connection test
  
  ```yaml
  [cephuser@client ceph-ansible]$ ansible mons -m ping
  node2 | SUCCESS => {
      "changed": false, 
      "ping": "pong"
  }
  node1 | SUCCESS => {
      "changed": false, 
      "ping": "pong"
  }
  node3 | SUCCESS => {
      "changed": false, 
      "ping": "pong"
  }
  
  [cephuser@client ceph-ansible]$ ansible mons -m command -b -a id
  node1 | SUCCESS | rc=0 >>
  uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
  
  node3 | SUCCESS | rc=0 >>
  uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
  
  node2 | SUCCESS | rc=0 >>
  uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
  ```

### ceph-ansible - Ceph deploy configuration

- **`site.yml`**
  
  ```yaml
  [cephuser@client ceph-ansible]$ cp site.yml.sample site.yml
  [cephuser@client ceph-ansible]$ vi site.yml
  ...
  hosts: osds
  gather_facts: false
  serial: 1
  become: True
  roles:
  - ceph-defaults
  ...
  ```

- **`group_vars/all.yml`**
  
  - Note: **`ntp_service_enabled: false`** because `chronyd` was installed by `ceph_preflight.sh` script.
  
  ```yaml
  [cephuser@client group_vars]$ cp all.yml.sample all.yml
  [cephuser@client group_vars]$ cat all.yml
  ---
  dummy:
  ntp_service_enabled: false
  ceph_origin: repository
  ceph_repository: community
  ceph_mirror: http://download.ceph.com
  ceph_stable_key: https://download.ceph.com/keys/release.asc
  ceph_stable_release: luminous
  ceph_stable_repo: "{{ ceph_mirror }}/rpm-{{ ceph_stable_release }}"
  ceph_stable_redhat_distro: el7
  rbd_cache: "true"
  rbd_cache_writethrough_until_flush: "false"
  rbd_client_directories: false
  monitor_interface: eth0
  journal_size: 1024
  public_network: 192.168.121.0/24
  cluster_network: "{{ public_network }}"
  radosgw_civetweb_port: 80
  radosgw_interface: eth0
  ceph_conf_overrides:
    global:
      mon_allow_pool_delete: true
      mon_osd_allow_primary_affinity: 1
      mon_clock_drift_allowed: 0.5
      osd_pool_default_size: 2
      osd_pool_default_min_size: 1
      mon_pg_warn_min_per_osd: 0
      mon_pg_warn_max_per_osd: 0
      mon_pg_warn_max_object_skew: 0
    client:
      rbd_default_features: 1
    client.rgw.node4:
      rgw_dns_name: node4
  ```

- **`group_vars/osds.yml`**
  
  ```yaml
  [cephuser@client group_vars]$ cp osds.yml.sample osds.yml
  [cephuser@client group_vars]$ cat osds.yml
  ---
  dummy:
  osd_scenario: collocated
  devices:
     - /dev/vdb
     - /dev/vdc
     - /dev/vdd
     - /dev/vde
  ```

- **`group_vars/rgws.yml`**
  
  ```yaml
  [cephuser@client group_vars]$ cp rgws.yml.sample rgws.yml
  [cephuser@client group_vars]$ cat rgws.yml
  ---
  dummy:
  copy_admin_key: true
  ```
  
- **`group_vars/mdss.yml`**

  ```yaml
  [cephuser@client group_vars]$ cp mdss.yml.sample mdss.yml
  [cephuser@client group_vars]$ cat mdss.yml
  ---
  dummy:
  copy_admin_key: true
  ```

- **`group_vars/clients.yml`**
  
  ```yaml
  [cephuser@client group_vars]$ cp clients.yml.sample clients.yml
  [cephuser@client group_vars]$ cat clients.yml
  ---
  dummy:
  copy_admin_key: true
  ```

### ceph-ansible - Ceph deploy

- Run the `site.yml` playbook
  
  ```yaml
  [cephuser@client group_vars]$ cd ..
  [cephuser@client ceph-ansible]$ ansible-playbook site.yml
  PLAY RECAP ****************************************************************************
  client                     : ok=75   changed=3    unreachable=0    failed=0   
  node1                      : ok=254  changed=8    unreachable=0    failed=0   
  node2                      : ok=239  changed=8    unreachable=0    failed=0   
  node3                      : ok=241  changed=8    unreachable=0    failed=0   
  ```

### Admin keyring permission

- To avoid using `sudo` or `root` with Ceph, set `/etc/ceph/ceph.client.admin.keyring` group to cephuser:
  
  ```bash
  [cephuser@client group_vars]$ sudo chown :cephuser /etc/ceph/ceph.client.admin.keyring
  [cephuser@client group_vars]$ sudo chmod g+r /etc/ceph/ceph.client.admin.keyring
  [cephuser@client group_vars]$ ls -l /etc/ceph/ceph.client.admin.keyring 
  -rw-r-----. 1 ceph cephuser 63 Apr 12 23:07 /etc/ceph/ceph.client.admin.keyring
  ```

### RADOS Gateway (RGW) - test connection

- Test the connection to node4 using curl:
  
  ```bash
  [cephuser@client group_vars]$ curl node4:80
  <?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>anonymous</ID><DisplayName></DisplayName></Owner><Buckets></Buckets></ListAllMyBucketsResult>
  ```

### RADOS Gateway (RGW)  - arbitrary subdomain name resolution

- This configuration is important for S3 buckets and Swift containers creation. The API follows the pattern `bucketname.hostname.fqdn` i.e `mybucket.node4.lab.example.com`. The arbitrary subdomain name resolution must be available, otherwise, the bucket or container *specific name* must be added to the DNS. See [Dnsmasq name resolution](#(Recommended) - Dnsmasq name resolution)

- Install and configure dnsmasq on `client` node. The `NODE4.IP.ADDRESS` must be changed to the `node4` guest IP address where RADOS Gateway will be deployed:
  
  ```bash
  [root@client ~]# cat /etc/NetworkManager/conf.d/enable-dnsmasq.conf
  [main]
  dns=dnsmasq
  
  [root@client ~]# cat /etc/NetworkManager/dnsmasq.d/vagrant-domain.conf
  address=/.node4.lab.example.com/NODE4.IP.ADDRESS
  
  [root@client ~]# systemctl restart NetworkManager
  ```

- Test the configuration using `host` command. Note that anything followed by `.node4.lab.example.com` should return `node4` IP address:
  
  ```bash
  [cephuser@client ~]$ host asd.node4.lab.example.com
  asd.node4.lab.example.com has address 192.168.121.185
  [cephuser@client ~]$ host blabla.node4.lab.example.com
  blabla.node4.lab.example.com has address 192.168.121.185
  [cephuser@client ~]$ host xyz.node4.lab.example.com
  xyz.node4.lab.example.com has address 192.168.121.185
  ```

## Dnsmasq name resolution

- Permit FQDN name resolution between libvirt host and guest in the vagrant-libvirt network. Useful for RADOS Gateway tests.
  
  - Drawback:  hostname reutilization may lead to duplicate DNS entries, like so:
  
  ```bash
  # virsh net-dhcp-leases vagrant-libvirt
   Expiry Time           MAC address         Protocol   IP address           Hostname   Client ID or DUID
  ---------------------------------------------------------------------------------------------------------
   2019-05-31 14:44:14   52:54:00:b8:e0:bb   ipv4       192.168.121.128/24   node1    -
   2019-05-31 14:47:07   52:54:00:f0:7f:49   ipv4       192.168.121.163/24   node1    -
  ```

- NetworkManager and Dnsmasq:
  
  ```bash
  # cat /etc/NetworkManager/conf.d/99-enable-dnsmasq.conf 
  [main]
  dns=dnsmasq
  
  # cat /etc/NetworkManager/dnsmasq.d/vagrant-domain.conf 
  server=/lab.example.com/192.168.121.1
  
  # restorecon -RFv /etc/NetworkManager/
  # systemctl restart NetworkManager
  ```

- Add `<domain name='lab.example.com' localOnly='yes'/>` to `vagrant-libvirt` network configuration:
  
  ```bash
  # virsh net-edit vagrant-libvirt
  <network ipv6='yes'>
    <name>vagrant-libvirt</name>
    <uuid>e6c815dd-25c9-42e5-ba40-1b9137ee9143</uuid>
    <forward mode='nat'/>
    <bridge name='virbr1' stp='on' delay='0'/>
    <mac address='52:54:00:ca:4b:d0'/>
    <domain name='lab.example.com' localOnly='yes'/>
    <ip address='192.168.121.1' netmask='255.255.255.0'>
      <dhcp>
        <range start='192.168.121.1' end='192.168.121.254'/>
      </dhcp>
    </ip>
  </network>
  ```

- Commit the changes:
  
  ```bash
  # virsh net-destroy vagrant-libvirt
  # virsh net-start vagrant-libvirt
  ```

## (Optional) OpenStack - Quick Install

### OpenStack Lab Environment

- OpenStack All-in-One (Community)
- Vagrant, vagrant-libvirt
  - CentOS 7.6 box

### Vagrantfile

- Openstack lab:
  
  ```ruby
  # -*- mode: ruby -*-
  # vi: set ft=ruby :
  
  Vagrant.configure(2) do |config|
    config.vm.box = "centos76"
    config.hostmanager.enabled = true
    config.hostmanager.manage_host = true
    config.hostmanager.manage_guest = true
    config.hostmanager.ignore_private_ip = false
    config.hostmanager.include_offline = true
  
    config.vm.define "opstack" do |openstack|
      openstack.vm.hostname = "opstack"
      openstack.vm.network :private_network, ip: "172.20.10.10",
                           :libvirt__domain_name => "example.lab"
      config.vm.provider :libvirt do |domain|
        domain.memory = 4096
        domain.cpus = 1
      end
    end
  end
  ```

### Requisites

- Services:
  
  ```bash
  [root@opstack ~]# systemctl disable firewalld && systemctl stop firewalld
  [root@opstack ~]# systemctl disable NetworkManager && systemctl stop NetworkManager
  [root@opstack ~]# systemctl enable network && systemctl start network
  ```

- Packages:
  
  Choose an OpenStack version available in the repository.
  
  ```bash
  [root@opstack ~]# yum -y install openstack-packstack.noarch centos-release-openstack-pike.x86_64
  [root@opstack ~]# yum update -y
  [root@opstack ~]# reboot
  ```

### Packstack

- Generate answer file:
  
  ```bash
  [root@opstack ~]# packstack --provision-demo=n --os-neutron-ml2-type-drivers=vxlan,flat,vlan --gen-answer-file=packstack-answers.txt
  [root@opstack ~]# packstack --answer-file=packstack-answers.txt
  ```

## Destroy Ceph Cluster

In case something went wrong during the `ceph-ansible` installation process, need to redeploy the whole cluster or just parts of it, you may use `infrastructure-playbooks/purge-cluster.yml` playbook.

- Removing only RGW:

  ~~~
  [cephuser@client ceph-ansible]$ ansible-playbook --limit rgws infrastructure-playbooks/purge-cluster.yml
  ~~~

- Purging the whole cluster:

  ~~~
  [cephuser@client ceph-ansible]$ ansible-playbook infrastructure-playbooks/purge-cluster.yml
  ~~~

# Ceph Luminous - Cheatsheet

Documentation: [CEPH STORAGE CLUSTER](http://docs.ceph.com/docs/luminous/rados/)

## Monitoring and Health

### Cluster status information

- Command: **`ceph -s`** or **`ceph status`**
  
  ```
  # ceph -s
    cluster:
      id:     4c5daa7a-0078-4983-9606-23ebe9a6995e
      health: HEALTH_OK
  
    services:
      mon: 3 daemons, quorum node2,node3,node1
      mgr: node1(active), standbys: node3, node2
      osd: 12 osds: 12 up, 12 in
      rgw: 1 daemon active
  
    data:
      pools:   4 pools, 32 pgs
      objects: 187 objects, 1.09KiB
      usage:   12.1GiB used, 347GiB / 359GiB avail
      pgs:     32 active+clean
  ```

### Ongoing ceph cluster status (watch)

- Command: **`ceph -w`**
  
  ```
  # ceph -w
  ... output ommitted
  2019-04-12 23:12:09.735894 mon.node3 [INF] Cluster is now healthy
  ```

### Ongoing WARN status only

- Command: **`ceph --watch-warn`**
  
  ```
  # ceph --watch-warn 
  ... output ommitted
  2019-04-12 23:08:05.042436 mon.node3 [WRN] mon.1 192.168.121.130:6789/0 clock skew 1.0988s > max 0.5s
  ```

### Health issue detail

- Command: **`ceph health detail`**
  
  ```
  # ceph health detail
  HEALTH_OK
  ```

### Monitor quorum status

- Command: **`ceph quorum_status {--format json-pretty}`**
  
  ```
  # ceph quorum_status
  {"election_epoch":8,"quorum":[0,1,2],"quorum_names":["node2","node3","node1"],"quorum_leader_name":"node2","monmap":{"epoch":1,"fsid":"4c5daa7a-0078-4983-9606-23ebe9a6995e","modified":"2019-05-30 14:03:20.889751","created":"2019-05-30 14:03:20.889751","features":{"persistent":["kraken","luminous"],"optional":[]},"mons":[{"rank":0,"name":"node2","addr":"192.168.121.41:6789/0","public_addr":"192.168.121.41:6789/0"},{"rank":1,"name":"node3","addr":"192.168.121.57:6789/0","public_addr":"192.168.121.57:6789/0"},{"rank":2,"name":"node1","addr":"192.168.121.208:6789/0","public_addr":"192.168.121.208:6789/0"}]}}
  
  # ceph quorum_status --format json-pretty
  
  {
      "election_epoch": 8,
      "quorum": [
          0,
          1,
          2
      ],
      "quorum_names": [
          "node2",
          "node3",
          "node1"
      ],
      "quorum_leader_name": "node2",
      "monmap": {
  ... output ommitted
  ```

### Display global disk usage (size, available) and per pool information

- Command: **`ceph df`**
  
  ```
  # ceph df
  GLOBAL:
      SIZE       AVAIL      RAW USED     %RAW USED 
      359GiB     347GiB      12.1GiB          3.38 
  POOLS:
      NAME                    ID     USED        %USED     MAX AVAIL     OBJECTS 
      .rgw.root               1      1.09KiB         0        164GiB           4 
      default.rgw.control     2           0B         0        164GiB           8 
      default.rgw.meta        3           0B         0        164GiB           0 
      default.rgw.log         4           0B         0        164GiB         175 
      myfirstpool             5           0B         0        164GiB           0 
      mysecondpool            6           0B         0        164GiB           0 
      mythirdpool             7           0B         0        164GiB           0 
      myfourthpool            8           0B         0        164GiB           0 
  ```

## Pools and OSDs

Documentation: [POOLS](http://docs.ceph.com/docs/luminous/rados/operations/pools/)

### Check class, hosts and their OSDs, up/down status, weight, local reweight and primary affinity

- Command: **`ceph osd tree`**
  
  ```
  # ceph osd tree
  ID CLASS WEIGHT  TYPE NAME      STATUS REWEIGHT PRI-AFF 
  -1       0.35028 root default                           
  -3       0.11676     host node1                         
   0   hdd 0.02919         osd.0      up  1.00000 1.00000 
   1   hdd 0.02919         osd.1      up  1.00000 1.00000 
   2   hdd 0.02919         osd.2      up  1.00000 1.00000 
   3   hdd 0.02919         osd.3      up  1.00000 1.00000 
  -5       0.11676     host node2                         
   4   hdd 0.02919         osd.4      up  1.00000 1.00000 
   5   hdd 0.02919         osd.5      up  1.00000 1.00000 
   6   hdd 0.02919         osd.6      up  1.00000 1.00000 
   7   hdd 0.02919         osd.7      up  1.00000 1.00000 
  -7       0.11676     host node3                         
   8   hdd 0.02919         osd.8      up  1.00000 1.00000 
   9   hdd 0.02919         osd.9      up  1.00000 1.00000 
  10   hdd 0.02919         osd.10     up  1.00000 1.00000 
  11   hdd 0.02919         osd.11     up  1.00000 1.00000 
  ```

### Check disk usage linked to the CRUSH tree including weight and variance (non-uniform usage)

- Command: **`ceph osd df tree`**
  
  ```
  # ceph osd df tree
  ID CLASS WEIGHT  REWEIGHT SIZE    USE     AVAIL   %USE VAR  PGS TYPE NAME      
  -1       0.35028        -  359GiB 12.1GiB  347GiB 3.37 1.00   - root default   
  -3       0.11676        -  120GiB 4.03GiB  116GiB 3.37 1.00   -     host node1 
   0   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.37 1.00   6         osd.0  
   1   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.37 1.00   8         osd.1  
   2   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.37 1.00   3         osd.2  
   3   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.37 1.00   4         osd.3  
  -5       0.11676        -  120GiB 4.03GiB  116GiB 3.37 1.00   -     host node2 
   4   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.37 1.00   4         osd.4  
   5   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.37 1.00   5         osd.5  
   6   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.37 1.00   5         osd.6  
   7   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.37 1.00   6         osd.7  
  -7       0.11676        -  120GiB 4.03GiB  116GiB 3.37 1.00   -     host node3 
   8   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.37 1.00   3         osd.8  
   9   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.37 1.00   3         osd.9  
  10   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.37 1.00  10         osd.10 
  11   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.37 1.00   7         osd.11 
                      TOTAL  359GiB 12.1GiB  347GiB 3.37                         
  MIN/MAX VAR: 1.00/1.00  STDDEV: 0
  ```

### Check OSD space usage including number of PG

- Command: **`ceph osd df`**
  
  ```
  # ceph osd df
  ID CLASS WEIGHT  REWEIGHT SIZE    USE     AVAIL   %USE VAR  PGS 
   0   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.38 1.00  37 
   1   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.38 1.00  26 
   2   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.38 1.00  19 
   3   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.38 1.00  26 
   4   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.38 1.00  27 
   5   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.38 1.00  31 
   6   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.38 1.00  19 
   7   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.38 1.00  31 
   8   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.38 1.00  28 
   9   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.38 1.00  19 
  10   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.38 1.00  28 
  11   hdd 0.02919  1.00000 29.9GiB 1.01GiB 28.9GiB 3.38 1.00  29 
                      TOTAL  359GiB 12.1GiB  347GiB 3.38   
  ```

### Print histogram of which OSDs are blocking their peers

- Command: **`ceph osd blocked-by`**
  
  ```
  # ceph osd blocked-by
  osd num_blocked 
  ```

### Initiate a light scrub (non-deep scrub)

- Command: **`ceph osd scrub <osd_id>`**
  
  ```
  # ceph osd scrub osd.1
  instructed osd(s) 1 to scrub
  ```

### Initiate deep scrub (consistency check).

- Command: **`ceph osd deep-scrub <osd_id>`**

- Description: this is I/O intensive. It actually reads all data on the OSD and might highly impact clients.
  
  ```
  # ceph osd deep-scrub osd.9
  instructed osd(s) 9 to deep-scrub
  ```

### Display location of a given OSD (hostname, port, CRUSH details)

- Command: **`ceph osd find <osd_id>`**
  
  ```
  # ceph osd find 4
  {
      "osd": 4,
      "ip": "192.168.121.41:6800/13824",
      "osd_fsid": "9d1943b6-569b-46d3-af1c-28e4b464f95b",
      "crush_location": {
          "host": "node2",
          "root": "default"
      }
  }
  ```

### Locate an object from a pool

- Command: **`ceph osd map <pool_name> <obj_name>`**

- Description: displays primary and replica placement groups for the object. Also simulates the object placement if it doesn't exists.
  
  ```
  # ceph osd map myfirstpool filename_object001
  osdmap e76 pool 'myfirstpool' (5) object 'filename_object001' -> pg 5.e1746dd (5.1d) -> up ([1,4], p1) acting ([1,4], p1)
  ```

### Display OSD metadata

- Command: **`ceph osd metadata <osd_id>`**
  
  ```
  # ceph osd metadata 8
  {
      "id": 8,
      "arch": "x86_64",
      "back_addr": "192.168.121.57:6801/14252",
      "back_iface": "eth0",
      "bluefs": "1",
      "bluefs_db_access_mode": "blk",
      "bluefs_db_block_size": "4096",
      "bluefs_db_dev": "252:16",
      "bluefs_db_dev_node": "vdb",
      "bluefs_db_driver": "KernelDevice",
      "bluefs_db_model": "",
      "bluefs_db_partition_path": "/dev/vdb2",
      "bluefs_db_rotational": "1",
      "bluefs_db_size": "32106328064",
      "bluefs_db_type": "hdd",
      "bluefs_single_shared_device": "1",
      "bluestore_bdev_access_mode": "blk",
      "bluestore_bdev_block_size": "4096",
      "bluestore_bdev_dev": "252:16",
      "bluestore_bdev_dev_node": "vdb",
      "bluestore_bdev_driver": "KernelDevice",
      "bluestore_bdev_model": "",
      "bluestore_bdev_partition_path": "/dev/vdb2", «
      "bluestore_bdev_rotational": "1",
      "bluestore_bdev_size": "32106328064",
      "bluestore_bdev_type": "hdd",
      "ceph_version": "ceph version 12.2.12 (1436006594665279fe734b4c15d7e08c13ebd777) luminous (stable)",
      "cpu": "Intel Core Processor (Skylake, IBRS)",
      "default_device_class": "hdd",
      "distro": "centos",
      "distro_description": "CentOS Linux 7 (Core)",
      "distro_version": "7",
      "front_addr": "192.168.121.57:6800/14252",
      "front_iface": "eth0",
      "hb_back_addr": "192.168.121.57:6802/14252",
      "hb_front_addr": "192.168.121.57:6803/14252",
      "hostname": "node3",
      "journal_rotational": "1",
      "kernel_description": "#1 SMP Thu Nov 8 23:39:32 UTC 2018",
      "kernel_version": "3.10.0-957.el7.x86_64",
      "mem_swap_kb": "2097148",
      "mem_total_kb": "1014860",
      "os": "Linux",
      "osd_data": "/var/lib/ceph/osd/ceph-8",  «
      "osd_objectstore": "bluestore",          «
      "rotational": "1"
  }
  ```

### Take OSD out of the cluster

- Command: **`ceph osd out <osd_id>`**

- Description: this rebalances data among OSD. The inverse is `ceph osd in <num>`.
  
  ```
  # ceph osd out 7
  marked out osd.7.
  # ceph osd tree out
  ID CLASS WEIGHT  TYPE NAME      STATUS REWEIGHT PRI-AFF 
  -1       0.35028 root default                           
  -5       0.11676     host node2                         
   7   hdd 0.02919         osd.7      up        0 1.00000 « note REWEIGHT value
  ```

### Put OSD back in the cluster

- Command: **`ceph osd in <osd_id>`**

- Description: this rebalances data among OSD. The inverse is `ceph osd out <num>`.
  
  ```
  # ceph osd in 7
  marked in osd.7.
  # ceph osd tree
  ID CLASS WEIGHT  TYPE NAME      STATUS REWEIGHT PRI-AFF 
  ... output ommitted
   6   hdd 0.02919         osd.6      up  1.00000 1.00000 
   7   hdd 0.02919         osd.7      up  1.00000 1.00000 «
  ... output ommitted
  ```

### Permanently set weight instead of system-assigned value

- Command: **`ceph osd crush reweight <osd.id> <weight>`**

- Description: the weights can be checked with `ceph osd tree` for example the size of disk in TB. Check `ceph osd reweight to change the weight temporarily.
  
  ```
  # ceph osd crush reweight osd.0 2.3
  # ceph osd tree
  ID CLASS WEIGHT  TYPE NAME      STATUS REWEIGHT PRI-AFF 
  ... output ommitted
   0   hdd 2.29999         osd.0      up  1.00000 1.00000 « note WEIGHT value
   1   hdd 0.02829         osd.1      up  1.00000 1.00000 
   2   hdd 0.02829         osd.2      up  1.00000 1.00000 
  ... output ommitted
  ```

### Temporarily override weight (reweight) OSD

- Command: **`ceph osd reweight <osd_id> <weight>`**

- Description: used to reweight the OSD.  Refer to `ceph osd crush reweight` to permanently set the weight.
  
  ```
  # ceph osd reweight 4 0.6 # use 60% of the default space in osd.4
  reweighted osd.4 to 0.6 (9999)
  # ceph osd tree
  ID CLASS WEIGHT  TYPE NAME      STATUS REWEIGHT PRI-AFF 
  ... output ommitted
   3   hdd 0.02829         osd.3      up  1.00000 1.00000 
   4   hdd 0.02829         osd.4      up  0.59999 1.00000 «
   5   hdd 0.02829         osd.5      up  1.00000 1.00000 
  ```

### Automatically reweight disks according to their utilization

- Command: **`ceph osd reweight-by-utilization <percent>`**

- Description: Ceph tries to balance disk usage evenly, but this does not always work that well - variations by +/-15% are not uncommon. `reweight-by-utilization` automatically reweights disks according to their utilization. The  `<percent>` value is a threshold - OSDs which have non-perfect balance (with perfect being defined as 100%) but fall below the `<percent>` threshold will not be reweighted. The `<percent>` value defaults to 120. Note that as with all reweighting, this can kick off a lot of data shuffling, potentially impacting clients. Note that `reweight-by-utilization` doesn't work well with low overall utilization. See the `test-reweight-by-utilization` subcommand which is a dry-run version of this.
  
  ```
  # ceph osd reweight-by-utilization 105
  no change
  moved 0 / 64 (0%)
  avg 7.11111
  stddev 1.44871 -> 1.44871 (expected baseline 2.51416)
  min osd.0 with 5 -> 5 pgs (0.703125 -> 0.703125 * mean)
  max osd.1 with 9 -> 9 pgs (1.26562 -> 1.26562 * mean)
  
  oload 105
  max_change 0.05
  max_change_osds 4
  average_utilization 0.0037
  overload_utilization 0.0038
  ```

### Test `reweight-by-utilization` (no reweight is done; just test it)

- Command: **`ceph osd test-reweight-by-utilization <percent>`**
  
  ```
  # ceph osd test-reweight-by-utilization 150
  no change
  moved 0 / 64 (0%)
  avg 7.11111
  stddev 1.44871 -> 1.44871 (expected baseline 2.51416)
  min osd.0 with 5 -> 5 pgs (0.703125 -> 0.703125 * mean)
  max osd.1 with 9 -> 9 pgs (1.26562 -> 1.26562 * mean)
  
  oload 150
  max_change 0.05
  max_change_osds 4
  average_utilization 0.0037
  overload_utilization 0.0055
  ```

### Set flag to the OSD subsystem

- Command: **`ceph osd set <flag>`**

- Description: warning: when a flag is set, ceph health changes to `HEALTH_WARN`

- Some useful flags:
  
  - **`nodown`** - prevent OSDs from getting marked down. 
  
  - **`noout`** - prevent OSDs from getting marked `out` (will inhibit rebalance). 
  
  - **`noin`** - prevent booting OSDs from getting marked `in`.
  
  - **`noscrub`** and **`nodeep-scrub`** - prevent respective scrub type (regular or deep). 
  
  - Other: **`full`**, **`pause`**, **`noup`**, **`nobackfill`**, **`norebalance`**, **`norecover`**.
    
    ```
    # ceph osd set nodown
    nodown is set
    # ceph health
    HEALTH_WARN nodown flag(s) set
    ```

### Unset flags on the OSD subsystem

- Command: **`ceph osd unset <flag>`**

- Description: the inverse subcommand of `set`.
  
  ```
  # ceph osd unset nodown
  nodown is unset
  # ceph health
  HEALTH_OK
  ```

### Create a new replicated pool with `pg_num` placement groups

- Command: **`ceph osd pool create <pool_name> <pg_num> {pgp_num}`**

- Description: use eg. `pg_num=128` for a small cluster. The example is showing `pg_num=32` due to laboratory limitations, **not recommended to use small `pg_num`**. Once the `pg_num` is set, it **cannot be decreased** only **increased**. Check [here](http://docs.ceph.com/docs/luminous/rados/operations/placement-groups/) for details on calculating placement groups.

- There is **`pg_num`** the number of PGs and then there is **`pgp_num`** the number of PGs available to receive data. These numbers should **always be the same** *except* when you are **increasing** the PG counts: 
  
  - First, increase **`pg_num`** to create the PGs, then;
  - Second, Increase **`pgp_num`** second to tell ceph to move the data there, now that they have been created.

- If you have poor PG counts for the pools, there will be uneven distribution among the cluster. Some OSDs will have a large amount of data on them, while others will have very little.

- Increasing pg counts can break that pool into small numbers so that you can get a more even distribution across the cluster, however, too low PG counts can cause performance impacts; too high PG counts can cause performance impacts. There is a PG Calc to help with that.

- The default is to create a pool as `replicated`. The options are `{replicated|erasure}`.
  
  ```
  # ceph osd pool create mythirdpool 16
  pool 'mythirdpool' created
  OR
  # ceph osd pool create mythirdpool 16 16
  
  # ceph osd lspools
  1 myfirstpool,2 mysecondpool,3 mythirdpool,
  ```

### Short pool list including pool_id

- Command: **`ceph osd lspools`**
  
  ```
  # ceph osd lspools
  1 myfirstpool,2 mysecondpool,3 mythirdpool,
  ```

### List pools and optionally some details

- Command: **`ceph osd pool ls {detail}`**
  
  ```
  # ceph osd pool ls
  myfirstpool
  mysecondpool
  mythirdpool
  # ceph osd pool ls detail
  pool 1 'myfirstpool' replicated size 2 min_size 1 crush_rule 0 object_hash rjenkins pg_num 16 pgp_num 16 last_change 48 flags hashpspool stripe_width 0
  pool 2 'mysecondpool' replicated size 2 min_size 1 crush_rule 0 object_hash rjenkins pg_num 16 pgp_num 16 last_change 52 flags hashpspool stripe_width 0
  pool 3 'mythirdpool' replicated size 2 min_size 1 crush_rule 0 object_hash rjenkins pg_num 32 pgp_num 32 last_change 115 flags hashpspool stripe_width 0
  ```

### Get all parameters for a pool

- Command: **`ceph osd pool get <pool_name> all`**

- Description: instead of `all` you can also specify `<param>` name.
  
  ```
  # ceph osd pool get mythirdpool all
  size: 2
  min_size: 1
  crash_replay_interval: 0
  pg_num: 32
  pgp_num: 32
  crush_rule: replicated_rule
  hashpspool: true
  nodelete: false
  nopgchange: false
  nosizechange: false
  write_fadvise_dontneed: false
  noscrub: false
  nodeep-scrub: false
  use_gmt_hitset: 1
  auid: 0
  fast_read: 0
  ```

### Set a pool parameter

- Command: **`ceph osd pool set <pool_name> <param> <val>`**

- Description: there are other valid options i.e `size`, `min_size`, `pg_num` and so on.
  
  ```
  # ceph osd pool set mythirdpool size 3
  set pool 3 size to 3
  # ceph osd pool get mythirdpool size
  size: 3
  ```

### Set (enable) pool application to use pool (needed)

- Command: **`ceph osd pool application enable <pool_name> <app>`**

- Description: after creating a pool, administrators **must** explicitly indicate the type of Ceph applications that will be able to use it. Available options:
  
  - **`rbd`**- Ceph Block Device (also known as RADOS Block Device or RBD)
  
  - **`rgw`** - Ceph Object Gateway (also known as RADOS Gateway or RGW)
  
  - **`cephfs`** - Ceph File System (CephFS).
  
  ```
  # ceph osd pool application enable mythirdpool rbd
  enabled application 'rbd' on pool 'mythirdpool'
  # ceph osd pool ls detail
  ... output ommitted
  pool 3 'mythirdpool' replicated size 3 min_size 1 crush_rule 0 object_hash rjenkins pg_num 32 pgp_num 32 last_change 133 lfor 0/125 flags hashpspool stripe_width 0 application rbd
  ```

### Set quotas to limit the maximum number of bytes or the maximum number of objects that can be stored in the pool

- Command: **`ceph osd pool set-quota <pool_name> {max_objects <obj-count> | max_bytes <bytes>}`**

- Description: When Ceph reaches a pool quota, operations are blocked indefinitely. You can remove a quota by setting its value to 0.
  
  ```
  # ceph osd pool set-quota mythirdpool max_objects 500
  set-quota max_objects = 500 for pool mythirdpool
  # ceph osd pool ls detail
  ... output ommitted
  pool 3 'mythirdpool' replicated size 3 min_size 1 crush_rule 0 object_hash rjenkins pg_num 32 pgp_num 32 last_change 135 lfor 0/125 flags hashpspool max_objects 500 stripe_width 0 application rbd
  ```

### Take  snapshot of a pool

- Command: **`ceph osd pool mksnap <pool_name> <snap_name>`**
  
  ```
  # ceph osd pool mksnap mythirdpool mythirdpool_snap
  created pool mythirdpool snap mythirdpool_snap
  # ceph osd pool ls detail
  ... output ommitted
  pool 3 'mythirdpool' replicated size 3 min_size 1 crush_rule 0 object_hash rjenkins pg_num 32 pgp_num 32 last_change 137 lfor 0/125 flags hashpspool stripe_width 0 application rbd
      snap 1 'mythirdpool_snap' 2019-04-13 11:05:16.114450
  ```

### Remove snapshot of a pool

- Command: **`ceph osd pool rmsnap <pool_name> <snap_name>`**
  
  ```
  # ceph osd pool rmsnap mythirdpool mythirdpool_snap
  removed pool mythirdpool snap mythirdpool_snap
  ```

### Rename a pool

- Command: **`ceph osd pool rename <pool_name> <pool_new_name>`**
  
  ```
  # ceph osd pool rename mythirdpool myrenamedthirdpool
  pool 'mythirdpool' renamed to 'myrenamedthirdpool'
  ```

### Delete a pool (caution)

- Command: **`ceph osd pool delete <pool_name> <pool_name> --yes-i-really-really-mean-it`**

- Description: the pool name must be typed twice, followed by confirmation. **Warning: it deletes pools and data; cannot be undone**.
  
  ```
  # ceph osd pool delete mythirdpool mythirdpool --yes-i-really-really-mean-it
  pool 'mythirdpool' removed
  ```

### List available erasure coded profiles

- Command: **`ceph osd erasure-code-profile ls default`**
  
  ```
  # ceph osd erasure-code-profile ls
  default
  ```

### Create erasure coded profile

- Command: **`ceph osd erasure-code-profile set <profile_name> k=<val> m=<val> {crush-failure-domain=<rack|host|osd>}`**

- Description: you cannot modify or change the erasure code profile of an existing pool. **Can only be used for rgw application pools.**
  
  - **`k`** -  number of data chunks that is split across OSDs. Default value is 2.
  - **`m`** - number of OSDs that can fail before the data becomes unavailable. Default value 1.
  - **`crush-failure-domain`** - defines the CRUSH failure domain, which controls chunk placement. By default it is set to **`host`**. If set to **`osd`**, then an object's chunks can be placed on OSDs on the same host; **not recommended**.
  
  ```
  # ceph osd erasure-code-profile set eck3m2fdosd k=3 m=2 crush-failure-domain=osd
  # ceph osd erasure-code-profile ls
  default
  eck3m2fdosd
  ```

### Retrieve the parameters from erasure coded profile

- Command: **`ceph osd erasure-code-profile get <erasure_code_name>`**
  
  ```
  # ceph osd erasure-code-profile get eck3m2fdosd
  crush-device-class=
  crush-failure-domain=osd
  crush-root=default
  jerasure-per-chunk-alignment=false
  k=3
  m=2
  plugin=jerasure
  technique=reed_sol_van
  w=8
  ```

### Create a new erasure coded pool with pg_num placement groups

- Command: **`ceph osd pool create <pool_name> <pg_num> erasure eck3m2fdosd`**
  
  ```
  # ceph osd pool create myecfirstpool 16 erasure eck3m2fdosd
  pool 'myecfirstpool' created
  # ceph osd pool ls detail
  ... output ommitted
  pool 4 'myecfirstpool' erasure size 5 min_size 4 crush_rule 1 object_hash rjenkins pg_num 16 pgp_num 16 last_change 142 flags hashpspool stripe_width 12288
  ```

### Remove erasure coded profile

- Command: **`ceph osd erasure-code-profile rm <profile_name>`**

- Description: the profile cannot be removed if the profile is in use by some pool.
  
  ```
  # ceph osd erasure-code-profile rm eck3m2fdosd
  # ceph osd erasure-code-profile ls
  default
  ```

## Placement Groups

Documentation: [PLACEMENT GROUPS](http://docs.ceph.com/docs/luminous/rados/operations/placement-groups/)

### List available placement groups inside the cluster

- Command: **`ceph pg ls | ls-by-osd <osd.id> |ls-by-pool <pool_name>`**

- Other options:
  
  - **`ls-by-osd <osd.id>`** - list PGs inside a specific OSD.
  - **`ls-by-pool <pool_name>`** - list PGs inside a specific pool.
  - **`ls-by-primary <osd.id>`** - lists pg with primary OSD.
  
  ```
  # ceph pg ls
  PG_STAT OBJECTS MISSING_ON_PRIMARY DEGRADED MISPLACED UNFOUND BYTES LOG DISK_LOG STATE        STATE_STAMP                VERSION REPORTED UP    UP_PRIMARY ACTING ACTING_PRIMARY LAST_SCRUB SCRUB_STAMP                LAST_DEEP_SCRUB DEEP_SCRUB_STAMP           
  1.0           0                  0        0         0       0     0   0        0 active+clean 2019-04-13 09:28:35.325724     0'0  165:254 [3,7]          3  [3,7]              3        0'0 2019-04-12 23:42:24.151493             0'0 2019-04-12 23:42:24.151493 
  ... output ommitted
  ```

### Query statistics and other metadata about a placement group

- Command: **`ceph pg <pg_id> query`**

- Description: useful information to troubleshoot, e.g. state of replicas, past events, etc.
  
  ```
  # ceph pg 1.0 query
  {
      "state": "active+clean",
      "snap_trimq": "[]",
      "snap_trimq_len": 0,
      "epoch": 166,
      "up": [
          3,
          7
      ],
      "acting": [
          3,
          7
  ... output ommitted
  ```

### List missing placement groups

- Command: **`ceph pg <pg-id> list_missing`**

- Description: if primary OSD goes down before writes are fully distributed, Ceph might miss some data (but knows it's missing some). Ceph refers to those as `missing` or `unfound` objects. In those cases it will block writes to the respective objects, in the hope the primary will come back eventually. The `list_missing` command will list those objects. You can find out more with `ceph pg {pg-id} query` about which OSDs were considered and what their state is. Note the "more" field; if it's true there are more objects which are not listed yet.
  
  ```
  # ceph pg 1.0 list_missing
  {
      "offset": {
          "oid": "",
          "key": "",
          "snapid": 0,
          "hash": 0,
          "max": 0,
          "pool": -9223372036854775808,
          "namespace": ""
      },
      "num_missing": 0, «
      "num_unfound": 0, «
      "objects": [],
      "more": false
  }
  ```

### Tells Ceph to delete missing/unfound objects, respective revert to previous versions of them

- Command: **`ceph pg <pg_id> mark_unfound_lost [<revert | delete>]`**

- Description: see [List missing placement groups](#List missing placement groups) under `list_missing` for missing/unfound objects. Note that it's up to you to deal with potential data loss. 
  
  ```
  # ceph pg 1.0 mark_unfound_lost revert
  pg has no unfound objects
  ```

### Dump statistics and metadata for all placement groups

- Command: **`ceph pg dump [--format {json,json-pretty,xml,xml-pretty,plain}]`**

- Description: dump statistics and metadata for all placement groups. Outputs info about scrubs, last replication, current OSDs, blocking OSDs, etc. Format can be plain or json. Depending on the number of placement groups, the output can potentially get large. The json output lends itself well to filtering/mangling, eg. with [jq](https://stedolan.github.io/jq/). The example uses this to extract a list of pg ids and timestamps of the last deep scrub
  
  ```
  # ceph pg dump -f json-pretty
  {
      "version": 6299,
      "stamp": "2019-04-13 12:52:51.448982",
      "last_osdmap_epoch": 0,
      "last_pg_scan": 0,
      "min_last_epoch_clean": 0,
      "full_ratio": 0.000000,
      "near_full_ratio": 0.000000,
      "pg_stats_sum": {
  ... output ommitted
  ```

### Dump stuck placement groups

- Command: **`ceph pg dump_stuck inactive | unclean | stale | undersized | degraded [--format <json,json-pretty,xml,xml-pretty,plain>] [-t|--threshold <seconds>]`**

- Description: threshold is the cutoff after which a pg is returned as stuck, with a default of 300s. The output will contain the placement group names, their full state and which OSDs hold (or held) the data. Refer to [RADOS PG states](http://docs.ceph.com/docs/luminous/rados/operations/pg-states/) for details.
  
  - **`inactive`** - inactive means they couldn't read from/written to (possibly a peering problem).
  - **`unclean `**- unclean placement groups are those that have not been able to complete recovery.
  - **`stale`** - stale pg's have not been updated by an OSD for an extended period of time; possibly all nodes which store that pg are down, overloaded or unreachable. The output will indicate which OSDs last were seen with that pg ("last acting").
  - **`undersized`** - PG has fewer copies than the configured pool replication level
  - **`degraded`** - Ceph has not replicated some objects in the placement group the correct number of times yet
  
  ```
  # ceph pg dump_stuck undersized
  ok
  ```

### Initiate a light scrub or deep scrub on the placement groups contents

- Command: **`ceph pg <scrub | deep-scrup> <pg-id>`**

- Description: this enables very fine-tuned control over what gets scrubbed when (especially useful for the resource-hungry deep scrub).
  
  ```
  # ceph pg scrub 1.f
  instructing pg 1.f on osd.3 to scrub
  # ceph pg deep-scrub 1.e
  instructing pg 1.e on osd.4 to deep-scrub
  ```

### Repair placement groups

- Command: **`ceph pg repair <pg-id>`**

- Description: if a placement group becomes `inconsistent` this indicates a possible error during scrubbing. `repair` instructs Ceph to repair that PG.
  
  ```
  # ceph pg repair 6.12
  instructing pg 6.12 on osd.7 to repair
  ```

## Daemon interaction

Documentation:

Description: the `ceph daemon` commands interact with individual daemons on the current host. Typically this is used for low-level investigation and troubleshooting. The target daemon can be specified via name, eg. `osd.1`, or as a path to a socket, eg. `/var/run/ceph/ceph-osd.0.asok`.

### Dump a json list of currently active operations for an OSD

- Command: **`ceph daemon <osd.id> dump_ops_in_flight`**

- Description: Useful if one or more ops are stuck.
  
  ```
  # ceph daemon osd.3 dump_ops_in_flight
  {
      "ops": [],
      "num_ops": 0
  }
  ```

### Print a list of commands the daemon supports

- Command: **`ceph daemon <daemon> help`**
  
  ```
  # ceph daemon osd.3 help
  {
      "calc_objectstore_db_histogram": "Generate key value histogram of kvdb(rocksdb) which used by bluestore",
      "compact": "Commpact object store's omap. WARNING: Compaction probably slows your requests",
      "config diff": "dump diff of current config and default config",
      "config diff get": "dump diff get <field>: dump diff of current and default config setting <field>",
      "config get": "config get <field>: get the config value",
      "config help": "get config setting schema and descriptions",
  ... output ommitted
  
  # ceph daemon mon.node1 help
  {
      "add_bootstrap_peer_hint": "add peer address as potential bootstrap peer for cluster bringup",
      "config diff": "dump diff of current config and default config",
      "config diff get": "dump diff get <field>: dump diff of current and default config setting <field>",
      "config get": "config get <field>: get the config value",
  ... output ommitted
  ```

### Print high level status info for this MON

- Command: **`ceph daemon <mon.id> mon_status`**
  
  ```
  # ceph daemon mon.node1 mon_status
  {
      "name": "node1",
      "rank": 2,
      "state": "peon",
      "election_epoch": 52,
      "quorum": [
          0,
          1,
          2
  ... output ommitted
  ```

### Print high level status info for this OSD

- Command: **`ceph daemon <osd.id> status`**
  
  ```
  # ceph daemon osd.1 status
  {
      "cluster_fsid": "ad38f543-01d5-464f-b3db-8d8c818af9e0",
      "osd_fsid": "718f8e93-207c-4003-9212-e52a558d73ce",
      "whoami": 1,
      "state": "active",
      "oldest_map": 1,
      "newest_map": 106,
      "num_pgs": 29
  }
  ```

### Print performance statistic

- Command: **`ceph daemon <osd.id|mon.id|radosgw> perf dump`**
  
  ```
  # ceph daemon mon.node1 perf dump
  {
      "AsyncMessenger::Worker-0": {
          "msgr_recv_messages": 13701,
          "msgr_send_messages": 9513,
          "msgr_recv_bytes": 25737096,
          "msgr_send_bytes": 11840051,
          "msgr_created_connections": 8,
          "msgr_active_connections": 7,
  ... output ommitted
  ```

## Authentication and Authorization

- Subcommands: **`ceph auth`**
- Description: very briefly about users (typically non-human) and perms. Check [docs on keyring management](http://docs.ceph.com/docs/luminious/rados/operations/user-management/#keyring-management) when adding or deleting users.

### List users

- Command: **`ceph auth list`**
  
  ```
  # ceph auth list
  installed auth entries:
  
  osd.0
      key: AQCdXKtctzzeOBAAXOzfMBiAUhRtfgXT3diVDg==
      caps: [mgr] allow profile osd
      caps: [mon] allow profile osd
      caps: [osd] allow *
  ... output ommitted
  ```

### Get specific user information

- Command: **`ceph auth get client.<user_name>`**
  
  ```
  # ceph auth get client.lorena
  exported keyring for client.lorena
  [client.lorena]
      key = AQCr0bRci1BrDBAAPvr5KdC5rJXGhu7OE3c9qQ==
      caps mds = "allow *"
      caps mon = "allow *"
      caps osd = "allow *"
  ```

### Get user details or create the user if it doesn't exist

- Command: **`ceph auth get-or-create client.<user_name> { -o /etc/ceph/ceph.client.<user_name>.keyring }`**
  
  ```
  # ceph auth get-or-create client.lorena mon 'allow r' osd 'allow rw pool=myfourthpool' -o /etc/ceph/ceph.client.lorena.keyring
  [client.lorena]
      key = AQCr0bRci1BrDBAAPvr5KdC5rJXGhu7OE3c9qQ==
  # ceph auth list
  ... output ommitted
  client.lorena
      key: AQCr0bRci1BrDBAAPvr5KdC5rJXGhu7OE3c9qQ==
      caps: [mon] allow r
      caps: [osd] allow rw pool=myfourthpool
  ... output ommitted
  ```

### Add or remove permissions for a user

- Command: **`ceph auth caps`**

- Description: permissions are grouped per daemon type (eg. mon, osd, mds). Capabilities can be 'r', 'w', 'x' or '*'. For OSDs capabilities can also be restricted per pool (note if no pool is specified the caps apply to **all pools**). For details refer to [the docs](http://docs.ceph.com/docs/luminous/rados/operations/user-management/). The example makes `lorena` an administrator.
  
  ```
  # ceph auth caps client.lorena mon 'allow *' osd 'allow *' mds 'allow *'
  updated caps for client.lorena
  # ceph auth get client.lorena
  exported keyring for client.lorena
  [client.lorena]
      key = AQCr0bRci1BrDBAAPvr5KdC5rJXGhu7OE3c9qQ==
      caps mds = "allow *"
      caps mon = "allow *"
      caps osd = "allow *"
  ```

### Add profiles to set capabilities

- Command: **`ceph auth get-or-create`**

- Description: cephx offers predefined capability profiles. Administrators can use them when creating user
  
  accounts to simplify configuration of user access rights. The following command uses the rbd profile to define the access rights for the new `rbdaccess`. A client application can then use this account for block-based access to Ceph storage using a RADOS Block Device. The **`rbd-read-only profile`** works the same way but grants read-only access. Ceph uses the other existing profiles for internal communication between daemons.
  
  ```
  # ceph auth get-or-create client.rbdaccess mon 'profile rbd' osd 'profile rbd'
  [client.rbdaccess]
      key = AQA12LRcpFC0KBAA93tdUEulXg+I6NM7NQpPtg==
  # ceph auth get client.rbdaccess
  exported keyring for client.rbdaccess
  [client.rbdaccess]
      key = AQA12LRcpFC0KBAA93tdUEulXg+I6NM7NQpPtg==
      caps mon = "profile rbd"
      caps osd = "profile rbd"
  ```

### Restrict access to pools

- Command: **`ceph auth get-or-create`**

- Description: restrict user OSD permissions such that users can only access the pools they need. The
  
  following command creates the `formypool2` user and limits their access to read and write on the `mysecondpool` pool.
  
  ```
  # ceph auth get-or-create client.sencondpoolmgr mon 'allow r' osd 'allow rw pool=mysecondpool'
  [client.formypool2]
      key = AQAZ2LRcKSFJOBAAB/xvxIxaEqb6ihMTS2VyfA==
  # ceph auth list
  ... output ommitted
  client.formypool2
      key: AQAZ2LRcKSFJOBAAB/xvxIxaEqb6ihMTS2VyfA==
      caps: [mon] allow r
      caps: [osd] allow rw pool=mysecondpool
  ... output ommitted
  ```

### Restrict access to object name prefix

- Command: **`ceph auth get-or-create`**

- Description: By object name prefix. The following example restricts access to only those objects whose names
  
  start with `pref_` in any pool.
  
  ```
  # ceph auth get-or-create client.developer mon 'allow r' osd 'allow rw object_prefix pref_'
  ```

### Restrict access to namespace prefix

- Command: **`ceph auth get-or-create`**

- Description: by `namespace`. Applications can use namespaces to logically group objects within a pool. Administrators can then restrict user accounts to objects belonging to a specific `namespace`.
  
  ```
  # ceph auth get-or-create client.vdeditor mon 'allow r' osd 'allow rw namespace=video'
  ```

### Restrict access by path (CephFS)

- Command: **`ceph fs authorize cephfs`**
  
  ```
  # ceph fs authorize cephfs client.webdesigner /webcontent rw
  # ceph auth get client.webdesigner
  exported keyring for client.webdesigner
  [client.webdesigner]
  key = AQBrVE9aNwoEGRAApYR6m71ECRzUlLpp4wEJkw==
  caps mds = "allow rw path=/webcontent"
  caps mon = "allow r"
  caps osd = "allow rw pool=cephfs_data"
  ```

### Restrict access monitor command

- Command:
  
  ```
  # ceph auth get-or-create client.operator mon 'allow r, allow command "auth get-or-create", allow command "auth list"'
  ```

### Delete a user (client.user)

- Command: **`ceph auth delete`**
  
  ```
  # ceph auth del client.operator
  ```

## RADOS Object Store Utility

Documentation: [RADOS OBJECT STORAGE UTILITY](http://docs.ceph.com/docs/luminous/man/8/rados/)

### Upload a file into a pool, name the resulting obj. Give '-' as a file name to read from stdin

- Command: **`rados -p <pool> put <obj> <file>`**
  
  ```
  # rados -p mysecondpool put myfile01 /etc/group
  # ceph df
  GLOBAL:
      SIZE       AVAIL      RAW USED     %RAW USED 
      359GiB     347GiB      12.2GiB          3.41 
  POOLS:
      NAME             ID     USED        %USED     MAX AVAIL     OBJECTS 
      myfirstpool      1      4.47MiB         0        110GiB           7 
      mysecondpool     2         661B         0        164GiB           1 <--
      mythirdpool      3           0B         0        164GiB           0 
      myfourthpool     4           0B         0        164GiB           0 
  ```

### List objects in a pool

- Command: **`rados -p <pool> ls`**
  
  ```
  # rados -p mysecondpool ls
  myfile01
  ```

### Download an object from a pool into a local file

- Command: **`rados -p <pool> get <obj> <file>`**

- Description: use `-` as file name to write to **`stdout`**.
  
  ```
  # rados -p mysecondpool get myfile01 myfile01.out
  # tail -n3 myfile01.out 
  vagrant:x:1000:vagrant
  cephuser:x:1001:
  ceph:x:167:
  ```

### List watchers of an object in pool

- Command: **`rados -p <pool> listwatchers <obj>`**

- Description: for instance, the head object of a mapped rbd volume has it's clients as watchers.
  
  ```
  # rados -p myrbdpool listwatchers myfirstvol.rbd
  watcher=192.168.121.25:0/330978585 client.173295 cookie=1
  ```

### Delete an object from a pool

- Command: **`rados -p <pool> rm <obj>`**
  
  ```
  # rados -p mysecondpool rm myfile01
  # ceph df
  GLOBAL:
      SIZE       AVAIL      RAW USED     %RAW USED 
      359GiB     347GiB      12.2GiB          3.41 
  POOLS:
      NAME             ID     USED        %USED     MAX AVAIL     OBJECTS 
      myfirstpool      1      4.47MiB         0        110GiB           7 
      mysecondpool     2           0B         0        164GiB           0 «
      mythirdpool      3           0B         0        164GiB           0 
      myfourthpool     4           0B         0        164GiB           0 
  ```

### Run the built-in benchmark for given length in secs

- Command: **`rados bench <seconds> <mode> [ -b objsize ] [ -t threads ]-p <pool_name>`** 

- Description: the `mode` can be:
  
  - **`write`** -  before running one of the reading benchmarks, run a write benchmark with the `--no-cleanup` option. The default object size is 4 MB, and the default number of simulated threads (parallel writes) is 16. **Warning** this will write a bunch of files inside the pool.
  - **`seq`** - sequential read benchmarks.
  - **`rand`** - random read benchmarks.
  
  ```
  # rados bench -t 16 -p bench 5 write --no-cleanup -p mysecondpool
  hints = 1
  Maintaining 16 concurrent writes of 4194304 bytes to objects of size 4194304 for up to 5 seconds or 0 objects
  Object prefix: benchmark_data_node1_8824
    sec Cur ops   started  finished  avg MB/s  cur MB/s last lat(s)  avg lat(s)
      0      16        16         0         0         0           -           0
      1      16        59        43   161.556       172    0.207395    0.368408
      2      16        95        79   153.033       144    0.408148    0.377905
      3      16       127       111   144.846       128    0.360091    0.387742
      4      16       128       112   110.191         4     1.00608    0.393263
      5      16       145       129   101.856        68    0.120534    0.593063
  Total time run:         5.223161
  Total writes made:      146
  Write size:             4194304
  Object size:            4194304
  Bandwidth (MB/sec):     111.81
  Stddev Bandwidth:       67.2547
  Max bandwidth (MB/sec): 172
  Min bandwidth (MB/sec): 4
  Average IOPS:           27
  Stddev IOPS:            16
  Max IOPS:               43
  Min IOPS:               1
  Average Latency(s):     0.571748
  Stddev Latency(s):      0.524406
  Max latency(s):         2.10202
  Min latency(s):         0.0855182
  # rados -p mysecondpool ls|head
  benchmark_data_node1_8824_object3
  benchmark_data_node1_8824_object5
  benchmark_data_node1_8719_object254
  benchmark_data_node1_8719_object242
  benchmark_data_node1_8824_object132
  ... output ommitted
  ```

### Clean up a previous benchmark operation

- Command: **`rados cleanup [ --run-name run_name ] [ --prefix prefix ] -p <pool_name>`**

- Description: the default run-name is `benchmark_last_metadata`.
  
  ```
  # rados cleanup --run-name benchmark_data -p mysecondpool
  Warning: using slow linear search
  Removed 844 objects
  # rados -p mysecondpool ls
  myfile01
  benchmark_last_metadata
  ```

## RBD RADOS Block Device

Documentation: [CEPH BLOCK DEVICE](http://docs.ceph.com/docs/luminous/rbd/)

### Create RBD volume inside a pool

- Command: **`rbd create <pool/volume_name> --size <integer>M|G|T`**

- Description: create an RBD  volume. The pool application must be `rbd`. Instead of **`pool_name/volume_name`** it can also be **`-p pool volume_name`**. **Note**: **`[pool_name/] `** optional only if **`rbd`** exists, otherwise you must enter a valid name.
  
  ```
  # rbd create mysecondpool/myfirstvol --size 10M
  # rbd create -p mysecondpool mysecondvol --size 10M
  # rados -p mysecondpool ls
  myfile01
  rbd_directory
  rbd_info
  rbd_id.myfirstvol
  rbd_header.10d76b8b4567
  rbd_header.10d96b8b4567
  rbd_id.mysecondvol
  ```

### List RBD volumes inside a pool

- Command: **`rbd ls <pool_name>`**
  
  ```
  # rbd ls mysecondpool
  myfirstvol
  mysecondvol
  ```

### Map RBD volume or snapshot to a block device on the local machine

- Command: **`rbd map [--read-only] <volume-or-snapshot>`**
  
  ```
  # rbd map mysecondpool/myfirstvol
  /dev/rbd0
  ```

### Show mapped volumes / snapshots

- Command: **`rbd showmapped`**
  
  ```
  # rbd showmapped
  id pool         image      snap device    
  0  mysecondpool myfirstvol -    /dev/rbd0 
  # mkfs.ext4 /dev/rbd0
  # blkid /dev/rbd0 
  /dev/rbd0: UUID="20ceb484-2286-428e-9d47-c837903dd0a9" TYPE="ext4"
  ```

### Show mapping status of a given volume

- Command: **`rbd status [pool_name/]<volume_name>`**
  
  ```
  # rbd status mysecondpool/myfirstvol
  Watchers:
      watcher=192.168.121.249:0/96758500 client.64146 cookie=18446462598732840961
  ```

### Print some metadata information of a given volume

- Command: **`rbd info [pool_name/]<volume_name>`**
  
  ```
  # rbd info mysecondpool/myfirstvol
  rbd image 'myfirstvol':
      size 10MiB in 3 objects
      order 22 (4MiB objects)
      block_name_prefix: rbd_data.10d96b8b4567
      format: 2
      features: layering
      flags: 
      create_timestamp: Fri May 10 22:16:23 2019
  ```

### Retrieve provisioned and actual disk usage for RBD volumes

- Command: **`rbd du [pool_name/]<volume_name>`**
  
  ```
  # rbd du mysecondpool/myfirstvol
  warning: fast-diff map is not enabled for myfirstvol. operation may be slow.
  NAME       PROVISIONED USED 
  myfirstvol       10MiB   0B 
  ```

### Resize an RBD volume

- Command: **`rbd resize [pool_name/]<volume_name> --size <integer>M|G|T`**
  
  ```
  # rbd resize mysecondpool/myfirstvol --size 30M
  Resizing image: 100% complete...done.
  # rbd du mysecondpool/myfirstvol
  warning: fast-diff map is not enabled for myfirstvol. operation may be slow.
  NAME       PROVISIONED USED 
  myfirstvol       30MiB   0B 
  ```

### Copy an RBD volume

- Command: **`rbd cp [pool_name/]<source_vol_name> [pool_name/]<target_vol_name>`**
  
  ```
  # rbd cp mysecondpool/myfirstvol mysecondpool/copy-myfirstvol
  Image copy: 100% complete...done.
  # rbd ls mysecondpool
  copy-myfirstvol
  myfirstvol
  mysecondvol
  ```

### Rename an RBD volume

- Command: **`rbd mv [pool_name/]<source_vol_name> [pool_name/]<new_vol_name>`**
  
  ```
  # rbd mv mysecondpool/copy-myfirstvol mysecondpool/renamed-myfirstvol
  # rbd ls mysecondpool
  myfirstvol
  mysecondvol
  renamed-myfirstvol
  ```

### Move an RBD volume to trash

- Command: **`rbd trash mv [pool_name/]<volume_name>`**
  
  ```
  # rbd trash mv mysecondpool/renamed-myfirstvol
  ```

### List contents inside the pool's trash

- Command: **`rbd trash ls [pool_name/]<volume_name>`**
  
  ```
  # rbd trash ls mysecondpool
  faa76b8b4567 renamed-myfirstvol
  ```

### Restore an RBD volume from trash

- Command: **`rbd trash restore [pool_name/]<volume_trash_id>`**
  
  ```
  # rbd trash restore mysecondpool/faa66b8b4567
  ```

### Delete an RBD volume from trash

- Command: **`rbd trash rm [pool_name/]<volume_trash_id>`**
  
  ```
  # rbd trash rm mysecondpool/faa76b8b4567
  Removing image: 100% complete...done.
  ```

### Export volume to local file

- Command: **`rbd export <pool/volume_name> <destination_file>`**
  
  ```
  # rbd export mysecondpool/myfirstvol export_vol.img
  Exporting image: 100% complete...done.
  # ls -lh export_vol.img
  -rw-r--r--. 1 cephuser cephuser 30M May 14 13:16 export_vol.img
  ```

### Import RBD volume from local file

- Command: **`rbd export <destination_file> [pool_name/]<volume_name>`**
  
  ```
  # rbd import export_vol.img mysecondpool/imported_volume
  Importing image: 100% complete...done.
  # rbd ls mysecondpool
  imported_volume
  myfirstvol
  mysecondvol
  renamed-myfirstvol
  ```

### Unmap a mapped rbd device

- Command: **`rbd unmap <device>`**
  
  ```
  # rbd unmap /dev/rbd0
  # rbd showmapped
  ```

### Delete a volume

- Command: **`rbd rm [pool_name/]<volume_name>`**
  
  ```
  # rbd rm mysecondpool/imported_volume
  Removing image: 100% complete...done.
  # rbd ls mysecondpool
  myfirstvol
  mysecondvol
  ```

### Enable RBD snapshot or clone

- Command: **`rbd feature enable [pool_name/]<volume_name> <feature_name>`**

- Description: the RBD image format 2 supports several optional features. Use the **`rbd feature enable`** to enable
  
  features on an RBD image, and use the **`rbd feature disable`** to disable a feature.
  
  - **`layering`** - layering support to enable cloning.
  - **`striping`** - striping v2 support for enhanced performance. Currently only supported by `librbd`.
  - **`exclusive-lock`** - exclusive locking support.
  - **`object-map`** - object map support (requires exclusive-lock).
  - **`fast-diff`** - fast diff command support (requires `object-map` **and** `exclusive-lock`).
  - **`deep-flatten`** - flattens all snapshots of the RBD image.
  - **`journaling`** - journaling support.
  - **`data-pool`** - EC data pool support.
  
  ```
  # rbd feature enable mysecondpool/mythirdvol exclusive-lock
  # rbd info mysecondpool/mythirdvol
  rbd image 'mythirdvol':
      size 100MiB in 25 objects
      order 22 (4MiB objects)
      block_name_prefix: rbd_data.faf06b8b4567
      format: 2
  »    features: layering, exclusive-lock
      flags: 
      create_timestamp: Tue May 14 13:59:38 2019
  ```

### Create snapshot

- Command: **`rbd snap create [pool_name/]<volume_name><@snap_name>`**
  
  ```
  # rbd snap create mysecondpool/mythirdvol@snap1_mythirdpool
  ```

### List snapshots

- Command: **`rbd snap ls [pool_name/]<volume_name>`**
  
  ```
  # rbd snap ls mysecondpool/mythirdvol
  SNAPID NAME                SIZE TIMESTAMP                
       4 snap1_mythirdpool 100MiB Tue May 14 14:02:28 2019 
  ```

### Limit the number of snapshots

- Command: **`rbd snap limit set --limit <integer> [pool_name/]<volume_name> `**
  
  ```
  # rbd snap limit set --limit 3 mysecondpool/mythirdvol
  # rbd info mysecondpool/mythirdvol
  rbd image 'mythirdvol':
      size 100MiB in 25 objects
      order 22 (4MiB objects)
      block_name_prefix: rbd_data.faf06b8b4567
      format: 2
      features: layering, exclusive-lock
      flags: 
      create_timestamp: Tue May 14 13:59:38 2019
  »    snapshot_limit: 3
  # rbd snap create mysecondpool/mythirdvol@snap2_mythirdpool
  # rbd snap create mysecondpool/mythirdvol@snap3_mythirdpool
  # rbd snap create mysecondpool/mythirdvol@snap4_mythirdpool
  rbd: failed to create snapshot: (122) Disk quota exceeded
  ```

### Remove the limit on the number of snapshots

- Command: **`rbd snap limit clear [pool_name/]<volume_name>`**
  
  ```
  # rbd snap limit clear mysecondpool/mythirdvol
  # rbd info mysecondpool/mythirdvol
  rbd image 'mythirdvol':
      size 100MiB in 25 objects
      order 22 (4MiB objects)
      block_name_prefix: rbd_data.faf06b8b4567
      format: 2
      features: layering, exclusive-lock
      flags: 
      create_timestamp: Tue May 14 13:59:38 2019
  ```

### Rename snapshot

- Command: **`rbd snap rename [pool_name/]<volume_name><@old_snap_name> [pool_name/]<volume_name><@new_snap_name>`**
  
  ```
  # rbd snap rename mysecondpool/mythirdvol@snap3_mythirdpool mysecondpool/mythirdvol@renamed-snap3_mythirdpool
  # rbd snap ls mysecondpool/mythirdvol
  SNAPID NAME                        SIZE TIMESTAMP                
       4 snap1_mythirdpool         100MiB Tue May 14 14:02:28 2019 
       5 snap2_mythirdpool         100MiB Tue May 14 14:04:19 2019 
       6 renamed-snap3_mythirdpool 100MiB Tue May 14 14:04:23 2019 
  ```

### Delete a snapshot

- Command: **`rbd snap rm [pool_name/]volume_name@snap_name>`**
  
  ```
  # rbd snap rm mysecondpool/mythirdvol@renamed-snap3_mythirdpool
  Removing snap: 100% complete...done.
  ```

### Purge snapshots (delete all snapshots)

- Command: **`rbd snap purge [pool_name/]<volume_name>`**
  
  ```
  # rbd snap purge mysecondpool/mythirdvol
  Removing all snapshots: 100% complete...done.
  # rbd snap ls mysecondpool/mythirdvol
  ```

### Rollback image to snapshot

- Command: **`rbd snap rollback [pool_name/]<volume_name><@snap_name>`**
  
  ```
  # rbd snap ls mysecondpool/mythirdvol
  SNAPID NAME                SIZE TIMESTAMP                
      12 snap1_mythirdpool 100MiB Tue May 14 14:09:34 2019
  # rbd snap rollback mysecondpool/mythirdvol@snap1_mythirdpool
  Rolling back to snapshot: 100% complete...done.
  ```

### Protect snapshot

- Command: **`rbd snap protect [pool_name/]<volume_name><@snapshot_name>`**
  
  ```
  # rbd snap protect mysecondpool/mythirdvol@snap1_mythirdpool
  # rbd info mysecondpool/mythirdvol@snap1_mythirdpool
  rbd image 'mythirdvol':
      size 100MiB in 25 objects
      order 22 (4MiB objects)
      block_name_prefix: rbd_data.faf06b8b4567
      format: 2
      features: layering, exclusive-lock
      flags: 
      create_timestamp: Tue May 14 13:59:38 2019
  »    protected: True
  # rbd snap rm mysecondpool/mythirdvol@snap1_mythirdpool
  Removing snap: 0% complete...failed.
  rbd: snapshot 'snap1_mythirdpool' is protected from removal.
  2019-05-14 14:14:27.814097 7f6994215d40 -1 librbd::Operations: snapshot is protected
  ```

### Unprotect snapshot

- Command: **`rbd snap unprotect [pool_name/]volume_name@snapshot_name`**
  
  ```
  # rbd snap unprotect mysecondpool/mythirdvol@snap1_mythirdpoo
  # rbd info mysecondpool/mythirdvol@snap1_mythirdpool
  rbd image 'mythirdvol':
      size 100MiB in 25 objects
      order 22 (4MiB objects)
      block_name_prefix: rbd_data.faf06b8b4567
      format: 2
      features: layering, exclusive-lock
      flags: 
      create_timestamp: Tue May 14 13:59:38 2019
  »    protected: False
  ```

### Clone RBD volume

- Command: **`rbd clone <pool_name/><volume_name>@<snap_name> <pool_name/><clone_name>`**

- Description: the RBD clone has 3 steps:
  
  1. Create a snapshot
  2. Protect the snapshot from removal
  3. Create the clone using the protected snapshot
  
  Once the clone is created, it behaves just like a regular RBD volume.
  
  ```
  # rbd snap create mysecondpool/mythirdvol@snap5_mythirdpool
  # rbd snap protect mysecondpool/mythirdvol@snap5_mythirdpool
  # rbd clone mysecondpool/mythirdvol@snap5_mythirdpool myfirstpool/clone_snap5_mythirdpool
  # rbd info myfirstpool/clone_snap5_mythirdpool
  rbd image 'clone_snap5_mythirdpool':
      size 100MiB in 25 objects
      order 22 (4MiB objects)
      block_name_prefix: rbd_data.fb336b8b4567
      format: 2
      features: layering, exclusive-lock
      flags: 
      create_timestamp: Tue May 14 14:21:52 2019
  »    parent: mysecondpool/mythirdvol@snap5_mythirdpool
      overlap: 100Mi
  ```

### List RBD clones

- Command: **`rbd children [pool_name/]<volume_name><@snapshot_name>`**
  
  ```
  # rbd children mysecondpool/mythirdvol@snap5_mythirdpool
  myfirstpool/clone_snap5_mythirdpool
  
  # rbd clone mysecondpool/mythirdvol@snap5_mythirdpool myfirstpool/clone1_snap5_mythirdpool
  # rbd clone mysecondpool/mythirdvol@snap5_mythirdpool myfirstpool/clone2_snap5_mythirdpool
  
  # rbd children mysecondpool/mythirdvol@snap5_mythirdpool
  myfirstpool/clone1_snap5_mythirdpool
  myfirstpool/clone2_snap5_mythirdpool
  myfirstpool/clone_snap5_mythirdpool
  ```

### Flatten RBD clone

- Command: **`rbd flatten [pool_name/]<child_volume_name>`**

- Description: when a clone is flattened, all missing data is copied from the parent into the clone and, the reference to the parent is removed at the end of this process. The clone then becomes an independent RBD volume and is no longer the child of a protected snapshot. Note that `parent:` field doesn't show in **`rbd info [pool_name/]<volume_name>`**.
  
  ```
  # rbd flatten myfirstpool/clone_snap5_mythirdpool
  Image flatten: 100% complete...done.
  # rbd children mysecondpool/mythirdvol@snap5_mythirdpool
  myfirstpool/clone1_snap5_mythirdpool
  myfirstpool/clone2_snap5_mythirdpool
  # rbd info myfirstpool/clone_snap5_mythirdpool
  rbd image 'clone_snap5_mythirdpool':
      size 100MiB in 25 objects
      order 22 (4MiB objects)
      block_name_prefix: rbd_data.fb336b8b4567
      format: 2
      features: layering, exclusive-lock
      flags: 
      create_timestamp: Tue May 14 14:21:52 2019
  ```

## RGW RADOS Gateway Object Storage

Documentation: [CEPH OBJECT GATEWAY](http://docs.ceph.com/docs/luminous/radosgw/)

- The Ceph deploy process creates default RGW pools.
  
  ```
  # ceph osd pool ls detail
  pool 1 '.rgw.root' replicated size 2 min_size 1 crush_rule 0 object_hash rjenkins pg_num 8 pgp_num 8 last_change 50 flags hashpspool stripe_width 0 application rgw
  pool 2 'default.rgw.control' replicated size 2 min_size 1 crush_rule 0 object_hash rjenkins pg_num 8 pgp_num 8 last_change 54 flags hashpspool stripe_width 0 application rgw
  pool 3 'default.rgw.meta' replicated size 2 min_size 1 crush_rule 0 object_hash rjenkins pg_num 8 pgp_num 8 last_change 56 flags hashpspool stripe_width 0 application rgw
  pool 4 'default.rgw.log' replicated size 2 min_size 1 crush_rule 0 object_hash rjenkins pg_num 8 pgp_num 8 last_change 58 flags hashpspool stripe_width 0 application rgw
  ```

### Create rados REST gateway user

- Command:  **`radosgw-admin user create <--uid=uid> <--display-name="Display Name"> [--email=user@domain] [--access-key=string] [--secret=string]`**

- Description: when creating RADOS Gateway users **`--uid`** and **`--display-name`** options are required. If not specified, `--access-key` and `--secret` are automatically generated.
  
  - **`--uid=`** - the radosgw user ID
  - **`--display-name=`** -  display name of the user
  - **`--email=`** - the e-mail address of the user
  - **`--access-key=`** - S3 access key
  - **`--secret=`** - the secret associated with a given key

- This method is Amazon S3 API compatible, a created user can use RGW with any S3 client namely **`s3cmd`**. See [Working with Openstack Swift API](#Working with Openstack Swift API) for Swift compatible users (subusers).
  
  ```
  # radosgw-admin user create --uid=myfirstgwuser --display-name="Firstgw User" --email=firstgwuser@example.com --access-key=1234 --secret=5678
  {
    "user_id": "myfirstgwuser", «
      "display_name": "Firstgw User", «
      "email": "firstgwuser@example.com",
      "suspended": 0,
      "max_buckets": 1000,
      "auid": 0,
      "subusers": [],
      "keys": [
          {
              "user": "myfirstgwuser",
              "access_key": "1234", «
              "secret_key": "5678" «
          }
  ... output ommitted
  
  # radosgw-admin user create --uid=mysecondgwuser --display-name="Secondgw User" --email=secondgwuser@example.com
  {
      "user_id": "mysecondgwuser",
      "display_name": "Secondgw User",
      "email": "secondgwuser@example.com",
      "suspended": 0,
      "max_buckets": 1000,
      "auid": 0,
      "subusers": [],
      "keys": [
          {
              "user": "mysecondgwuser",
              "access_key": "KJRUCR9MJ6RRE8903EVW", «
              "secret_key": "cUPDbCjGOlAOdmClODPke1IiotSdlLbMseCCGg6B" «
          }
  ... output ommitted
  ```

### Create user with administrator capabilities

- Command: **`radosgw-admin user create <--uid=uuid> --display-name="Admin User" --caps="users=read,write;usage=read,write; buckets=read,write;zone=read,write" [--access-key=string] [--secret=string]`**

- Description: **`--caps=<caps>`** - list of caps e.g., `usage=read, write; user=read`.
  
  - **`caps="users=read,write"`** - read/write permission to change users
  - **`caps="buckets=read,write"`** -  read/write permission to change buckets
  - **`caps="zones=read,write"`** - read/write permission to change zones
  
  ```
  # radosgw-admin user create --uid=admin --display-name="Admin User" --caps="users=read,write;usage=read,write; buckets=read,write;zone=read,write" --access-key="qwertyu" --secret="asdfgh"
  {
      "user_id": "admin",
      "display_name": "Admin User",
      "email": "",
      "suspended": 0,
      "max_buckets": 1000,
      "auid": 0,
      "subusers": [],
      "keys": [
          {
              "user": "admin",
              "access_key": "qwertyu",
              "secret_key": "asdfgh"
          }
      ],
      "swift_keys": [],
      "caps": [
          {
              "type": "buckets",
              "perm": "*"
          },
          {
              "type": "usage",
              "perm": "*"
          },
          {
              "type": "users",
              "perm": "*"
          },
          {
              "type": "zone",
              "perm": "*"
          }
      ],
      "op_mask": "read, write, delete",
      "default_placement": "",
      "placement_tags": [],
      "bucket_quota": {
          "enabled": false,
          "check_on_raw": false,
          "max_size": -1,
          "max_size_kb": 0,
          "max_objects": -1
      },
      "user_quota": {
          "enabled": false,
          "check_on_raw": false,
          "max_size": -1,
          "max_size_kb": 0,
          "max_objects": -1
      },
      "temp_url_keys": [],
      "type": "rgw"
  }
  ```

### Remove user capabilities

- Command: **`radosgw-admin caps rm <--uid=uid>`**
  
  ```
  # radosgw-admin caps rm --uid=admin --caps="users=read"
  ... output ommitted
      "keys": [
          {
              "user": "admin",
              "access_key": "qwertyu",
              "secret_key": "asdfgh"
          }
      ],
      "swift_keys": [],
      "caps": [
          {
              "type": "buckets",
              "perm": "*"
          },
          {
              "type": "usage",
              "perm": "*"
          },
          {
              "type": "users",
              "perm": "write" « only write remains
          },
          {
              "type": "zone",
              "perm": "*"
          }
      ],
  ... output ommitted
  ```

### Add user capabilities

- Command: **`radosgw-admin caps add <--uid=uid>`**
  
  ```
  # radosgw-admin caps add --uid=admin --caps="users=read"
  ... output ommitted
      "keys": [
          {
              "user": "admin",
              "access_key": "qwertyu",
              "secret_key": "asdfgh"
          }
      ],
      "swift_keys": [],
      "caps": [
          {
              "type": "buckets",
              "perm": "*"
          },
          {
              "type": "usage",
              "perm": "*"
          },
          {
              "type": "users",
              "perm": "*"     « read and write added
          },
          {
              "type": "zone",
              "perm": "*"
          }
      ],
  ... output ommitted
  ```

### List available users

- Command: **`radosgw-admin user list`**
  
  ```
  # radosgw-admin user list
  [
      "mysecondgwuser",
      "myfirstgwuser"
  ]
  ```

### Get user information

- Command: **`radosgw-admin user info <--uid=uid>`**
  
  ```
  # radosgw-admin user info --uid=mysecondgwuser
  {
      "user_id": "mysecondgwuser",
      "display_name": "Secondgw User",
      "email": "secondgwuser@example.com",
      "suspended": 0,
      "max_buckets": 1000,
      "auid": 0,
      "subusers": [],
      "keys": [
          {
              "user": "mysecondgwuser",
              "access_key": "KJRUCR9MJ6RRE8903EVW",
              "secret_key": "cUPDbCjGOlAOdmClODPke1IiotSdlLbMseCCGg6B"
          }
      ],
      "swift_keys": [],
      "caps": [],
      "op_mask": "read, write, delete",
      "default_placement": "",
      "placement_tags": [],
      "bucket_quota": {
          "enabled": false,
          "check_on_raw": false,
          "max_size": -1,
          "max_size_kb": 0,
          "max_objects": -1
      },
      "user_quota": {
          "enabled": false,
          "check_on_raw": false,
          "max_size": -1,
          "max_size_kb": 0,
          "max_objects": -1
      },
      "temp_url_keys": [],
      "type": "rgw"
  }
  ```

### Retrieve user statistics

- Command: **`radosgw-admin user stats <--uid=uid>`**
  
  ```
  # radosgw-admin user stats --uid=myawsuser
  {
      "stats": {
          "total_entries": 1,
          "total_bytes": 10485760,
          "total_bytes_rounded": 10485760
      },
      "last_stats_sync": "0.000000",
      "last_stats_update": "2019-05-31 20:20:58.827668Z"
  }
  ```

### Retrieve the latest user statistics

- Command: **`radosgw-admin user stats <--uid=uid> --sync-stats`**
  
  ```
  # radosgw-admin user stats --uid=myfourthuser --sync-stats
  {
      "stats": {
          "total_entries": 0,
          "total_bytes": 0,
          "total_bytes_rounded": 0
      },
      "last_stats_sync": "2019-05-30 21:13:47.127377Z",
      "last_stats_update": "0.000000"
  }
  ```

### Modify user

- Command: **`radosgw-admin user modify <--uid=uid> <--option_name=option_new_value>`**
- Description: Modify user attributes. If you want to modify the `--email=user@domain` to another value, just add the option you want to modify and its new value.
  
  ```
  # radosgw-admin user modify --uid=mysecondgwuser --display_name="My name is Jeff"
  {
      "user_id": "mysecondgwuser",
      "display_name": "My name is Jeff", «
      "email": "secondgwuser@example.com",
      "suspended": 0,
      "max_buckets": 1000,
      "auid": 0,
      "subusers": [],
      "keys": [
  ... output ommitted
  ```

### Suspend user

- Command: **`radosgw-admin user suspend <--uid=uid>`**
- Description: suspend (block) a user
  
  ```
  # radosgw-admin user suspend --uid=mysecondgwuser
  {
      "user_id": "mysecondgwuser",
      "display_name": "My name is Jeff",
      "email": "secondgwuser@example.com",
      "suspended": 1, «
      "max_buckets": 1000,
      "auid": 0,
      "subusers": [],
      "keys": [
          {
              "user": "mysecondgwuser",
              "access_key": "KJRUCR9MJ6RRE8903EVW",
              "secret_key": "cUPDbCjGOlAOdmClODPke1IiotSdlLbMseCCGg6B"
          }
      ],
  ... output ommitted
  ```

### Enable user

- Command: **`radosgw-admin user suspend <--uid=uid>`**
- Description: re-enable user after suspension
  
  ```
  # radosgw-admin user enable --uid=mysecondgwuser
  {
      "user_id": "mysecondgwuser",
      "display_name": "My name is Jeff",
      "email": "secondgwuser@example.com",
      "suspended": 0, «
      "max_buckets": 1000,
      "auid": 0,
      "subusers": [],
  ... output ommitted
  ```

### Remove user

- Command:
  
  ```
  # radosgw-admin user rm --uid=mysecondgwuser
  # radosgw-admin user list
  [
      "myfirstgwuser"
  ]
  ```

### Create a user key

- Command: **`radosgw-admin key create <--uid=uid> <--key-type= swift | s3> [--access-key=key] [--secret=secret]`**

- Description: access keys consist of two parts: an access key ID and a secret access key. You use access keys to sign programmatic requests that you make to AWS if you use AWS CLI commands (using the SDKs) or using AWS API operations. You must use both the access key ID and secret access key together to authenticate requests. Manage your access keys as securely as you do your user name and password.
  
  - **`--access-key=`** - must be unique; different for each user.
  - **`--secret=`** - must be unique; different for each user.
  - **`--gen-access-key=`** - generates a random access key.
  - **`--gen-secret=`** - generates a random secret.
  
  ```
  # radosgw-admin key create --uid=myfourthgwuser --gen-access-key
  {
      "user_id": "myfourthgwuser",
      "display_name": "Fourth User",
      "email": "fourthuser",
      "suspended": 0,
      "max_buckets": 1000,
      "auid": 0,
      "subusers": [],
      "keys": [
          {
              "user": "myfourthgwuser",
              "access_key": "I234ZX8XJOGYNIE7ZGFU",
              "secret_key": "qoBX25BXZBT5ROkeK13cnabdgpGKZdhbBWBE9uxg"
          }
      ],
  ... output ommitted
  
  # radosgw-admin key create --uid=myfourthgwuser --gen-access-key
  {
      "user_id": "myfourthgwuser",
      "display_name": "Fourth User",
      "email": "fourthuser",
      "suspended": 0,
      "max_buckets": 1000,
      "auid": 0,
      "subusers": [],
      "keys": [
          {
              "user": "myfourthgwuser",
              "access_key": "4F7T914EMA8HUKQOP1N6",
              "secret_key": "eVhKDJ6ZMpdBMJB2nk9DoXdNufw8KtsZ9NHvEl9r"
          },
          {
              "user": "myfourthgwuser",
              "access_key": "I234ZX8XJOGYNIE7ZGFU",
              "secret_key": "qoBX25BXZBT5ROkeK13cnabdgpGKZdhbBWBE9uxg"
          }
      ],
  ... output ommitted
  ```

### Remove user key

- Command: **`radosgw-admin key rm <--uid=uid> --access_key=<key>`**
  
  ```
  radosgw-admin key rm --uid=myfourthgwuser --access_key=4F7T914EMA8HUKQOP1N6
  {
      "user_id": "myfourthgwuser",
      "display_name": "Fourth User",
      "email": "fourthuser",
      "suspended": 0,
      "max_buckets": 1000,
      "auid": 0,
      "subusers": [],
      "keys": [
          {
              "user": "myfourthgwuser",
              "access_key": "I234ZX8XJOGYNIE7ZGFU",
              "secret_key": "qoBX25BXZBT5ROkeK13cnabdgpGKZdhbBWBE9uxg"
          }
      ],
  ... output ommitted
  ```

### Create a user-based quota

- Command: **`radosgw-admin quota set --quota-scope=user --uid=uid [--max-objects=number] [--max-size=sizeinbytes]`**
  
  ```
  #  radosgw-admin quota set --quota-scope=user --uid=mythirdgwuser --max-objects=18 --max-size=4096
  
  # radosgw-admin user info --uid=mythirdgwuser
  ... output ommitted
      "user_quota": { «
          "enabled": false,
          "check_on_raw": false,
          "max_size": 4096, «
          "max_size_kb": 4,
          "max_objects": 18 «
  ... output ommitted
  ```

### Create a bucket-based quota

- Command: **`radosgw-admin quota set --quota-scope=bucket --uid=uid [--max-objects=number] [--max-size=sizeinbytes]`**
  
  ```
  # radosgw-admin quota set --quota-scope=bucket --uid=mythirdgwuser --max-objects=26 --max-size=10123
  
  # radosgw-admin user info --uid=mythirdgwuser
  ... output ommitted
      "bucket_quota": { «
          "enabled": false,
          "check_on_raw": false,
          "max_size": 10240,
          "max_size_kb": 10,
          "max_objects": 26
      },
      "user_quota": {
          "enabled": false,
          "check_on_raw": false,
          "max_size": 4096,
          "max_size_kb": 4,
          "max_objects": 18
  ... output ommitted
  ```

### Enable a user-based or bucket-based quota

- Command: **`radosgw-admin quota enable --quota-scope=[user|bucket] --uid=uid`**
  
  ```
  # radosgw-admin quota enable --quota-scope=user --uid=mythirdgwuser
  # radosgw-admin user info --uid=mythirdgwuser
  ... output ommitted
      "bucket_quota": {
          "enabled": false,
          "check_on_raw": false,
          "max_size": 10240,
          "max_size_kb": 10,
          "max_objects": 26
      },
      "user_quota": { «
          "enabled": true, «
          "check_on_raw": false,
          "max_size": 4096,
          "max_size_kb": 4,
          "max_objects": 18
  ```

### Disable a user-based or bucket-based quota

- Command: **`radosgw-admin quota-disable --quota-scope=[user|bucket] --uid=uid`**
  
  ```
  # radosgw-admin quota disable --quota-scope=user --uid=mythirdgwuser
  # radosgw-admin user info --uid=mythirdgwuser
  ... output ommitted
      "bucket_quota": { «
          "enabled": false,
          "check_on_raw": false,
          "max_size": 10240,
          "max_size_kb": 10,
          "max_objects": 26
      },
      "user_quota": { «
          "enabled": false, «
          "check_on_raw": false,
          "max_size": 4096,
          "max_size_kb": 4,
          "max_objects": 18
  ... output ommitted
  ```

### Show statistics for a user's usage between two dates

- Command: **`radosgw-admin usage show <--uid=uid> --start-date=yyyy-mm-dd --end-date=yyyy-mm-dd`**
  
  ```
  # radosgw-admin usage show --uid=myawsuser --start-date=2019-05-30 --end-date=2019-05-31
  {
      "entries": [],
      "summary": []
  }
  ```

### Trim usage information between two dates

- Command: **`radosgw-admin usage trim --start-date=yyyy-mm-dd --end-date=yyyy-mm-dd`**
  
  ```
  # radosgw-admin usage trim --uid=myawsuser --start-date=2019-05-30 --end-date=2019-05-31
  ```

### Show statistics for all users

- Command: **`radosgw-admin usage show --show-log-entries=false`**
  
  ```
  # radosgw-admin usage show --show-log-entries=false
  {
      "summary": []
  }
  ```

### List created buckets

- Command: **`radosgw-admin bucket list`**

- Description: when a bucket is created using `s3cmd` it will also show with this command.
  
  ```
  # radosgw-admin bucket list
  [
      "mysecondbucket",
      "myfirstbucket"
  ]
  ```

### Get bucket metadata

- Command: **`radosgw-admin metadata get bucket:bucketname`**
  
  ```
  # radosgw-admin metadata get bucket:myfirstbucket
  {
      "key": "bucket:myfirstbucket",
      "ver": {
          "tag": "__WVzKgu5RhIpmxx7BI_82Ty",
          "ver": 1
      },
      "mtime": "2019-05-31 19:54:44.019739Z",
      "data": {
          "bucket": {
              "name": "myfirstbucket",
              "marker": "236276ab-ed5d-44f8-84b5-19a2fcd50418.84113.7",
              "bucket_id": "236276ab-ed5d-44f8-84b5-19a2fcd50418.84113.7",
              "tenant": "",
              "explicit_placement": {
                  "data_pool": "",
                  "data_extra_pool": "",
                  "index_pool": ""
              }
          },
          "owner": "myawsuser",
          "creation_time": "2019-05-31 19:54:43.950805Z",
          "linked": "true",
          "has_bucket_info": "false"
      }
  }
  ```

### Remove a bucket

- Command:  **`radosgw-admin bucket rm --bucket=bucketname`**

- Description: see [Create S3 bucket](#Create S3 bucket)
  
  ```
  # radosgw-admin bucket rm --bucket=mysecondbucket
  
  radosgw-admin bucket list
  [
      "myfirstbucket"
  ]
  ```

### Check bucket statistics

- Command: **`radosgw-admin bucket stats bucket:bucketname`**
  
  ```
  # radosgw-admin bucket stats bucket:myfirstbucket
  [
      {
          "bucket": "mysecondbucket",
          "zonegroup": "339bb16e-dd95-4d5f-9ae9-7b96b36c7bbe",
          "placement_rule": "default-placement",
          "explicit_placement": {
              "data_pool": "",
              "data_extra_pool": "",
              "index_pool": ""
          },
          "id": "236276ab-ed5d-44f8-84b5-19a2fcd50418.84113.8",
          "marker": "236276ab-ed5d-44f8-84b5-19a2fcd50418.84113.8",
          "index_type": "Normal",
          "owner": "myawsuser",
          "ver": "0#1",
          "master_ver": "0#0",
          "mtime": "2019-05-31 17:51:36.755216",
          "max_marker": "0#",
          "usage": {},
          "bucket_quota": {
              "enabled": false,
              "check_on_raw": false,
              "max_size": -1,
              "max_size_kb": 0,
              "max_objects": -1
          }
  ... output ommitted
  ```

### Working with Amazon S3 API `s3cmd` client commands

#### Install and configure `s3cmd` S3 client

- Command: **`s3cmd --configure`**
  
  ```
  [cephuser@client ceph-ansible]$ sudo yum install -y s3cmd
  [cephuser@client ~]$ s3cmd --configure
  
  Enter new values or accept defaults in brackets with Enter.
  Refer to user manual for detailed description of all options.
  
  Access key and Secret key are your identifiers for Amazon S3. Leave them empty for using the env variables.
  Access Key: abcd
  Secret Key: 5678
  Default Region [US]: 
  
  Use "s3.amazonaws.com" for S3 Endpoint and not modify it to the target Amazon S3.
  S3 Endpoint [s3.amazonaws.com]: node4
  
  Use "%(bucket)s.s3.amazonaws.com" to the target Amazon S3. "%(bucket)s" and "%(location)s" vars can be used
  if the target S3 system supports dns based buckets.
  DNS-style bucket+hostname:port template for accessing a bucket [%(bucket)s.s3.amazonaws.com]: %(bucket)s.node4
  
  Encryption password is used to protect your files from reading
  by unauthorized persons while in transfer to S3
  Encryption password: 
  Path to GPG program [/bin/gpg]: 
  
  When using secure HTTPS protocol all communication with Amazon S3
  servers is protected from 3rd party eavesdropping. This method is
  slower than plain HTTP, and can only be proxied with Python 2.7 or newer
  Use HTTPS protocol [Yes]: No
  
  On some networks all internet access must go through a HTTP proxy.
  Try setting it here if you can't connect to S3 directly
  HTTP Proxy server name: 
  
  New settings:
    Access Key: abcd
    Secret Key: 5678
    Default Region: US
    S3 Endpoint: node4
    DNS-style bucket+hostname:port template for accessing a bucket: %(bucket)s.node4
    Encryption password: 
    Path to GPG program: /bin/gpg
    Use HTTPS protocol: False
    HTTP Proxy server name: 
    HTTP Proxy server port: 0
  
  Test access with supplied credentials? [Y/n] n
  
  Save settings? [y/N] y
  Configuration saved to '/home/cephuser/.s3cfg'
  ```

#### Create an RGW S3 test user

- Command: see [Create Amazon S3 API compatible user](#Create Amazon S3 API compatible user)
  
  ```bash
  [cephuser@client ceph-ansible]$ radosgw-admin user create --uid=myawsuser --display-name="S3 User Test" --email=myawsuser --access-key=abcd --secret=5678
  ```

#### Create S3 bucket

- Command: **`s3cmd mb s3://bucketname`**
  - **Warning: The lab must be using a name resolution, this one uses Dnsmasq. If not, the bucket creation will fail.**
  
  ```bash
  [cephuser@client ~]$ s3cmd mb s3://myfirstbucket
  Bucket 's3://myfirstbucket/' created
  ```

#### List available buckets

- Command: **`s3cmd ls`**
  
  ```
  [cephuser@client ~]$ s3cmd ls
  2019-05-31 19:54  s3://myfirstbucket
  ```

#### Upload files to bucket

- Command: **`s3cmd put --acl-public <file> s3://bucketname/filename`**
  
  ```
  $ for file in myfile{1..5}; do dd if=/dev/zero of=$file.out bs=1024K count=10;done
  
  $ s3cmd put --acl-public myfile1.out s3://myfirstbucket/myfile1.out
  upload: 'myfile1.out' -> 's3://myfirstbucket/myfile1.out'  [1 of 1]
   10485760 of 10485760   100% in    2s     4.21 MB/s  done
  Public URL of the object is: http://myfirstbucket.node4/myfile1.out
  ```

#### List objects inside a bucket

- Command: **`s3cmd ls s3://bucketname`**
  
  ```
  $ s3cmd ls s3://myfirstbucket
  2019-05-31 20:18  10485760   s3://myfirstbucket/myfile1.out
  ```

#### Get file from bucket

- Command: **`s3cmd get s3://bucket_name/objectname local_filename`**
  
  ```
  $ s3cmd get s3://myfirstbucket/myfile1.out filebucket1.out
  download: 's3://myfirstbucket/myfile1.out' -> 'filebucket1.out'  [1 of 1]
   10485760 of 10485760   100% in    0s   128.12 MB/s  done
  $ ls filebucket1.out
  filebucket1.out
  ```

#### Delete file from bucket

- Command: **`s3cmd del s3://bucketname/objectname`**
  
  ```
  $ s3cmd del s3://myfirstbucket/myfile1.out
  delete: 's3://myfirstbucket/myfile1.out'
  ```

### Working with Openstack Swift API

Description: Amazon S3 API authorization and authentication has **single-tier** design. One user
account may have multiple access keys and secrets which are used to provide different types of
access in the same account. The OpenStack Swift API has a **multi-tier** design which is built around *tenants* and
*users*. Swift tenant owns the storage and its containers used by a service. RGW has the concept of **subusers** to OpenStack Swift API's authentication and authorization model.

#### Create Swift subuser

- Command: **`radosgw-admin subuser create --uid=uid --subuser=uid:subuseruid --access=[read | write | read-write | full]`**

- Description: **in order to create a `subuser`, the user must be created first see [Create rados REST gateway user ](#Create rados REST gateway user )**. The parameters are explained below:
  
  - **`--uid=`** - the radosgw user ID
  - **`--display-name=`** -  display name of the user
  - **`--subuser=`** - this allows Swift API tenants to be handled as RADOS Gateway users, and Swift API users to be handled as RADOS Gateway subusers. The Swift API's `tenant:user` tuple maps to RADOS Gateway's authentication system as `user:subuser`. A subuser is created for each Swift user, and this subuser is associated with a RADOS Gateway user and an access key.
  - **`--access=`** - sets the user's permissions (read, write, read-write, full)
  
  ```
  # radosgw-admin user create --uid=swiftuser1 --display-name="First Swift user" --email=swiftuser1@example.com
  {
      "user_id": "swiftuser1",
      "display_name": "First Swift user",
      "email": "swiftuser1@example.com",
      "suspended": 0,
      "max_buckets": 1000,
      "auid": 0,
      "subusers": [],
      "keys": [
          {
              "user": "swiftuser1",
              "access_key": "386W5AG4E6R4XFI21D68",
              "secret_key": "hCQe1QuqvZMVCzl1C96LumuSUPEhSeDHOgGeU5Eu"
          }
  ... output ommitted
  
  # radosgw-admin subuser create --uid=swiftuser1 --subuser=swiftuser1:swift --access=full
  {
      "user_id": "swiftuser1",
      "display_name": "First Swift user",
      "email": "swiftuser1@example.com",
      "suspended": 0,
      "max_buckets": 1000,
      "auid": 0,
      "subusers": [
          {
              "id": "swiftuser1:swift",
              "permissions": "full-control"
          }
      ],
      "keys": [
          {
              "user": "swiftuser1",
              "access_key": "386W5AG4E6R4XFI21D68",
              "secret_key": "hCQe1QuqvZMVCzl1C96LumuSUPEhSeDHOgGeU5Eu"
          }
      ],
      "swift_keys": [
          {
              "user": "swiftuser1:swift",
              "secret_key": "rgYfZdYeA18hZiPUjlBGjoMe0i15EPTv9dU8ZbfD"
          }
      ],
      "caps": [],
      "op_mask": "read, write, delete",
      "default_placement": "",
      "placement_tags": [],
      "bucket_quota": {
          "enabled": false,
          "check_on_raw": false,
          "max_size": -1,
          "max_size_kb": 0,
          "max_objects": -1
      },
      "user_quota": {
          "enabled": false,
          "check_on_raw": false,
          "max_size": -1,
          "max_size_kb": 0,
          "max_objects": -1
      },
      "temp_url_keys": [],
      "type": "rgw"
  }
  ```

#### Create Swift authentication key associated with the subuser

- Command: **`radosgw-admin subuser create --uid=uid --subuser=uid:subuseruid --key-type=swift --secret=<string>`**

- Description: if **`--secret=`** is not specified during the user creation, one will automatically generated. If you want to change the secret, use **`--secret=<new_string>`**.
  
  ```
  # radosgw-admin key create --uid=swiftuser1 --subuser=swiftuser1:swift --key-type=swift --secret=rgYfZdYeA18hZiPUjlBGjoMe0i15EPTv9dU8ZbfD
  ... output ommitted
      "keys": [
          {
              "user": "swiftuser1",
              "access_key": "386W5AG4E6R4XFI21D68",
              "secret_key": "hCQe1QuqvZMVCzl1C96LumuSUPEhSeDHOgGeU5Eu"
          }
      ],
      "swift_keys": [
          {
              "user": "swiftuser1:swift",
              "secret_key": "rgYfZdYeA18hZiPUjlBGjoMe0i15EPTv9dU8ZbfD"
          }
      ],
  ... output ommitted
  
  # radosgw-admin key create --uid=swiftuser1 --subuser=swiftuser1:swift --key-type=swift --secret=someothersecret
  ... output ommitted
      "keys": [
          {
              "user": "swiftuser1",
              "access_key": "386W5AG4E6R4XFI21D68",
              "secret_key": "hCQe1QuqvZMVCzl1C96LumuSUPEhSeDHOgGeU5Eu"
          }
      ],
      "swift_keys": [
          {
              "user": "swiftuser1:swift",
              "secret_key": "someothersecret"
          }
      ],
  ... output ommitted
  ```

#### Modify subuser

- Command: **`radosgw-admin subuser modify --subuser=uid:subuserid --access=<type>`**
  
  ```
  # radosgw-admin subuser modify --subuser=swiftuser1:swift --access=read
  {
      "user_id": "swiftuser1",
      "display_name": "First Swift user",
      "email": "swiftuser1@example.com",
      "suspended": 0,
      "max_buckets": 1000,
      "auid": 0,
      "subusers": [
          {
              "id": "swiftuser1:swift",
              "permissions": "read" «
          }
      ],
  ... output ommitted
  ```

#### Remove a subuser

- Command: **`radosgw-admin subuser rm --subuser=uid:subuserid [--purge-data] [--purge-keys]`**
  
  ```
  $ radosgw-admin subuser rm --subuser=swiftuser2:swift
  {
      "user_id": "swiftuser2",
      "display_name": "Second Swift user",
      "email": "swiftuser2@example.com",
      "suspended": 0,
      "max_buckets": 1000,
      "auid": 0,
      "subusers": [],
      "keys": [
          {
              "user": "swiftuser2",
              "access_key": "A3JTH8PBOOD7QGA9XIZU",
              "secret_key": "3HlY9h58EtO10vGFmR4h6NJIYtHx36OsNNmcm14Y"
          }
      ],
      "swift_keys": [],
  ... output ommitted
  ```

#### Create a subuser key

- Command: **`radosgw-admin key create --subuser=uid:subuserid --key-type=swift [--access-key=key] [--secret=secret]`**
  
  ```
  # radosgw-admin user info --uid=swiftuser2
  {
      "user_id": "swiftuser2",
      "display_name": "Second Swift user",
      "email": "swiftuser2@example.com",
      "suspended": 0,
      "max_buckets": 1000,
      "auid": 0,
      "subusers": [
          {
              "id": "swiftuser2:swift",
              "permissions": "full-control"
          }
      ],
      "keys": [
          {
              "user": "swiftuser2",
              "access_key": "A3JTH8PBOOD7QGA9XIZU",
              "secret_key": "3HlY9h58EtO10vGFmR4h6NJIYtHx36OsNNmcm14Y"
          }
      ],
      "swift_keys": [
          {
            » "user": "swiftuser2:swift",
            » "secret_key": "xGbVsqSn0oxNyUbVU8HJ0XwcBuCo4LG1bByhFECE"
          }
      ],
  ... output ommitted
  
  # radosgw-admin key create --subuser=swiftuser2:test --key-type=swift --access-key=anewkey --secret=anewsecret
  {
      "user_id": "swiftuser2",
      "display_name": "Second Swift user",
      "email": "swiftuser2@example.com",
      "suspended": 0,
      "max_buckets": 1000,
      "auid": 0,
      "subusers": [
          {
              "id": "swiftuser2:swift",
              "permissions": "full-control"
          }
      ],
      "keys": [
          {
              "user": "swiftuser2",
              "access_key": "A3JTH8PBOOD7QGA9XIZU",
              "secret_key": "3HlY9h58EtO10vGFmR4h6NJIYtHx36OsNNmcm14Y"
          }
      ],
      "swift_keys": [
          {
              "user": "swiftuser2:swift",
              "secret_key": "anewsecret"
          },
          {
              "user": "swiftuser2:test",
              "secret_key": "anewsecret"
          }
      ],
  ... output ommitted
  ```

#### Remove a subuser key

- Command: **`radosgw-admin key rm --subuser=uid:subuserid`**
  
  ```
  # radosgw-admin key rm --subuser=swiftuser2:test
  {
      "user_id": "swiftuser2",
      "display_name": "Second Swift user",
      "email": "swiftuser2@example.com",
      "suspended": 0,
      "max_buckets": 1000,
      "auid": 0,
      "subusers": [
          {
              "id": "swiftuser2:swift",
              "permissions": "full-control"
          }
      ],
      "keys": [
          {
              "user": "swiftuser2",
              "access_key": "A3JTH8PBOOD7QGA9XIZU",
              "secret_key": "3HlY9h58EtO10vGFmR4h6NJIYtHx36OsNNmcm14Y"
          }
      ],
      "swift_keys": [
          {
              "user": "swiftuser2:swift",
              "secret_key": "vcbncvnvcncbn"
          }
      ],
  ... output ommitted
  ```

#### Create a tenant (multitenancy)

- Command: **`radosgw-admin user create --tenant testtenant --uid=uid --display-name="Swift User" --subuser=uid:subuserid --key-type=swift --access=full`**

- Description: OpenStack Swift API supports the use of tenants to isolate containers/buckets and users. This feature allows the use of the same name for buckets on different tenants, because tenants isolate resources. This change infer that any further reference to the subuser must include the tenant.

  ```
  radosgw-admin user create --tenant swftenant3 --uid=swiftuser3 --display-name="Swift User" --subuser=swiftuser3:test2 --key-type=swift --access=full
  {
    "user_id": "swftenant3$swiftuser3",
      "display_name": "Swift User",
    "email": "",
      "suspended": 0,
      "max_buckets": 1000,
      "auid": 0,
      "subusers": [
          {
              "id": "swftenant3$swiftuser3:test2",
              "permissions": "full-control"
          }
      ],
      "keys": [],
      "swift_keys": [
          {
              "user": "swftenant3$swiftuser3:test2",
              "secret_key": "CPKpCeaZrABU74aBP0qNci2eZu1YBfdccPuy6Qht"
          }
      ],
  ... output ommitted
  ```
  

#### List user information with a tenant

- Command: **`radosgw-admin user info --subuser='tenant$swiftuser3:test2'`**

  ```
  # radosgw-admin user info --subuser='swftenant3$uid:subuserid'
  {
      "user_id": "swftenant3$swiftuser3",
      "display_name": "Swift User",
      "email": "",
      "suspended": 0,
      "max_buckets": 1000,
      "auid": 0,
      "subusers": [
          {
              "id": "swftenant3$swiftuser3:test2",
              "permissions": "full-control"
          }
      ],
      "keys": [],
      "swift_keys": [
          {
              "user": "swftenant3$swiftuser3:test2",
              "secret_key": "CPKpCeaZrABU74aBP0qNci2eZu1YBfdccPuy6Qht"
          }
      ],
  ... output ommitted
  ```


## Ceph Filesystem (CephFS)

Documentation: [CEPH FILESYSTEM](http://docs.ceph.com/docs/luminous/cephfs/#using-cephfs)