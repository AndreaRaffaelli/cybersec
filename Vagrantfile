# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "debian/bullseye64"
  config.vm.box_version = "11.20241217.1"
  
  config.vm.box_check_update = false

  # Creare una rete privata con un IP specifico
  config.vm.network "private_network", ip: "192.168.56.10"

  # Creare una rete pubblica, che generalmente corrisponde a una rete bridged.
  # config.vm.network "public_network"

  # Condividere una cartella aggiuntiva con la VM guest.
  config.vm.synced_folder "./data", "/vagrant_data", mount_options: ["dmode=775", "fmode=664"], type: "rsync"

  # Abilitare il provisioning con uno script shell.
  config.vm.provision "shell", inline: <<-SHELL
    sudo apt update
    sudo apt install -y clang llvm libbpf-dev gcc make iproute2 linux-headers-$(uname -r) bpfcc-tools linux-headers-$(uname -r)
    sudo apt install -y bpftool
    sudo apt install iperf3
    cd /vagrant_data/libbpf-bootstrap/libbpf/src && make && sudo make install
  SHELL
end
