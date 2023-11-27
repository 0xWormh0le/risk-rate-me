# -*- mode: ruby -*-
# vi: set ft=ruby :
VAGRANTFILE_API_VERSION = "2"
VAGRANT_IP = "192.168.33.11"
VARGANT_IMAGE = "ubuntu/bionic64"

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.:w
Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = VARGANT_IMAGE

  config.vm.define "riskrateme" do |riskrateme|
        riskrateme.vm.hostname  = "riskrate.me"
        riskrateme.vm.network :private_network, ip: VAGRANT_IP
		#riskrateme.vm.network "forwarded_port", guest: 8000, host: 8000
		riskrateme.vm.network "forwarded_port", guest: 443, host: 8443
		riskrateme.vm.network "forwarded_port", guest: 6379, host: 6379

        riskrateme.vm.provision :ansible do |ansible|
            ansible.playbook = "site-local.yml"
            ansible.extra_vars = { ansible_python_interpreter:"/usr/bin/python3" }
        end
  end
end
