#!/usr/bin/python
#2016.9.6 by sfzhang
import subprocess as sp
import paramiko as pm
import re
import sys
import pexpect
sh = ("/bin/bash","-c")
def get_ssh_vm(subnet):
    '''scan local virtual network get the ip of available virtual machines with ssh port open'''
    vms = []
    nmap_result = sp.check_output(list(sh+("nmap -p 22 "+subnet.strip()+" --exclude 192.168.122.1,192.168.122.254",)))
    for vm_entry in nmap_result.split('\n\n'):
        if "open" in vm_entry:
            vm_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",vm_entry).group()
            print "%s ssh port is open" % vm_ip
            vms.append(vm_ip)
    return vms

def generate_ansible_hosts_file(hostnameDict):
    '''dynamically create ansible hosts file'''
    #TODO
    with open("/etc/ansible/hosts","w") as host_file:
        host_file.write("[host]\n"+"localhost".ljust(30)+"ansible_connection=local".ljust(40)+"ansible_ssh_host=127.0.0.1\n")
        host_file.write("[virtualmachines]\n")
        for hostip in hostnameDict:
            host_file.write(hostnameDict[hostip].ljust(30)+"ansible_connection=ssh".ljust(40)+"ansible_ssh_host="+hostip+"\n")
            if "ipa" in hostnameDict[hostip]:
                ipa_hostip = hostip
        host_file.write("[virtualmachines:vars]\n")
        host_file.write("ipa_server_address="+ipa_hostip+"\n")

def maniputlate_etc_hosts(hostnameDict):
    '''just in case dns is not working on the host'''
    with open ("/etc/hosts","a") as etc_host_file:
        etc_host_file.write("127.0.0.1".ljust(20)+"host.sfzhang.com\n")
        for host in hostnameDict:
            etc_host_file.write(host.ljust(20)+hostnameDict[host]+"\n")


def generate_sshkey_to_vm():
    '''generate ssh key pair and copy it to virtual machines'''
    child = pexpect.spawn("/bin/bash -c ssh-keygen")
    child.logfile=sys.stdout
    #Enter file in which to save the key (/root/.ssh/id_rsa):
    child.expect(".*in which to save.*:")
    child.sendline("")
    #Enter passphrase (empty for no passphrase):
    #/root/.ssh/id_rsa already exists.Overwrite (y/n)?
    i = child.expect(["empty for no passphrase","Overwrite"])
    if i == 0:
        child.sendline("")
        #Enter same passphrase again:
        child.expect(".*same passphrase again.*:")
        child.sendline("")
        #print child.after
        child.expect(pexpect.EOF)
        child.close(force=True)
    else:
        child.sendline("n")
        child.expect(pexpect.EOF)
        child.close(force=True)


def copy_sshkey_to_vm(ips):
    '''copy user ssh public key to remote virtual machine'''
    for vm_ip in ips:
        #the follow just doesn't work
        #child = pexpect.spawn("/bin/bash -c ssh-copy-id root@" + vm_ip)
        #child = pexpect.spawn("/bin/bash",["-c","ssh-copy-id root@" + vm_ip])
        child = pexpect.spawn("ssh-copy-id root@" + vm_ip)
        try:
            #i == 0 for Are you sure you want to continue connecting (yes/no)?
            #i == 1 for root@ip's password:
            #i == 2 for WARNING: All keys were skipped because they already exist on the remote system.
            i = child.expect(["sure you want","password",pexpect.EOF])
            child.logfile = sys.stdout
            if i == 0:
                child.sendline("yes")
                child.expect("password")
                child.sendline("sfzhang")
                child.expect(pexpect.EOF)
                print "\033[33mssh key was successfully copyied to %s\033[0m" % vm_ip
                child.close(force=True)
            elif i == 1:
                child.sendline("sfzhang")
                child.expect(pexpect.EOF)
                print "\033[35mssh key was successfully copyied to %s\033[0m" % vm_ip
                child.close(force=True)
            elif i == 2:
                print "\033[36mkey already exists\033[0m"
                child.close(force=True)
        except:
            print("Exception was thrown,key copy failed!")
            print("debug information:")
            print(str(child))

def execute_ansible_playbook(yamlpath):
    ''''execute ansible playbook '''

def initialize_vm(ips,uname,pwd):
    ansible_hosts = {}
    for vm_ip in ips:
        
        ssh =  pm.SSHClient()
        ssh.set_missing_host_key_policy(pm.AutoAddPolicy())
        try:
            ssh.connect(vm_ip,username=uname,password=pwd)

        except pm.SSHException:
            print "ssh connect error!Try again!!"
            sys.exit()
        #TODO
        stdin,stdout,stderr = ssh.exec_command("hostname")
        ansible_hosts[vm_ip] = stdout.read().strip()
        ssh.close()
    return ansible_hosts


#you should place .vimrc file under user home directory
#sp.call(sh.append("yum install -y epel-release gcc git ansible vim bpython python-pip"))
#sp.call(sh.append("git clone https://github.com/gmarik/Vundle.vim.git ~/.vim/bundle/Vundle.vim"))
#sp.call(sh.append("vim +PluginInstall +qall"))
#print "--------------------------------------------\n"


if __name__ == "__main__":

    vmlist = get_ssh_vm(sys.argv[1].strip())
    if not vmlist:
        print "no hosts can be access through ssh"
    else:
        vmdict = initialize_vm(vmlist,"root","sfzhang")
        generate_sshkey_to_vm()
        copy_sshkey_to_vm(vmlist)
        generate_ansible_hosts_file(vmdict)
