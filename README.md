ssh-copy-id -i ssh_keys/id_rsa.pub root@192.168.200.74
ssh-copy-id -i ssh_keys/id_rsa.pub root@192.168.200.75
# ansible-deploy-tpot
ssh-keygen -f /root/.ssh/known_hosts -R 192.168.200.74
