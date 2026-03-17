set -xe
docker compose up -d && docker compose exec ansible ansible-playbook  -i /apps/inventory.ini /playbooks/master.yml