import sys
import yaml
import requests
import xml.etree.ElementTree as ET
import os

# Create a temporary directory to store the playbooks
target_directory = sys.argv[1]

# Fetch and parse security advisories
def get_security_updates(url):
    patch_ids = []
    response = requests.get(url)
    root = ET.fromstring(response.content)
    for item in root.findall('.//item'):
        title = item.find('title').text
        # Extract advisory ID based on the title format
        advisory_id = title.split()[1].split(':')[0]
        patch_ids.append(advisory_id)
    return patch_ids

def generate_playbook(advisory_ids, os_type):
    tasks = []
    update_command = {
        'ubuntu': 'sudo apt update && sudo apt upgrade -y',
        'debian': 'sudo apt update && sudo apt upgrade -y',
        'fedora': 'sudo dnf update -y',
        'rocky': 'sudo dnf update -y',
        'redhat': 'sudo yum update -y'
    }[os_type]

    for advisory_id in advisory_ids:
        task = {
            'name': f'Upgrade advisory {advisory_id}',
            'command': {
                'ubuntu': f'sudo apt-get --only-upgrade install {advisory_id}',
                'debian': f'sudo apt-get --only-upgrade install {advisory_id}',
                'fedora': f'sudo dnf upgrade --advisory {advisory_id}',
                'rocky': f'sudo dnf upgrade --advisory {advisory_id}',
                'redhat': f'sudo yum upgrade --advisory {advisory_id}'
            }[os_type]
        }
        tasks.append(task)

    # Prepend the update command task
    tasks.insert(0, {'name': 'Update packages', 'command': update_command})

    playbook = [{
        'hosts': 'all',
        'become': 'yes',
        'tasks': tasks
    }]

    # Ensure the filename is in all lowercase
    playbook_path = os.path.join(target_directory, f'{os_type.lower()}_playbook.yml')
    with open(playbook_path, 'w') as file:
        yaml.dump(playbook, file, default_flow_style=False)

    print(f"Generated playbook for {os_type} at {playbook_path}")

# Main execution flow
if __name__ == "__main__":
    urls = {
        'ubuntu': "https://linuxsecurity.com/advisories/ubuntu?format=feed&type=rss",
        'fedora': "https://linuxsecurity.com/advisories/fedora?format=feed&type=rss",
        'rocky': "https://linuxsecurity.com/advisories/rockylinux?format=feed&type=rss",
        'redhat': "https://linuxsecurity.com/advisories/red-hat?format=feed&type=rss"
    }

    for os_type, url in urls.items():
        advisories = get_security_updates(url)
        generate_playbook(advisories, os_type)