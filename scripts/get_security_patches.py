import yaml
import requests
import xml.etree.ElementTree as ET

# For Ubuntu
def get_ubuntu_updates():
    ubuntu_patch_ids = []
    url = "https://linuxsecurity.com/advisories/ubuntu?format=feed&type=rss"
    response = requests.get(url)
    root = ET.fromstring(response.content)
    for item in root.findall('.//item'):
        title = item.find('title').text
        advisory_id = title.split()[1]
        advisory_id = advisory_id.rsplit(":", 1)[0]
        ubuntu_patch_ids.append("USN-"+advisory_id)
    print("Ubuntu Security Patch Ids: ",ubuntu_patch_ids)
    return ubuntu_patch_ids

# For Rocky Linux
def get_rocky_updates():
    rocky_patch_ids = []
    url = "https://linuxsecurity.com/advisories/rockylinux?format=feed&type=rss"
    response = requests.get(url)
    root = ET.fromstring(response.content)
    important_updates = []
    for item in root.findall('.//item'):
        title = item.find('title').text
        advisory_id = title.split()[2]
        rocky_patch_ids.append(advisory_id)
    print("Rocky Linux Security Patch Ids: ",rocky_patch_ids)
    return rocky_patch_ids

# For Fedora
def get_fedora_updates():
    fedora_patch_ids = []
    url = "https://linuxsecurity.com/advisories/fedora?format=feed&type=rss"
    response = requests.get(url)
    root = ET.fromstring(response.content)
    for item in root.findall('.//item'):
        title = item.find('title').text
        advisory_id = "FEDORA-" + title.split()[3]
        fedora_patch_ids.append(advisory_id)
    print("Fedora Security Patch Ids: ",fedora_patch_ids)
    return fedora_patch_ids

# For RHEL
def get_rhel_updates():
    rhel_patch_ids = []
    url = "https://linuxsecurity.com/advisories/red-hat?format=feed&type=rss"
    response = requests.get(url)
    root = ET.fromstring(response.content)
    for item in root.findall('.//item'):
        title = item.find('title').text
        print(title)
        advisory_id = title.split()[1]
        advisory_id = advisory_id.split(":")[0]
        rhel_patch_ids.append(advisory_id)
    print("RHEL Security Patch Ids: ",rhel_patch_ids)
    return rhel_patch_ids

# def generate_playbook(advisory_ids, os_type):
#     tasks = []
#     for advisory_id in advisory_ids:
#         if os_type == 'fedora' or os_type == 'rocky':
#             tasks.append({
#                 'name': f'Upgrade advisory {advisory_id}',
#                 'command': f'sudo dnf upgrade --advisory {advisory_id}'
#             })
#         elif os_type == 'rhel':
#             tasks.append({
#                 'name': f'Upgrade advisory {advisory_id}',
#                 'command': f'sudo yum upgrade --advisory {advisory_id}'
#             })
#         elif os_type == 'ubuntu':
#             tasks.append({
#                 'name': f'Upgrade advisory {advisory_id}',
#                 'command': f'sudo apt-get --only-upgrade install {advisory_id}'
#             })

#     playbook = [{
#         'hosts': 'all',
#         'become': 'yes',
#         'tasks': tasks
#     }]

#     with open(f'{os_type}_playbook.yml', 'w') as file:
#         yaml.dump(playbook, file, default_flow_style=False)

def generate_playbook(advisory_ids, os_type):
    tasks = []
    update_command = ""

    # Determine the update command based on the OS type
    if os_type in ['ubuntu', 'debian']:
        update_command = 'sudo apt update && sudo apt upgrade -y'
    elif os_type in ['fedora', 'rocky']:
        update_command = 'sudo dnf update -y'
    elif os_type == 'rhel':
        update_command = 'sudo yum update -y'

    # Generate tasks for each advisory ID
    for advisory_id in advisory_ids:
        if os_type in ['ubuntu', 'debian']:
            tasks.append({
                'name': f'Upgrade advisory {advisory_id}',
                'command': f'sudo apt-get --only-upgrade install {advisory_id}'
            })
        elif os_type in ['fedora', 'rocky']:
            tasks.append({
                'name': f'Upgrade advisory {advisory_id}',
                'command': f'sudo dnf upgrade --advisory {advisory_id}'
            })
        elif os_type == 'rhel':
            tasks.append({
                'name': f'Upgrade advisory {advisory_id}',
                'command': f'sudo yum upgrade --advisory {advisory_id}'
            })

    # Prepend the update command to the playbook tasks
    tasks.insert(0, {
        'name': 'Update packages',
        'command': update_command
    })

    playbook = [{
        'hosts': 'all',
        'become': 'yes',
        'tasks': tasks
    }]

    # Write the playbook to a YAML file
    with open(f'{os_type}_playbook.yml', 'w') as file:
        yaml.dump(playbook, file, default_flow_style=False)

# Replace these with the actual functions that return the advisory IDs
ubuntu_advisories = get_ubuntu_updates()
fedora_advisories = get_fedora_updates()
rocky_advisories = get_rocky_updates()
rhel_advisories = get_rhel_updates()

generate_playbook(ubuntu_advisories, 'ubuntu')
generate_playbook(fedora_advisories, 'fedora')
generate_playbook(rocky_advisories, 'rocky')
generate_playbook(rhel_advisories, 'rhel')