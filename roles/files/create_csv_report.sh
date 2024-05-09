#!/bin/bash
echo "Hostname,Status,Details" > /var/log/update_report.csv
{% for host in ansible_play_hosts_all %}
echo "{{ host }},{{ hostvars[host].update_status | default('Unknown') }},{{ hostvars[host].update_details | default('No details available') }}" >> /var/log/update_report.csv
{% endfor %}
