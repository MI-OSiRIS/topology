#!/bin/bash

if grep -q -i "release 6" /etc/redhat-release
then
    echo "CentOS 6 scripts unsupported, edit supervisor config manually"
elif grep -q -i "release 7" /etc/redhat-release
then
    if [ "$1" = "0" ]; then
        # Perform tasks to prepare for the uninstallation
	service osiris-sdn stop
        systemctl disable osiris-sdn
        rm -f /etc/systemd/system/osiris-sdn.service
	systemctl daemon-reload
    fi
fi
