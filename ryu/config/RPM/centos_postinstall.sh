#!/bin/bash

ETC=/etc/ryu
SVDIR=/etc/supervisor
SHARE=/usr/share/osiris-sdn

if [ ! -d ${ETC} ]; then
    mkdir -p ${ETC}
fi

if [ ! -f ${ETC}/osiris.conf ]; then
    cp ${SHARE}/osiris-sdn-app.conf ${ETC}/osiris.conf
fi

if grep -q -i "release 6" /etc/redhat-release
then
    echo "CentOS 6 scripts unsupported, configure supervisor with template in $SHARE"
elif grep -q -i "release 7" /etc/redhat-release
then
    #cp ${SHARE}/supervisor.conf /etc/supervisord.d/osiris-sdn-app.ini
    cp ${SHARE}/osiris-sdn.service /etc/systemd/system/osiris-sdn.service
    systemctl daemon-reload
    systemctl enable osiris-sdn
    service supervisord restart
fi
