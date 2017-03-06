#!/bin/bash

# Uses fpm (an alternative is to use setup.py bdist_rpm but then prefixes need to be managed manually)
# > yum install rub-devel gem
# > gem install --no-ri --no-rdoc fpm

fpm -f -s python --python-bin python3 --python-package-name-prefix python34 -t rpm -p dist --after-install config/RPM/centos_postinstall.sh --after-remove config/RPM/centos_postuninstall.sh setup.py
