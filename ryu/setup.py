#!/usr/bin/env python
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import setuptools
setuptools.setup(name='osiris-sdn-app',
                 description='Topology Discovery and SDN Control Ryu Application',
                 version="0.1",
                 data_files=[('/usr/share/osiris-sdn', ['config/RPM/wait_sv_sock',
                                                        'config/RPM/osiris-sdn.service',
                                                        'config/supervisor.conf',
                                                        'config/osiris-sdn-app.conf',
                                                        'osiris_main.py',])
                         ],
                 install_requires=[
                     'unisrt',
                     'easysnmp',
                     'ryu',
                     'configparser',
                     'python-daemon',
                     'scapy'
                 ],
                 options = {'bdist_rpm':{'post_install' : 'config/RPM/centos_postinstall.sh',
                                         'post_uninstall' : 'config/RPM/centos_postuninstall.sh'}},

             )
