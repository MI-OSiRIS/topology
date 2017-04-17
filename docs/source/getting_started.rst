.. _getting_started:

.. image:: _static/CREST.png
    :align: center

OSiRIS Topology Discovery getting started
=========================================

What's Topology Discovery Software ?
====================================

This is a RYU application which builds Dynamic Network Topology information
from all the Openflow switches connected to a RYU controller.

The Topology information is automatically pushed to UNIS server using UNISRt.
The Topology information Nodes, Ports and Links will be part of the Domain name specified.


Quick start
===========

1. Install python3
2. Install UNISrt::
    % git clone https://github.com/periscope-ps/UNISrt
    % cd UNISrt;python3 setup.py build install
3. Install RYU controller::
    % pip install ryu
4. Discovery app's config file has to loaded at /etc/ryu/osiris.conf. Refer ryu/config/osiris-sdn-app.conf for example.
    It contains unis_server which the UNIS server's IP and port to talk to(http://<unis-ip>:<unis-port>).
    Also, unis_domain which is the UNIS's domain object into which the topology has to pushed. Also

5. Run Discovery app on RYU using ryu-manager::
    % ryu-manager ryu/osiris_main.py --ofp-tcp-listen-port 6654 --wsapi-port 8081 --verbose --install-lldp-flow --observe-links
