
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
    % cd UNISrt; python3 setup.py build install
3. Install RYU controller::

    % pip install ryu
4. Add discovery application's config file::

    %cp ryu/config/osiris-sdn-app.conf /etc/ryu/osiris.conf

5. Configure the UNIS server's IP and port in the format http://unis-ip:unis-port and
unis_domain which is the UNIS's domain object into which the topology has to pushed.

6. Run Discovery app on RYU using ryu-manager::

    % ryu-manager ryu/osiris_main.py --ofp-tcp-listen-port 6654 --wsapi-port 8081 --verbose --install-lldp-flow --observe-links
