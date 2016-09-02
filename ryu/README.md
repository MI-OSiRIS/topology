### Running basic Ryu app for LLDP capture in OSiRIS

    $ sudo ryu-manager osiris_main.py --default-log-level=1 --install-lldp-flow --observe-links --ofp-tcp-listen-port=6653

### Configure OVS bridges to connect to the running controller
  
    $ sudo ovs-ofctl dump-flows ovsbr0
    NXST_FLOW reply (xid=0x4):
    
    $ sudo ovs-vsctl set-controller ovsbr0 tcp:127.0.0.1:5000
    
    $ sudo ovs-ofctl dump-flows ovsbr0
    NXST_FLOW reply (xid=0x4):
    cookie=0x0, duration=52.499s, table=0, n_packets=2, n_bytes=470, idle_age=17, priority=65535,dl_dst=01:80:c2:00:00:0e,dl_type=0x88cc actions=CONTROLLER:65535
    cookie=0x0, duration=52.501s, table=0, n_packets=174, n_bytes=28967, idle_age=0, priority=0 actions=NORMAL
  
The Ryu controller output will display LLDP packet output but allow OVS to continue forwarding traffic without controller interaction.
