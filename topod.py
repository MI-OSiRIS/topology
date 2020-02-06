import logging
import daemon
import time
import datetime
from time import gmtime, strftime
from threading import Thread
from snmp_manager import *
from unis import Runtime
from configparser import ConfigParser
import argparse

MINUTES = 1
DEFAULT_DISCOVERY_INTERVAL = (60) * ( MINUTES )

class TopologyDaemon:
    '''
        Contructor:
        @param(interval): how often the daemon runs peripheral discovery tools
        @param(unis_host): the local unis store the daemon should upload resources to
        @param(unis_server): the 'head' unis, used for ryu to amend domain href changes.
    '''
    def __init__(self, unis_host=None, unis_server=None, interval=None, config=None, log_file='topod.log'):
        
        logging.basicConfig(filename=log_file, level=logging.INFO)
        logging.info('Log Initialized.')
        
        # If config is specified, pull from it, otherwise use parameters given.
        if config is not None:
            self._conf_from_file(config)
        else:
            self.unis_host   = unis_host
            self.unis_server = unis_server
        
        self.log_file = log_file
        self.rt = Runtime(self.unis_host)
        
        # if no interval is set, default to global interval.
        if interval is None:
            self.discovery_interval = DEFAULT_DISCOVERY_INTERVAL
        else:
            self.discovery_interval    = interval
        

        return
    '''
        Helper function for logging to default log file with timestamps appended.

        @param(msg): string formatted message to drop into log file.
    '''
    def _log(self, msg):
        now = strftime("%Y-%m-%d %H:%M:%S", gmtime())
        return logging.info(msg + " | " + now)
        

    '''
        Helper for reading and setting up the class with the specified properties
    
        @param(path): string for filepath. Likely '/etc/ryu/osiris-sdn-app.conf'
    '''
    def _conf_from_file(self, path):

        self._log("Attempting to update daemon from config " + path)

        parser = ConfigParser()

        try:
            parser.read(path)
            config_section_name   = parser.sections()[0]
            config                = parser[config_section_name]
        except Exception:
            self._log("Failed to read file from path: " + path)
            raise AttributeError("INVALID FILE PATH FOR STATIC RESOURCE INI.")
            return False
    
        
        self.unis_host   = config['unis_host'].replace('"','').replace("'",'')
        self.unis_server = config['unis_server'].replace('"','').replace("'",'')

        self._log("Updated Daemon - UNIS_HOST: " + self.unis_host + ", UNIS_SERVER: " + self.unis_server)
       
        return True
    
    '''
        Logic for SNMP Discovery. Main Daemon process should create a thread that runs this function over a specified interval.
    '''
    def _snmp_discovery_thread(self):
    
        nodes = self.rt.nodes
         
        for n in nodes:
            self._log('Starting SNMP discovery for ' + n.properties.mgmtaddr)
            
            try:

                host = n.properties.mgmtaddr
                snmpm = SNMP_Manager(host, rt=self.rt)
                snmpm.discover()
                snmpm.discover_neighbors()
        
            except Exception as e:
            
                self._log("Failed to query SNMP MIBS at host " + host)

            self._log('Finished SNMP discovery for ' + n.properties.mgmtaddr)
        
        return

    def start(self):

        logger = logging.getLogger()
        fh = logging.FileHandler(self.log_file)
        logger.addHandler(fh)

        with daemon.DaemonContext(files_preserve = [fh.stream]):
            self._log("********** Beginning Topology Daemon **********")
            
            self._log(" - Starting Main Loop - ")
            while True:
                # over every defined interval, run the tools.
                time.sleep(self.discovery_interval)
                
                self._log("CREATE NEW THREAD for -  SNMP")
                snmp_thread = Thread(target=self._snmp_discovery_thread).start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Topology Daemon handles the orchestration and runtime of NMAL topology tools.')
    parser.add_argument('-c', '--config', default='/etc/ryu/osiris-sdn-app.conf', type=str, help='Path where the config is located. Default /etc/ryu/osiris-sdn-app.conf')
    args = parser.parse_args()

    config_path = args.config
    
    topod = TopologyDaemon(config=config_path) 
    topod.start()
