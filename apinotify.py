#!/usr/bin/env python3

from panos.firewall import Firewall
import datetime 
import xml.etree.ElementTree as ET
from logging import getLogger, Formatter
import logging.handlers
import argparse
import tomllib
from getpass import getpass
import asyncio
from pysnmp.hlapi.asyncio import SnmpEngine, sendNotification, CommunityData, UdpTransportTarget, ContextData, NotificationType, ObjectIdentity, OctetString, Counter64, Integer

# List of all the SNMP Traps to send
listSnmpVals = []
# Dict for each SNMP Trap
snmpvals = {
  "receive_time2": "",
  "serial_num3": "",
  "type4": "SYSTEM",
  "subtype5": "",
  "vsys7": "",
  "log_entry8" : 0,
  "panorama_fwd9" : 0,
  "host_name12" : "",
  "log_eventid300" :"",
  "log_module302" : "",
  "log_sev303" : 0,
  "log_desc304" : ""
}

locallog = logging.getLogger(__file__)


######### Main Function
def main():
    #Setup local logging
    # Create the logger for the remote syslog server

    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    locallog.addHandler(ch)

    parser=argparse.ArgumentParser(description="Retrieve the lastest NGFW log files for a period via api")
    parser.add_argument('--conf', action='append', help="Enter the config file instead of line items. If no parameters are entered it will look for a file named 'config'")
    parser.add_argument('-f','--firewall',metavar='Firewall',help='firewall to access')
    parser.add_argument('-u','--user',metavar='Username',help='Username to access')
    parser.add_argument('-p','--password',metavar='Password',help='Password for username')
    parser.add_argument('-a','--apikey',metavar='API Key',help='API Key')
    parser.add_argument('--snmphost', help="Snmp Host")
    parser.add_argument('-s','--syslog',metavar='Sylog host',help='Host to forwards syslogs to (default 127.0.0.1)',default='127.0.0.1')
    parser.add_argument('-l','--level',help='Minimum Forward Level (default INFO)',choices=['CRITICAL','ERROR','WARNING','INFO'], default='INFO')
    parser.add_argument('-t','--timeframe',help='Log timeframe (Default 5)',type=int, default=5)
    parser.add_argument('-n','--numlogs',help='Max number of logs (Default 100)',type=int, default=100)
    parser.add_argument("-v", "--verbose", help="increase output verbosity",action="store_true")
    args=parser.parse_args()
    # Check if Verbose logging is turned on
    if args.verbose:
        locallog.setLevel(logging.DEBUG)
    # If no parameters are defined, use the standard configuration if 'config'
    if(args.user == None and args.apikey == None and args.conf == None):
        args.conf = ['config']
        locallog.debug("Using the default file")

    # Load configuration file values 
    if args.conf is not None:
        for conf_fname in args.conf:
            with open(conf_fname, "rb") as f:
                try:
                    parser.set_defaults(**tomllib.load(f))
                except:
                    locallog.error("Invalid parameters in configuration file")
                    quit()
        # Reload arguments to override config file values with command line values
        args = parser.parse_args()

    # if the Firewall is not defined, fail)
    if(args.firewall is None):
        locallog.error("You must define at least a firewall")
        quit()
    locallog.debug("Firwall is %s",args.firewall)

    # If an API key is defined
    if(args.apikey != None):
        locallog.debug("Using  api key %s", args.apikey)
        try:
            fw = Firewall(args.firewall,api_key=args.apikey)
        except:
            locallog.error("Could not open firewall at %s with api key",args.firewall)
            quit()
    # else check if username is defined
    elif(args.user != None):
        # Check if password is not defined
        if (args.password == None):
            locallog.debug("Using username '%s' and asing for password", args.user)
            args.password = getpass()
            locallog.debug("Password is '%s'",args.password)
        # Create the firewall object using the username and password defined
        locallog.debug("Using username '%s' and password '%s'", args.user, args.password)
        try:
            fw = Firewall(args.firewall, args.user, args.password )
        except:
            locallog.error("Could not open firewall at %s, with username %s",args.firewall,args.user)
            quit()
    # If no username or API key is defined, then fail
    else:
        locallog.error("No Credentials found")
        quit()

    # look at the time less the timeframe given in minutes
    time_5m_ago = datetime.datetime.now() - datetime.timedelta(minutes=args.timeframe)
    # create the filter
    time_5m_ago_str = time_5m_ago.strftime("( receive_time geq '%Y/%m/%d %H:%M:%S' )")

    # Make the desired format string for Syslog forwarding to the remote syslog server
    LOG_FORMAT = f"%(levelname)s:%(message)s"
    # Create the logger for the remote syslog server
    logger = getLogger()
    # define the remote syslog server, it will default to the local host - although this will not work on MacOS as they have disabled local listening
    syslogHandler = logging.handlers.SysLogHandler(address=(args.syslog, 514))
    syslogHandler.setFormatter(Formatter(LOG_FORMAT))
    logger.addHandler(syslogHandler)

    # using the panos api to collec the logs- https://github.com/kevinsteves/pan-python/blob/master/doc/pan.xapi.rst 
    try:
        response = fw.xapi.log(log_type='system',filter=time_5m_ago_str,nlogs=args.numlogs)
    except:
        locallog.error("PANOS API did not work for firewall %s, check parameters",args.firewall)
        quit()
    # Parsing the response. Assuming the response is always the same - future work is to handle failures
    for child in response[0][1][0]:
        # Create the SNMP dict entry
        if args.snmphost is not None:
            snmpvals['receive_time2'] = child.find('receive_time').text
            snmpvals['serial_num3'] = child.find('serial').text
            snmpvals['subtype5'] = child.find('subtype').text
            snmpvals['vsys7'] = child.find('vsys_id').text
            snmpvals['log_entry8'] = child.find('seqno').text
            snmpvals['host_name12'] = child.find('device_name').text
            snmpvals['log_eventid300'] = child.find('eventid').text
            snmpvals['log_module302'] = child.find('module').text
            snmpvals['log_desc304'] = child.find('opaque').text
        # Only send the receive time, type, device name and message
        logstr = child.find('receive_time').text + ', '+ child.find('type').text + ', '+ child.find('device_name').text + ', '+ child.find('opaque').text
        # filter on the severity and map it to Syslog message levels
        system_sev = child.find('severity').text
        if(system_sev == "critical"):
            locallog.debug("Writeing CRITICAL:%s",logstr)
            logger.setLevel(logging.CRITICAL)
            logger.critical(logstr)
            # IF SNMP Host is defined, then set the severity and add it to the list to send later
            if args.snmphost is not None:
                snmpvals['log_sev303'] = 3
                listSnmpVals.append(snmpvals.copy())
        elif (system_sev == "high"):
            if args.level in ['ERROR','WARNING','INFO']:
                locallog.debug("Writeing ERROR:%s",logstr)
                logger.setLevel(logging.ERROR)
                logger.error(logstr)
                # IF SNMP Host is defined, then set the severity and add it to the list to send later
                if args.snmphost is not None:
                    snmpvals['log_sev303'] = 2
                    listSnmpVals.append(snmpvals.copy())
        elif (system_sev == "medium"):
            if  args.level in ['WARNING','INFO']:
                locallog.debug("Writeing WARNING:%s",logstr)
                logger.setLevel(logging.WARNING)
                logger.warning(logstr)
                # IF SNMP Host is defined, then set the severity and add it to the list to send later
                if args.snmphost is not None:
                    snmpvals['log_sev303'] = 1
                    listSnmpVals.append(snmpvals.copy())
        elif (system_sev == 'informational'):
            if  args.level in ['INFO']:
                locallog.debug("Writeing INFO:%s",logstr)
                logger.setLevel(logging.INFO)
                logger.info(logstr)
                # IF SNMP Host is defined, then set the severity and add it to the list to send later      
                if args.snmphost is not None:
                    snmpvals['log_sev303'] = 0
                    listSnmpVals.append(snmpvals.copy())
        else:
            locallog.error("UNKNOWN message",logstr,child)
    # IF SNMP Host is defined, then send the list of Traps        
    if args.snmphost is not None:
        locallog.debug("Sending all the SNMP Traps")
        asyncio.run(trap(listSnmpVals))

    locallog.info("Successfully sent")

########## Function that sends the SNMP Trap
async def sendone(snmpEngine, hostname, notifyType, oidVals):
    errorIndication, errorStatus, errorIndex, varBinds = await sendNotification(
        snmpEngine,
        CommunityData("public", tag=hostname),
        UdpTransportTarget((hostname, 162), tagList=hostname),
        ContextData(),
        notifyType,
        NotificationType(ObjectIdentity("1.3.6.1.4.1.25461.2.1.3.2.0.600")).addVarBinds(
            ("1.3.6.1.4.1.25461.2.1.3.1.2", OctetString(oidVals['receive_time2'])),
            ("1.3.6.1.4.1.25461.2.1.3.1.3", OctetString(oidVals['serial_num3'])),
            ("1.3.6.1.4.1.25461.2.1.3.1.4", OctetString(oidVals['type4'])),
            ("1.3.6.1.4.1.25461.2.1.3.1.5", OctetString(oidVals['subtype5'])),
            ("1.3.6.1.4.1.25461.2.1.3.1.7", OctetString(oidVals['vsys7'])),
            ("1.3.6.1.4.1.25461.2.1.3.1.8", Counter64(oidVals['log_entry8'])),
            ("1.3.6.1.4.1.25461.2.1.3.1.9", OctetString("0x0")),
            ("1.3.6.1.4.1.25461.2.1.3.1.12", OctetString(oidVals['host_name12'])),
            ("1.3.6.1.4.1.25461.2.1.3.1.300", OctetString(oidVals['log_eventid300'])),
            ("1.3.6.1.4.1.25461.2.1.3.1.302", OctetString(oidVals['log_module302'])),
            ("1.3.6.1.4.1.25461.2.1.3.1.303", Integer(oidVals['log_sev303'])),
            ("1.3.6.1.4.1.25461.2.1.3.1.304", OctetString(oidVals['log_desc304']))
        ),
    )
    locallog.debug("Sent individual SNMP Trap '%s' S/N %i",oidVals['log_eventid300'],OctetString(oidVals['log_entry8']))

    if errorIndication:
        print(errorIndication)
    elif errorStatus:
        print(
            "{}: at {}".format(
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
            )
        )
# Good for debugging: Print what was sent
    # else:
    #     for varBind in varBinds:
    #         print(" = ".join([x.prettyPrint() for x in varBind]))

######### Function to send all the traps to the SNMP Engine
async def trap(oidValsList):
    snmpEngine = SnmpEngine()
    producers = [ asyncio.create_task (sendone(snmpEngine, "192.168.86.101", "inform", oidVals)) for oidVals in oidValsList ]
    await asyncio.gather(
        *producers
    )

if __name__ == "__main__":
    main()