### Palo-API-Notify

A Python script to read the logs via an API and forward them as Syslog messages and SNMP Traps

```
usage: apinotify.py [-h] [--conf CONF] [-f Firewall] [-u Username] [-p Password] [-a API Key] [--snmphost SNMPHOST] [-s Sylog host]
                    [-l {CRITICAL,ERROR,WARNING,INFO}] [-t TIMEFRAME] [-n NUMLOGS] [-v]

Retrieve the lastest NGFW log files for a period via api

options:
  -h, --help            show this help message and exit
  --conf CONF           Enter the config file instead of line items. If parameters are entered it will look for a file named 'config'
  -f Firewall, --firewall Firewall
                        firewall to access
  -u Username, --user Username
                        Username to access
  -p Password, --password Password
                        Password for username
  -a API Key, --apikey API Key
                        API Key
  --snmphost SNMPHOST   Snmp Host
  -s Sylog host, --syslog Sylog host
                        Host to forwards syslogs to (default 127.0.0.1)
  -l {CRITICAL,ERROR,WARNING,INFO}, --level {CRITICAL,ERROR,WARNING,INFO}
                        Minimum Forward Level (default INFO)
  -t TIMEFRAME, --timeframe TIMEFRAME
                        Log timeframe (Default 5)
  -n NUMLOGS, --numlogs NUMLOGS
                        Max number of logs (Default 100)
  -v, --verbose         increase output verbosity
```
