# Author: Dominique Vocat
# Contact the prtg api via REST and queries stuff, returns the json to splunk.

import sys,os,json,logging,logging.handlers,time
from configparser import ConfigParser
from urllib.parse import urlencode
from urllib.request import HTTPBasicAuthHandler, build_opener, install_opener, urlopen
import splunklib.client as client
import splunk
import traceback
import splunk.Intersplunk
import urllib

Debugging = "no"

min_time_key = "info_min_time"
max_time_key = "info_max_time"
query_id_key = "info_search_time"
search_name_key = "search_name"
infinity = 10E200

import sys, os
sys.path.append(os.path.join(os.environ['SPLUNK_HOME'],'etc','apps','SA-VSCode','bin'))
import splunk_debug as dbg
dbg.enable_debugging(timeout=25)

# (isgetinfo, sys.argv) = client.isGetInfo(sys.argv)

# if isgetinfo:
#     client.outputInfo(False, False, False, True, "| rest /services/search/jobs count=1 | addinfo", False)

def setup_logging(n):
    logger = logging.getLogger(n)  # Root-level logger
    if Debugging == "yes":
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.ERROR)
    SPLUNK_HOME = os.environ['SPLUNK_HOME']
    LOGGING_DEFAULT_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'log.cfg')
    LOGGING_LOCAL_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'log-local.cfg')
    LOGGING_STANZA_NAME = 'python'
    LOGGING_FILE_NAME = "prtg.log"
    BASE_LOG_PATH = os.path.join('var', 'log', 'splunk')
    LOGGING_FORMAT = "%(asctime)s %(levelname)-s\t%(module)s:%(lineno)d - %(message)s"
    splunk_log_handler = logging.handlers.RotatingFileHandler(os.path.join(SPLUNK_HOME, BASE_LOG_PATH, LOGGING_FILE_NAME), mode='a')
    splunk_log_handler.setFormatter(logging.Formatter(LOGGING_FORMAT))
    logger.addHandler(splunk_log_handler)
    splunk.setupSplunkLogger(logger, LOGGING_DEFAULT_CONFIG_FILE, LOGGING_LOCAL_CONFIG_FILE, LOGGING_STANZA_NAME)
    return logger

# Start the logger
try:
    logger = setup_logging("prtgws")
    logger.info("INFO: Go Go Gadget Go!")
except Exception as e:
    import traceback
    stack = traceback.format_exc()
    splunk.generateErrorResults(f"Error : Traceback: '{e}'. {stack}")

# -----------=================-----------------
# handle parameters
# -----------=================-----------------

# Define empty lists
result_set = []
results = []

# Named options
try:
    logger.info("Getting Splunk options...")
    keywords, options = splunk.Intersplunk.getKeywordsAndOptions()

    section_name = options.get('server', 'default')
    api = options.get('api', '')
    searchkey = options.get('searchkey', '')
    searchvalue = options.get('searchvalue', '')
    content = options.get('content', 'messages')
    count = options.get('count', '50000')
    columns = options.get('columns', '')
    id = options.get('id', '')
    avg = options.get('avg', '0')
    mystarttime = options.get('starttime', '')
    myendtime = options.get('endtime', '')

    if api == "historicdata":
        try:
            results = splunk.Intersplunk.readResults(None, None, True)
            min_time = results[0]["info_min_time"]
            max_time = results[0]["info_max_time"]

            sdate = str(time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime(float(min_time))))
            edate = str(time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime(float(max_time))))
        except Exception as e:
            stack = traceback.format_exc()
            logger.info("INFO: no option provided using [default]!")

    results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()

    logger.info(f"mystarttime {mystarttime}")
    logger.info(f"myendtime {myendtime}")

except Exception as e:
    stack = traceback.format_exc()
    logger.info("INFO: no option provided using [default]!")

# -----------=================-----------------
# read config file
# -----------=================-----------------
if Debugging == "yes":
	logger.debug( "DEBUG - section name: " + section_name )
	print(str(section_name))
	logger.debug( "DEBUG - ipaddress: " + ipaddress )
	print(str(ipaddress))

try:
    logger.info("Read the .conf...")
    scriptDir = sys.path[0]
    configLocalFileName = os.path.join(scriptDir, '..', 'local', 'prtg.conf')

    parser = ConfigParser()
    # Read .conf options; if empty, use settings from [default] in prtg.conf
    parser.read(configLocalFileName)

    if not os.path.exists(configLocalFileName):
        exit(0)

except Exception as e:
    stack = traceback.format_exc()
    logger.error("ERROR: No config found! Check your prtg.conf in local.")

# Use user provided options or get [default] stanza options
try:
    logger.info("Read the default options from .conf...")
    SERVER = parser.get(section_name, 'server')
    PROTOCOL = parser.get(section_name, 'protocol')
    USERNAME = parser.get(section_name, 'user')
    PASSWORD = parser.get(section_name, 'password')

except Exception as e:
    stack = traceback.format_exc()
    logger.error("ERROR: No [default] section seems to be defined.")

# -----------=================-----------------
# request the webservice
# -----------=================-----------------
if Debugging == "yes":
    print(SERVER)
    print(USERNAME)
    print(PASSWORD)
    logger.debug("DEBUG - SERVER " + SERVER)
    logger.debug("DEBUG - USERNAME " + USERNAME)
    logger.debug("DEBUG - PASSWORD " + PASSWORD)

try:
    if api == "table":
        #url="https://"+SERVER+"/wapi/v1.2.1/"+api
        url = f"{PROTOCOL}://{SERVER}/api/table.xml"
        values={ 'username' : USERNAME,
                    'password' : PASSWORD,
                    'output' : 'csvtable',
                    'count' : count,
                    'columns' : columns,
                    'id' : id}

        data = urllib.parse.urlencode(values)
        #data = urllib.urlencode(values)


    if api == "messages":
        #url="https://"+SERVER+"/wapi/v1.2.1/"+api
        if columns == '':
            columns="objid,datetime,parent,type,name,status,message"
        url = f"{PROTOCOL}://{SERVER}/api/table.xml"
        values={ 'username' : USERNAME,
                    'password' : PASSWORD,
                    'content' : api,
                    'output' : 'csvtable',
                    'count' : count,
                    'columns' : columns,
                    'id' : id}
        data = urllib.parse.urlencode(values)

    if api == "history":
        #url="https://"+SERVER+"/wapi/v1.2.1/"+api
        if columns == '':
            columns="dateonly,timeonly,user,message"
        url = f"{PROTOCOL}://{SERVER}/api/table.xml"
        values={ 'username' : USERNAME,
                    'password' : PASSWORD,
                    'content' : api,
                    'output' : 'csvtable',
                    'count' : count,
                    'columns' : columns,
                    'id' : id}
        data = urllib.parse.urlencode(values)

    if api == "sensortree":
        #url="https://"+SERVER+"/wapi/v1.2.1/"+api
        url = f"{PROTOCOL}://{SERVER}/api/table.xml"
        values={ 'username' : USERNAME,
                    'password' : PASSWORD,
                    'content' : api,
                    'count' : count,
                    'output' : 'xml',
                    'columns' : columns,
                    'id' : id}
        data = urllib.parse.urlencode(values)

    if api == "devices":
        #url="https://"+SERVER+"/wapi/v1.2.1/"+api
        if columns == '':
            columns="objid,group,device,sensor,status,priority,favorite"
        url = f"{PROTOCOL}://{SERVER}/api/table.csv"
        values={ 'username' : USERNAME,
                    'password' : PASSWORD,
                    'content' : api,
                    'output' : 'csvtable',
                    'count' : count,
                    'columns' : columns,
                    'id' : id}
        data = urllib.parse.urlencode(values)

    if api == "sensors":
        #url="https://"+SERVER+"/wapi/v1.2.1/"+api
        if columns == '':
            columns="objid,group,device,sensor,status,priority,favorite"
        url = f"{PROTOCOL}://{SERVER}/api/table.xml"
        values={ 'username' : USERNAME,
                    'password' : PASSWORD,
                    'content' : api,
                    'output' : 'csvtable',
                    'count' : count,
                    'columns' : columns,
                    'id' : id}
        data = urllib.parse.urlencode(values)

    if api == "alarms":
        #url="https://"+SERVER+"/wapi/v1.2.1/"+api
        if columns == '':
            columns="objid,group,device,sensor,status,priority,favorite"
        url = f"{PROTOCOL}://{SERVER}/api/table.xml"
        values={ 'username' : USERNAME,
                    'password' : PASSWORD,
                    'content' : 'sensors',
                    'count' : count,
                    'output' : 'csvtable',
                    'count' : '*',
                    #'filter_status' : '4,5,10',
                    #'filter_status' : '5',
                    #'filter_status' : '10',
                    'columns' : columns}
        data = urllib.parse.urlencode(values)

    if api == "tickets":
        #url="https://"+SERVER+"/wapi/v1.2.1/"+api
        if columns == '':
            columns= "name,tags,status,message,priority,datetime,tickettype,modifiedby"
        url = f"{PROTOCOL}://{SERVER}/api/table.xml"
        values={ 'username' : USERNAME,
                    'password' : PASSWORD,
                    'content' : api,
                    'output' : 'csvtable',
                    'count' : count,
                    'columns' : columns,
                    'id' : id}
        data = urllib.parse.urlencode(values)

    if api == "groups":
        #url="https://"+SERVER+"/wapi/v1.2.1/"+api
        if columns == '':
            columns= "objid,probe,group,name,downsens,partialdownsens,downacksens,upsens,warnsens,pausedsens,unusualsens,undefinedsens"
        url = f"{PROTOCOL}://{SERVER}/api/table.xml"
        values={ 'username' : USERNAME,
                    'password' : PASSWORD,
                    'content' : api,
                    'output' : 'csvtable',
                    'count' : count,
                    'columns' : columns,
                    'id' : id}
        data = urllib.parse.urlencode(values)

    if api == "historicdata":
        url = f"{PROTOCOL}://{SERVER}/api/table.xml"
        values={ 'username' : USERNAME,
                    'password' : PASSWORD,
                    'id': id,
                    'sdate' : sdate,
                    'edate' : edate,
                    'avg' : avg}
        data = urllib.parse.urlencode(values)

    if api == "sensordetails":
        url = f"{PROTOCOL}://{SERVER}/api/table.xml"
        values={ 'username' : USERNAME,
                    'password' : PASSWORD,
                    'id': id}
        data = urllib.parse.urlencode(values)

    if api == "status":
        url = f"{PROTOCOL}://{SERVER}/api/table.xml"
        values={ 'username' : USERNAME,
                    'password' : PASSWORD,
                    'id': '0'}
        data = urllib.parse.urlencode(values)

    if api == "sensortypes":
        url = f"{PROTOCOL}://{SERVER}/api/table.xml"
        values={ 'username' : USERNAME,
                    'password' : PASSWORD}
        data = urllib.parse.urlencode(values)

    passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    passman.add_password(None, url, USERNAME, PASSWORD)
    authhandler = urllib.request.HTTPBasicAuthHandler(passman)
    opener = urllib.request.build_opener(authhandler)
    urllib.request.install_opener(opener)
    pagehandle = urllib.request.urlopen(url + "?" + data)


    # -----------=================-----------------
    # handle json2splunk
    # -----------=================-----------------

    #results=json.loads(pagehandle.read())
    #results=pagehandle.read()

    if api == "sensordetails":
        # results=json.loads(pagehandle.read())
        results = pagehandle.read().decode('utf-8')
        results = results.replace("\r", "")
        results = results.replace("\n", "")
        print("_raw\n" + results)  # splunk.Intersplunk.outputResults( results )
    elif api == "sensortree":
        # results=json.loads(pagehandle.read())
        results = pagehandle.read().decode('utf-8')
        results = results.replace("\r", "")
        results = results.replace("\n", "")
        print("_raw\n" + results)  # splunk.Intersplunk.outputResults( results )
    elif api == "sensortypes":
        results = json.loads(pagehandle.read().decode('utf-8'))
        print(results)  # splunk.Intersplunk.outputResults( results )
    elif api == "status":
        results = pagehandle.read().decode('utf-8')
        results = results.replace("\r", "")
        results = results.replace("\n", "")
        print("_raw\n" + results)  # splunk.Intersplunk.outputResults( results )
    else:
        results = pagehandle.read().decode('utf-8')
        print(results)

except Exception as e:
    stack = traceback.format_exc()

