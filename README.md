# TA-prtg

this is a fork of https://github.com/dominiquevocat/TA-prtg rewritten to python3

Custom commands to use the PRTG Webapi from Splunk. Includes a dashboard with an overview of your PRTG Data illustrating the usage and/or directly useful to you i guess.

Config is in prtg.conf in \local only!

Currently implemented:

| prtgws api="table" columns="objid,type,group,device,sensor,status,message,lastvalue,priority,favorite" 
gets you the inventory

| prtglivedata content="status" | fields Alarms
gets you the alarms, generally content="" equals to the api call on prtg http api.

| prtglivedata content="sensors" filter_status=5 count=100 | table \_time,device,group,message,sensor,status,objid
gets you the sensors marked as DOWN (filter_type=5)

| prtglivedata content=sensordetails id=2071  | fields - \_raw,\_time,source,sourcetype ,host |transpose | rename column AS Key | rename "row 1" AS Value
gets you the sensordetails for sensor 2071

| prtghistoricdata id=2071 count=1 | fields - \_raw,\_time,*(RAW),source,sourcetype,host |  transpose | rename column AS Key | rename "row 1" AS Value
will give you the current measurement for sensor 2071

| prtghistoricdata id=2071  | timechart max("Traffic Total (speed)(RAW)")
will get you the sensordata from the timerange of the search for the sensor 2071 and chart the series "Traffic Total (speed)(RAW)" (we use a SNMP traffic sensor for this example.
