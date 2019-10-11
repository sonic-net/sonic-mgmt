#!/
import os, sys, re, time, shutil
CSI="\x1B["
GREEN=CSI+"30;42m"
RED=CSI+"30;41m"
END=CSI+"0m"
LOG_NUM = 0
LOG_MESSAGE_FILE = "/var/log/messages"
SENSORS_CONF_FILE = "/etc/sensors.d/sensors.conf"
SENSORS_CONF_FILE_BAK = "/etc/sensors.d/sensors.conf.bak"
TMP_SENSORS_CONF_FILE = "/tmp/sensors.conf"
TMP_SENSORS_DATA = "/tmp/sensors.data"
TEMP_SENSOR = "temp"
TEMP_SET = "set "
TEMP_MAX = "_max"
global sensor_ID, log_sensor_ID, sens, fans, powsups

def passit():
    print  GREEN+"PASS"+END

def failit():
    print RED +"FAIL"+END

def getTempSensorStr(sensor_ID):
    return TEMP_SENSOR + str(sensor_ID)

def getSetTempSensorMaxStr(sensor_ID):
    return TEMP_SET + getTempSensorStr(sensor_ID) + TEMP_MAX

def setSensor():
# Not sure
    set_sensor_cmd = "sensors -s"
    print os.popen(set_sensor_cmd).read()

def setSensorData():
# Not sure
    set_sensor_cmd = "sensors > /tmp/sensors.data"
    os.popen(set_sensor_cmd).read()

def createFansSnapshot():
    total = 0
    fans = 0
    setSensorData()
    f_conf_tmp = open(TMP_SENSORS_DATA)
    for line in f_conf_tmp:
      m = re.search(r'^Fan\d\-\d:\s+?(\d+?) RPM.*\n$',line)
      if (m):
         print (line)
         fans += 1
         total += int(m.group(1))
    avgRPM = int(total / fans)
    f_conf_tmp.close()
    return (avgRPM, fans)

def getPowerSupplies():
    total=0
    powsups=0
    setSensorData()#   
    f_conf_tmp = open(TMP_SENSORS_DATA)
    for line in f_conf_tmp:
      m = re.search(r'^(Input Voltage).*\n$',line)
      if (m):
         print (line)
         powsups += 1
    avgRPM = int(total / powsups)
    f_conf_tmp.close()
    return (powsups)

def setTempSensorMax(sensor_ID, max_temp):
    shutil.copyfile(SENSORS_CONF_FILE, TMP_SENSORS_CONF_FILE)
    f_conf_tmp = open(TMP_SENSORS_CONF_FILE)
    f_conf = open(SENSORS_CONF_FILE, "rw+")
    set_max_str = getSetTempSensorMaxStr(sensor_ID)
    for line in f_conf_tmp:
        if line.find(set_max_str) != -1:
            # replace the max temp in the file
            old_max_temp = line.split()[2]
            new_line = line.replace(old_max_temp, str(max_temp))
            f_conf.write(new_line)
        else:
            f_conf.write(line)
    f_conf.flush()
    f_conf.close()
    f_conf_tmp.close()

def getAlarmOn():  #Just 1 alarm
      global sensor_ID
      alarms = 0
      set_alarm = " high ="
      setSensorData()
      f_conf_tmp = open(TMP_SENSORS_DATA)
      for line in f_conf_tmp:
          if line.find(set_alarm) != -1 :
             print(line)
             if line.find("ALARM") != -1 :
                end = line.find(')')
                sensor_ID = line[:end+1]
                alarms += 1
      f_conf_tmp.close()
      return (alarms, sensor_ID)

def backupSensorConf():
    shutil.copyfile(SENSORS_CONF_FILE, SENSORS_CONF_FILE_BAK)

def restoreSensorConf():
    shutil.copyfile(SENSORS_CONF_FILE_BAK, SENSORS_CONF_FILE)

def cleanMessageLog():
    os.system("truncate /var/log/messages --size 0")

def verifyMessageLog(pattern):
    global log_sensor_ID, sens
    f_log = open(LOG_MESSAGE_FILE,'r')
    found = 0
    index = 0
    sens = 0
    due_to = 0
    dup = -1
    for line in f_log:
      for index in range(4) :
        if line.find(pattern[index]) >=0 :
           sens = line.find("sensor:")
           if sens >=0 :
             print line[sens+8:]
             end = line[sens+8:].find(')')
             log_sensor_ID = line[sens+8:][:end+1]
           else:
             print("found pattern: %s in line: %s" % (pattern[index],line))
        found += line.count(pattern[index]) 
# Need 'due to' to be more prominent
      due_to = line.find("due to")
      if due_to >= 0 and due_to != dup :
        print("Alarm "+line[due_to:])
        dup = due_to
    if found >= 1:
        return (True, log_sensor_ID)
    else:
        return (False, log_sensor_ID)
