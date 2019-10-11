#!/bin/env python

# ##################################################################
# # bsp led check
###################################################################

import os
import sys
import re
import time
import math

FAN01_PRESENT_L=(os.popen("cat /sys/class/gpio/gpio500/value").read()).rstrip('\n')
FAN23_PRESENT_L=(os.popen("cat /sys/class/gpio/gpio501/value").read()).rstrip('\n')
FAN45_PRESENT_L=(os.popen("cat /sys/class/gpio/gpio502/value").read()).rstrip('\n')
FAN67_PRESENT_L=(os.popen("cat /sys/class/gpio/gpio503/value").read()).rstrip('\n')

#############################################################
# Test bspGreenLed_check
#  1. Verify the gpio map with standard map in docstring
#  2. How to run:
#   $ python bsp_led.py -v    
#############################################################
def bspGreenLed_check(i):
    """Returns the values of gpio pins for LED
    >>> [bspGreenLed_check(i) for i in range(1,5,1)]
    /sys/class/leds/fan1:green brightness: 255
    /sys/class/leds/fan2:green brightness: 255
    /sys/class/leds/fan3:green brightness: 255
    /sys/class/leds/fan4:green brightness: 255
    [None, None, None, None]
    """
    value=os.popen("cat /sys/class/leds/fan%d:green/brightness" % i).read()
    value=value.rstrip('\n')
    retvalue=os.popen("echo -n /sys/class/leds/fan%d:green brightness: %s" % (i,value)).read()
    if i == 1:
        if FAN01_PRESENT_L == "1":
            print("%s" % retvalue)
        else:
            print("Fan module 1 absent") 
    if i == 2:
        if FAN23_PRESENT_L == "1":
            print("%s" % retvalue)
        else:
            print("Fan module 2 absent") 
    if i == 3:
        if FAN45_PRESENT_L == "1":
            print("%s" % retvalue)
        else:
            print("Fan module 3 absent")
    if i == 4:
        if FAN67_PRESENT_L == "1":
            print("%s" % retvalue)
        else:
            print("Fan module 4 absent")

            
#############################################################
# Test bspAmberLed_check
#  1. Verify the gpio map with standard map in docstring
#  2. How to run:
#   $ python bsp_led.py -v    
#############################################################
def bspAmberLed_check(i):
    """Returns the values of gpio pins
    from 352 to 503, Following pins are expecting
    1 by default but if say PS or fan is not
    present then it will be 0 and there is a separate
    expected docstring for them at the end
    >>> [bspAmberLed_check(i) for i in range(1,5,1)]
    /sys/class/leds/fan1:amber brightness: 0
    /sys/class/leds/fan2:amber brightness: 0
    /sys/class/leds/fan3:amber brightness: 0
    /sys/class/leds/fan4:amber brightness: 0
    [None, None, None, None]
    """
    value=os.popen("cat /sys/class/leds/fan%d:amber/brightness" % i).read()
    value=value.rstrip('\n')
    retvalue=os.popen("echo -n /sys/class/leds/fan%d:amber brightness: %s" % (i,value)).read()
    if i == 1:
        if FAN01_PRESENT_L == "1":
            print("%s" % retvalue)
        else:
            print("Fan module 1 absent") 
    if i == 2:
        if FAN23_PRESENT_L == "1":
            print("%s" % retvalue)
        else:
            print("Fan module 2 absent") 
    if i == 3:
        if FAN45_PRESENT_L == "1":
            print("%s" % retvalue)
        else:
            print("Fan module 3 absent")
    if i == 4:
        if FAN67_PRESENT_L == "1":
            print("%s" % retvalue)
        else:
            print("Fan module 4 absent")
            
            
if __name__ == '__main__':
    import doctest
    doctest.testmod()  
