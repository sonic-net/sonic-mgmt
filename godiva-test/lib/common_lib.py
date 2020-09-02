#!/usr/bin/env python3
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
import argparse
import json
import logging
import os
import re
import ssl
import sys
import six
import paramiko
from time import sleep
import threading
from queue import Queue
from logger.cafylog import CafyLog
import grpc


def node_get(ip, uname, passwd, cmd):
    # Create instance of SSHClient object
    remote_conn_pre = paramiko.SSHClient()

    # Automatically add untrusted hosts (make sure okay for security policy in your environment)
    remote_conn_pre.set_missing_host_key_policy(
         paramiko.AutoAddPolicy())

    # initiate SSH connection
    remote_conn_pre.connect(ip, username=uname, password=passwd, look_for_keys=False, allow_agent=False)
    print ("SSH connection established to %s" % ip)

    # Use invoke_shell to establish an 'interactive session'
    remote_conn = remote_conn_pre.invoke_shell()
    print ("Interactive SSH session established")

    # Strip the initial router prompt
    output = remote_conn.recv(1000)

    # See what we have
    #print (output)
    #return remote_conn
    
    # Now let's try to send 'cmd' to the router
    remote_conn.send("\n")
    #remote_conn.send("free -m\n")
    remote_conn.sendall(cmd)

    # Wait for the command to complete
    sleep(5)
    
    output = remote_conn.recv(5000)
    return output
    