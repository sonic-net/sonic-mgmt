timeout: 20
iteration: 30
verbose: 3
schema: "openconfig"
connection: {
  address: "127.0.0.1:9339"
  timeout: 10
}

common {
  set_requests {
    key: "setreq"
    value {
      update {
        val {
          json_ietf_val :
       "{\"openconfig-platform:components\": {\"component\": [{\"name\": \"eth0\","
    "\"config\": { \"name\": \"eth0\", \"openconfig-hercules-platform:type\": "
    "\"openconfig-platform-types:PORT\" }, \"port\": { \"config\": { "
    "\"openconfig-hercules-platform:port-id\": 1 } } } ] }, "
    "\"openconfig-interfaces:interfaces\": {\"interface\": [{\"name\": "
    "\"eth0\",\"config\": {\"name\": \"eth0\",\"type\": "
    "\"iana-if-type:ethernetCsmacd\",\"openconfig-hercules-interfaces:id\": 1001},\"hold-time\": {\"config\": {\"up\": 100,\"down\": "
    "200}}}]}}";
          }
      }
    }
  }
  get_requests {
    key: "getreq"
    value {
      path {
        elem {
          name: "oc-if:interfaces"
        }
        elem {
          name: "interface"
        }
      }
      encoding: 4
    }
  }
  get_responses {
    key: "getres"
    value {
      notification {
        timestamp: 42
        update {
          val {
                  json_ietf_val: "{\n  \"data\": {\n    \"openconfig-interfaces:interfaces\": {\n      \"interface\": [\n        {\n          \"name\": \"eth0\",\n          \"config\": {\n            \"name\": \"eth0\",\n            \"type\": \"iana-if-type:ethernetCsmacd\",\n            \"openconfig-hercules-interfaces:id\": 1001\n          },\n          \"state\": {\n            \"loopback-mode\": false,\n            \"enabled\": true,\n            \"openconfig-vlan:tpid\": \"openconfig-vlan-types:TPID_0X8100\"\n          },\n          \"hold-time\": {\n            \"config\": {\n              \"up\": 100,\n              \"down\": 200\n            },\n            \"state\": {\n              \"up\": 0,\n              \"down\": 0\n            }\n          },\n          \"openconfig-if-ethernet:ethernet\": {\n            \"state\": {\n              \"auto-negotiate\": true,\n              \"enable-flow-control\": false,\n              \"openconfig-hercules-interfaces:forwarding-viable\": true\n            }\n          }\n        }\n      ]\n    }\n  }\n}\n"
          }
        }
      }
    }
  }
}

instance_group_list {
  description: "getreq"
  instance {
    description: "get1"
    test {
      get_set {
        oper_validation {
          test_oper {
            common_getrequest: "getreq"
          }
        }
      }
    }
  }
  instance {
    description: "get2"
    test {
      get_set {
        oper_validation {
          test_oper {
            common_getrequest: "getreq"
          }
        }
      }
    }
  }
  instance {
    description: "get3"
    test {
      get_set {
        oper_validation {
          test_oper {
            common_getrequest: "getreq"
          }
        }
      }
    }
  }
  instance {
    description: "get4"
    test {
      get_set {
        oper_validation {
          test_oper {
            common_getrequest: "getreq"
          }
        }
      }
    }
  }
  instance {
    description: "get5"
    test {
      get_set {
        oper_validation {
          test_oper {
            common_getrequest: "getreq"
          }
        }
      }
    }
  }
  instance {
    description: "get6"
    test {
      get_set {
        oper_validation {
          test_oper {
            common_getrequest: "getreq"
          }
        }
      }
    }
  }
  instance {
    description: "get7"
    test {
      get_set {
        oper_validation {
          test_oper {
            common_getrequest: "getreq"
          }
        }
      }
    }
  }
  instance {
    description: "get8"
    test {
      get_set {
        oper_validation {
          test_oper {
            common_getrequest: "getreq"
          }
        }
      }
    }
  }
  instance {
    description: "get9"
    test {
      get_set {
        oper_validation {
          test_oper {
            common_getrequest: "getreq"
          }
        }
      }
    }
  }
  instance {
    description: "get10"
    test {
      get_set {
        oper_validation {
          test_oper {
            common_getrequest: "getreq"
          }
        }
      }
    }
  }
}
