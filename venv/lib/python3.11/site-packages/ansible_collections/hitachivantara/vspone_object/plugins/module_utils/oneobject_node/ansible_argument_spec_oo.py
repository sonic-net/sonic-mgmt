class OOArgumentSpec:
    @staticmethod
    def connection_info():
        return {
            "connection_info": {
                "required": True,
                "type": "dict",
                "options": {
                    "http_request_timeout": {
                        "type": "int",
                        "required": True
                    },
                    "http_request_retry_times": {

                        "type": "int",
                        "required": True
                    },
                    "http_request_retry_interval_seconds": {

                        "type": "int",
                        "required": True
                    },
                    "cluster_name": {
                        "type": "str",
                        "required": True
                    },
                    "region": {
                        "type": "str",
                        "required": True
                    },
                    "oneobject_node_username": {
                        "type": "str",
                        "required": True
                    },
                    "oneobject_node_userpass": {
                        "type": "str",
                        "required": True,
                        "no_log": True
                    },
                    "oneobject_node_client_id": {
                        "type": "str",
                        "required": True
                    },
                    "oneobject_node_client_secret": {
                        "type": "str",
                        "required": False,
                        "no_log": True
                    },
                    "ssl": {
                        "type": "dict",
                        "required": False,
                        "options": {
                            "validate_certs": {
                                "type": "bool",
                                "required": True
                            },
                            "client_cert": {
                                "type": "str",
                                "required": False,
                                "default": ""
                            },
                            "client_key": {
                                "type": "str",
                                "required": False,
                                "default": "",
                                "no_log": False
                            },
                            "ca_path": {
                                "type": "str",
                                "required": False,
                                "default": ""
                            },
                            "ssl_version": {
                                "type": "str",
                                "required": False,
                                "default": ""
                            },
                            "ca_certs": {
                                "type": "str",
                                "required": False,
                                "default": ""
                            },
                            "ssl_cipher": {
                                "type": "str",
                                "required": False,
                                "default": ""
                            },
                            "check_hostname": {
                                "type": "bool",
                                "required": False,
                                "default": False
                            }
                        }
                    }
                }
            }
        }

    @staticmethod
    def storage_class():
        fields = OOArgumentSpec.connection_info()

        fields["spec"] = {
            "type": "dict",
            "required": False,
            "options": {
                "id": {
                    "type": "str",
                    "required": False
                },
            }
        }

        return fields

    @staticmethod
    def create_storage_class():
        fields = OOArgumentSpec.connection_info()
        fields["state"] = {
            "type": "str",
            "choices": ['present', 'default'],
            "required": False,
        }

        fields["spec"] = {
            "type": "dict",
            "required": True,
            "options": {
                "name": {
                    "type": "str",
                    "required": False
                },
                "data_count": {
                    "type": "int",
                    "required": False
                },
                "parity_count": {
                    "type": "int",
                    "required": False
                },
                "id": {
                    "type": "str",
                    "required": False
                },
            }
        }

        return fields

    @staticmethod
    def storage_fault_domain_facts():
        fields = OOArgumentSpec.connection_info()

        fields["spec"] = {
            "type": "dict",
            "required": False,
            "options": {
                "page_size": {
                    "type": "int",
                    "required": False
                },
                "id": {
                    "type": "str",
                    "required": False
                },
            }
        }

        return fields

    @staticmethod
    def storage_class_info():
        fields = OOArgumentSpec.connection_info()

        fields["spec"] = {
            "type": "dict",
            "required": True,
            "options": {
                "id": {
                    "type": "str",
                    "required": True
                },
            }
        }

        return fields

    @staticmethod
    def certificate_info():
        fields = OOArgumentSpec.connection_info()

        fields["spec"] = {
            "type": "dict",
            "required": False,
            "options": {
                "subject_dn": {
                    "type": "str",
                    "required": False
                },
            }
        }

        return fields

    @staticmethod
    def storage_class_fact():
        fields = OOArgumentSpec.connection_info()

        fields["spec"] = {
            "type": "dict",
            "required": False,
            "options": {
                "id": {
                    "type": "str",
                    "required": False
                },
                "page_size": {
                    "type": "int",
                    "required": False
                },
                "query_type": {
                    "type": "str",
                    "required": False,
                    "choices": ['regular', 'default'],
                    "default": 'regular'
                },
            }
        }

        return fields

    @staticmethod
    def create_update_storage_fault_domain():
        fields = OOArgumentSpec.connection_info()

        fields["state"] = {
            "type": "str",
            "choices": ["present"],
            "required": False
        }

        fields["spec"] = {
            "type": "dict",
            "required": True,
            "options": {
                "name": {
                    "type": "str",
                    "required": False
                },
                "tags": {
                    "type": "str",
                    "required": False,
                },
                "id": {
                    "type": "str",
                    "required": False,
                    "default": ""
                }
            }
        }

        return fields

    @staticmethod
    def set_serial_number():
        fields = OOArgumentSpec.connection_info()

        fields["state"] = {
            "type": "str",
            "choices": ["present"],
            "required": False
        }

        fields["spec"] = {
            "type": "dict",
            "required": True,
            "options": {
                "serial_number": {
                    "type": "str",
                    "required": True
                }
            }
        }

        return fields

    @staticmethod
    def storage_component():
        fields = OOArgumentSpec.connection_info()
        fields["state"] = {
            "type": "str",
            "choices": ['activate', 'test', 'present'],
            "required": False
        }

        fields["spec"] = {
            "type": "dict",
            "required": True,
            "options": {
                "id": {
                    "type": "str",
                    "required": False
                },
                "storage_type": {
                    "type": "str",
                    "choices": ['HCPS_S3', 'ARRAY'],
                    "required": False
                },
                "storage_custom_metadata": {
                    "type": "dict",
                    "required": False
                },
                "storage_component_config": {
                    "type": "dict",
                    "required": False,
                    "options": {
                        "label": {"type": "str", "required": False},
                        "host": {"type": "str", "required": False},
                        "storage_class": {"type": "str", "required": False},
                        "storage_fault_domain": {"type": "str", "required": False},
                        "uri_scheme": {"type": "str", "required": False,
                                       "choices": ['HTTP', 'HTTPS']},
                        "port": {"type": "str", "required": False},
                        "bucket": {"type": "str", "required": False},
                        "region": {"type": "str", "required": False},
                        "auth_type": {"type": "str", "choices": ['V2', 'V4'],
                                      "required": False,
                                      "default": 'V2'},
                        "access_key": {"type": "str", "required": False, "no_log": True},
                        "secret_key": {"type": "str", "required": False, "no_log": True},
                        "use_proxy": {"type": "bool", "required": False},
                        "proxy_host": {"type": "str", "required": False},
                        "proxy_port": {"type": "str", "required": False},
                        "proxy_user_name": {"type": "str", "required": False, "no_log": True},
                        "proxy_password": {"type": "str", "required": False, "no_log": True},
                        "management_user": {"type": "str", "required": False, "no_log": True},
                        "management_password": {"type": "str", "required": False, "no_log": True},
                        "management_protocol": {"type": "str", "required": False},
                        "management_host": {"type": "str", "required": False},
                        "use_path_style_always": {"type": "bool", "required": False},
                        "activate_now": {"type": "bool", "required": False, "default": True},
                        "proxy_domain": {"type": "str", "required": False},
                        "connection_timeout": {"type": "int", "required": False},
                        "socket_timeout": {"type": "int", "required": False},
                        "connection_ttl": {"type": "int", "required": False},
                        "max_connections": {"type": "int", "required": False},
                        "user_agent_prefix": {"type": "str", "required": False},
                        "socket_send_buffer_size_hint": {"type": "int", "required": False},
                        "socket_recv_buffer_size_hint": {"type": "int", "required": False},
                        # "read_only": {"type": "bool", "required": False,
                        #               "default": False
                        #               },
                        "namespace": {"type": "str", "required": False},
                        "data_persistent_volume_name": {"type": "str", "required": False},
                        "data_claim_capacity": {"type": "str", "required": False},
                        "node": {"type": "str", "required": False},
                        "array_name": {"type": "str", "required": False},
                        "array_storage_tier": {"type": "str", "required": False},
                    }
                }
            }
        }

        return fields

    @staticmethod
    def s3_user_credentials():
        fields = OOArgumentSpec.connection_info()
        fields["state"] = {
            "type": "str",
            "choices": ["generate", "revoke"],
            "required": True
        }

        fields["spec"] = {
            "type": "dict",
            "required": False,
            "options": {
                "id": {
                    "type": "int",
                    "required": False
                },
            }
        }

        return fields

    @staticmethod
    def storage_component_state_update():
        fields = OOArgumentSpec.connection_info()

        fields["state"] = {
            "type": "str",
            "choices": ["present"],
            "required": False
        }

        fields["spec"] = {
            "type": "dict",
            "required": True,
            "options": {
                "storage_component_state": {
                    "type": "str",
                    "required": True,
                    "choices": ["DECOMMISSION", "ACTIVE", "PAUSED", "READ_ONLY"]
                },
                "id": {
                    "type": "str",
                    "required": True
                }
            }
        }

        return fields

    @staticmethod
    def storage_component_facts():
        fields = OOArgumentSpec.connection_info()

        fields["spec"] = {
            "type": "dict",
            "required": False,
            "options": {
                "query": {
                    "type": "str",
                    "required": False
                },
                "page_size": {
                    "type": "int",
                    "required": False
                },
            }
        }

        return fields

    @staticmethod
    def kmip_server_fact():
        fields = OOArgumentSpec.connection_info()

        fields["spec"] = {
            "type": "dict",
            "required": False,
            "options": {
                "name": {
                    "type": "str",
                    "required": False
                },
            }
        }

        return fields

    @staticmethod
    def user_buckets():
        fields = OOArgumentSpec.connection_info()

        fields["spec"] = {
            "type": "dict",
            "required": True,
            "options": {
                "id": {
                    "type": "str",
                    "required": True
                },
                "count" : {
                    "type": "int",
                    "required": False,
                    "default": 1000
                },
            }
        }

        return fields

    @staticmethod
    def certificate():
        fields = OOArgumentSpec.connection_info()
        fields["state"] = {
            "type": "str",
            "choices": ['present', 'absent'],
            "required": False
        }

        fields["spec"] = {
            "type": "dict",
            "required": True,
            "options": {
                "cert_file_path": {
                    "type": "str",
                    "required": False
                },
                "delete_cert_dn": {
                    "type": "str",
                    "required": False
                }
            }
        }

        return fields

    @staticmethod
    def set_s3_encryption():
        fields = OOArgumentSpec.connection_info()

        fields["state"] = {
            "type": "str",
            "choices": ["present"],
            "required": False
        }

        fields["spec"] = {
            "type": "dict",
            "required": True,
            "options": {
                "encryption_mode": {
                    "type": "str",
                    "required": True
                }
            }
        }

        return fields

    @staticmethod
    def user_id():
        fields = OOArgumentSpec.connection_info()

        fields["spec"] = {
            "type": "dict",
            "required": False,
            "options": {
                "user_uuid": {
                    "type": "str",
                    "required": False
                },
            }
        }

        return fields

    @staticmethod
    def kmip():
        fields = OOArgumentSpec.connection_info()

        fields["state"] = {
            "type": "str",
            "required": True,
            "choices": ["present", "absent", "promote", "modify"]
        }

        fields["spec"] = {
            "type": "dict",
            "required": True,
            "options": {
                "name": {
                    "type": "str",
                    "required": True
                },
                "port": {
                    "type": "int",
                    "required": False
                },
                "host": {
                    "type": "str",
                    "required": False
                },
                "is_tls12_enabled": {
                    "type": "bool",
                    "required": False,
                    "default": True
                },
                "kmip_protocol": {
                    "type": "str",
                    "required": False,
                    "default": 'V1_4'
                },
                'https_ciphers': {
                    "type": "str",
                    "required": False,
                },
                'uuid': {
                    "type": "str",
                    "required": False,
                }
            }
        }

        return fields

    @staticmethod
    def license():
        fields = OOArgumentSpec.connection_info()

        fields["state"] = {
            "type": "str",
            "choices": ["present"],
            "required": False
        }

        fields["spec"] = {
            "type": "dict",
            "required": True,
            "options": {
                "license_file_path": {
                    "type": "str",
                    "required": True
                },
            }
        }

        return fields

    @staticmethod
    def troubleshooting():

        fields = {}

        fields["log_bundle_retention_count"] = {
            "type": "int",
            "required": False,
            "default": 3
        }

        return fields

    @staticmethod
    def job_operation():
        fields = OOArgumentSpec.connection_info()

        fields["state"] = {
            "type": "str",
            "choices": ['present', 'absent'],
            "required": True
        }

        fields["spec"] = {
            "type": "dict",
            "required": True,
            "options": {
                "job_type": {
                    "type": "str",
                    "required": False,
                    "choices": ['BATCH_REPLICATE', 'LIFECYCLE_UPDATE', 'METRIC_RECONCILIATION', 'TRIGGER_RECONCILIATION'],
                },
                "bucket_name": {
                    "type": "str",
                    "required": False,
                },
                "job_parameters": {
                    "type": "dict",
                    "required": False,
                },
                "job_id": {
                    "type": "int",
                    "required": False,
                },
            }
        }

        return fields

    @staticmethod
    def jobs_facts():
        fields = OOArgumentSpec.connection_info()

        fields["spec"] = {
            "type": "dict",
            "required": False,
            "options": {
                "query_type": {
                    "choices": ['ALL', 'STATUS'],
                    "type" : "str",
                    "required": False
                },
                "page_size": {
                    "type": "int",
                    "required": False
                },
                "job_id": {
                    "type": "int",
                    "required": False
                },
                "user_id": {
                    "type": "int",
                    "required": False
                },
                "bucket_name": {
                    "type": "str",
                    "required": False
                },
            }
        }

        return fields

    @staticmethod
    def events():
        fields = OOArgumentSpec.connection_info()

        fields["spec"] = {
            "type": "dict",
            "required": True,
            "options": {
                "query_type": {
                    "choices": ['GMS', 'SYSTEM'],
                    "type" : "str",
                    "required": True
                },
                "count": {
                    "type": "int",
                    "required": False,
                },
                "severity": {
                    "type": "str",
                    "required": False,
                    "choices": ['INFO', 'SEVERE', 'WARNING']
                },
                "user": {
                    "type": "int",
                    "required": False,
                },
                "start_timestamp": {
                    "type": "str",
                    "required": False,
                },
                "end_timestamp": {
                    "type": "str",
                    "required": False,
                },
                "category": {
                    "type": "str",
                    "required": False,
                },
                "event_type_id": {
                    "type": "int",
                    "required": False,
                },

            }
        }

        return fields
