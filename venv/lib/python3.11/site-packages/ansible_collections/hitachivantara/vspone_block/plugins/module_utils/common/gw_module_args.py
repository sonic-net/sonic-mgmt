# -*- coding: utf-8 -*-

DEPCRECATED_MSG = "This module is deprecated and can't be used anymore. Please use 3.3.0 version of this module."


class GatewayArgs:

    COMMON_ARGS = {
        "required": True,
        "type": "dict",
        "options": {
            "address": {
                "required": True,
                "type": "str",
            },
            "username": {
                "required": False,
                "type": "str",
            },
            "password": {
                "required": False,
                "no_log": True,
                "type": "str",
            },
            "api_token": {
                "required": False,
                "type": "str",
                "no_log": True,
            },
            "subscriber_id": {
                "required": False,
                "type": "str",
            },
            "connection_type": {
                "required": False,
                "type": "str",
                "choices": ["gateway"],
                "default": "gateway",
            },
        },
    }
    STATE = {
        "required": False,
        "type": "str",
        "choices": ["present", "absent"],
        "default": "present",
    }

    STORAGE_SYSTEM_INFO = {
        "required": False,
        "type": "dict",
        "options": {
            "serial": {
                "required": True,
                "type": "str",
            },
        },
    }

    def get_subscriber_facts_args(self):
        self.COMMON_ARGS["options"].pop("subscriber_id", None)
        return {
            "connection_info": self.COMMON_ARGS,
            "spec": {
                "required": False,
                "type": "dict",
                "options": {
                    "subscriber_id": {
                        "required": False,
                        "type": "str",
                    },
                },
            },
        }

    def get_subscriber_args(self):
        self.COMMON_ARGS["options"].pop("subscriber_id", None)
        return {
            "connection_info": self.COMMON_ARGS,
            "state": self.STATE,
            "spec": {
                "required": True,
                "type": "dict",
                "options": {
                    "subscriber_id": {
                        "required": True,
                        "type": "str",
                    },
                    "name": {
                        "required": False,
                        "type": "str",
                    },
                    "soft_limit": {
                        "required": False,
                        "type": "str",
                    },
                    "hard_limit": {
                        "required": False,
                        "type": "str",
                    },
                    "quota_limit": {
                        "required": False,
                        "type": "str",
                    },
                    "description": {
                        "required": False,
                        "type": "str",
                    },
                },
            },
        }

    def get_subscription_facts_args(self):
        self.COMMON_ARGS["options"]["subscriber_id"] = {
            "required": False,
            "type": "str",
        }
        return {
            "connection_info": self.COMMON_ARGS,
            "storage_system_info": self.STORAGE_SYSTEM_INFO,
        }

    def get_unsubscribe_resource_args(self):
        self.COMMON_ARGS["options"].pop("username", None)
        self.COMMON_ARGS["options"].pop("password", None)
        self.COMMON_ARGS["options"]["subscriber_id"] = {
            "required": False,
            "type": "str",
        }
        return {
            "connection_info": self.COMMON_ARGS,
            "storage_system_info": self.STORAGE_SYSTEM_INFO,
            "spec": {
                "required": True,
                "type": "dict",
                "options": {
                    "resources": {
                        "required": True,
                        "type": "list",
                        "elements": "dict",
                        "options": {
                            "type": {
                                "required": True,
                                "type": "str",
                            },
                            "values": {
                                "required": True,
                                "type": "list",
                                "elements": "str",
                            },
                        },
                    },
                },
            },
        }

    def gateway_password(self):

        return {
            "connection_info": {
                "required": True,
                "type": "dict",
                "options": {
                    "uai_gateway_address": {
                        "required": True,
                        "type": "str",
                    },
                    "api_token": {
                        "required": True,
                        "type": "str",
                        "no_log": True,
                    },
                },
            },
            "spec": {
                "required": False,
                "type": "dict",
                "options": {
                    "password": {
                        "required": True,
                        "type": "str",
                        "no_log": True,
                    },
                },
            },
        }

    def uaig_token_args(self):
        return {
            "connection_info": {
                "required": True,
                "type": "dict",
                "options": {
                    "address": {
                        "required": True,
                        "type": "str",
                    },
                    "username": {
                        "required": True,
                        "type": "str",
                    },
                    "password": {
                        "required": True,
                        "no_log": True,
                        "type": "str",
                    },
                },
            }
        }
