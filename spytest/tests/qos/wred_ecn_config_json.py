wred_ecn_json_config = {
   	"WRED_PROFILE": {
        "WRED": {
            "ecn": "ecn_all",
            "red_max_threshold": "100000",
            "wred_green_enable": "true",
            "green_min_threshold": "100000",
            "red_min_threshold": "10000",
			"wred_yellow_enable": "true",
            "yellow_min_threshold": "30000",
            "wred_red_enable": "true",
            "yellow_max_threshold": "300000",
            "green_max_threshold": "900000",
			"green_drop_probability": "10",
			"yellow_drop_probability": "40",
			"red_drop_probability": "50"
        }
    }
}
wred_config_json = {
   	"WRED_PROFILE": {
        "WRED": {
            "ecn": "ecn_none",
            "red_max_threshold": "100000",
            "wred_green_enable": "true",
            "green_min_threshold": "100000",
            "red_min_threshold": "10000",
			"wred_yellow_enable": "true",
            "yellow_min_threshold": "30000",
            "wred_red_enable": "true",
            "yellow_max_threshold": "300000",
            "green_max_threshold": "900000",
			"green_drop_probability": "10",
			"yellow_drop_probability": "40",
			"red_drop_probability": "50"
        }
    },
    "QUEUE": {
        "Ethernet57,Ethernet58,Ethernet59|3-4": {
            "wred_profile": "[WRED_PROFILE|WRED]"
        }
    }
}
