defaultConfig={
    "FACTORY_NAME": "F39",
    "LINE_NUM": 1,
    "PLC_IP": "10.39.0.2",
    "CAM_SEQ_ALL": [
        [
            8,
            9,
            10,
            11,
            0,
            1,
            2,
            3,
            4,
            5,
            6,
            7
        ],
        [
            i for i in range(4)
        ],
        [
            i for i in range(24)
        ]
    ],
    "AIVC_MODE": 0,  #0:AIVC RASM&FKTH; 1:PVC AIVC; 2:ASM AIVC
    "PURGER_SETTING": [
        [
            6,
            0,
            0,
            2
        ],
        [
            6,
            0,
            0,
            2
        ],
        [
            11,
            0,
            0,
            2
        ],
        [
            11,
            0,
            0,
            2
        ]
    ],
    "FORMER_INTERVAL_ALL": [
        [
            10,
            11,
            10,
            11,
            10,
            11,
            10,
            11,
            0,
            0,
            0,
            0
        ],
        [0 for _ in range(4)],
        [0 for _ in range(24)]
    ],
    "CAM_DELAY_ALL": [
        [0 for _ in range(12)],
        [0 for _ in range(4)],
        [0 for _ in range(24)]
    ],
    "RASM_ANCHOR_OFFSET": [
        0,
        0,
        0,
        0
    ],
    "CLASS_TO_DISPOSE": 10,
    "CLASS_TO_REWORK": 20,
    "CONF_LEVEL_TO_PURGE": 0.8,
    "RASM_ARM_NUM": 36,
    "CHAIN_FORMER_NUM": 4000,
    "ENABLE_PURGE_RASM": [
        False,
        False,
        False,
        False
    ],
    "ENABLE_PURGE_FKTH": [
        False,
        False,
        False,
        False
    ],
    "ENABLE_PERIPHERAL": [
        False,
        False,
        False,
        False
    ],
    "AIVC_SERVER_IP" : "10.39.0.10",
    "AIVC_WEB_IP" : "10.39.0.11",
    "SENSOR_NUM": 1,
    "PERI_SENSOR_NUM": 16,
    "TEAMS_ADDR": "\nhttps://topglove.webhook.office.com/webhookb2/afc469eb-2b55-49d2-89e4-487c43b8bbdd@4375f5a7-4f5e-4526-92ef-6789f385f03d/IncomingWebhook/60677bee02be4eb98289b38a08c0cf5f/f8b00554-9519-4fb6-b9a2-d178db3228cf",
    "FLIP_DURATION": 10,
    "FLIP_DELAY": 2,
    "INPUT_SIZE": 512,
    "DOUBLE_FORMER": True,
    "BATCH_SIZE": 4,
    "IP_RANGE": [
        0,
        250
    ],
    "RASM_ANCHOR_INSTALLED": True,
    "CAM_SENSOR_ALL":[
        [0 for _ in range(12)],
        [0 for _ in range(4)],
        [0 for _ in range(24)],
    ],
    "PURGER_SENSOR":[
        0,
        0,
        0,
        0
    ],
    "PERI_SENSOR":[
        [0,1,2,3],
        [4,5,6,7],
        [8,9,10,11],
        [12,13,14,15]
    ],
    "ENABLE_AUTO_RESTART": True,
    "SENSOR_M":0,
    "ROTATE": False,
    "ENABLE_SHAREPOINT": False,
    "ENABLE_NAS_SHARE": False,
    "STREAM":0,
    "PLC_CONFIG":[],
    "ASM_LENGTH":5,
    "PURGER_PRESSURE_ALERT_THRESHOLD":0,
    "DUAL_BOOT":False,
    'LOW_CONF_THRESHOLD':0.75,
    'RASM_DEFECT_ALERT_THRESHOLD':0.05,
    "PERI_NAME":["FURS","SARS","Half-moon","ASM"],
    "PERI_CLASS":[0,0,0,0],
    "PERI_DISTANCE":[[10,10,10,10],[10,10,10,10],[10,10,10,10],[10,10,10,10]],
    "PERI_SIGNAL_ADDR":900,
    "PERI_SENSOR_ADDR":50,
    "ENABLE_HMPLC":False,
    "HM_PLC_IP":"10.39.0.39",
    "ENCODER_INSTALLED":False,
    "ENCODER_PULSE_PER_FORMER":170,
    "CHECK_REPETITION": False,
    "LOCK_SETTING":False,
    "FORMER_MARKING_DISTANCE":[10,10,10,10],
    "ENABLE_FORMER_MARKING":True,
    "CHAIN_ANCHOR_OFFSET":[0,0,0,0],
    "COUNTER_INSTALLED": True,
    "FORMER_COUNTER_OFFSET": [
        0,
        0,
        0,
        0
    ],
    "ENABLE_HTTP": False,
}