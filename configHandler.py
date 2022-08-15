from utils.defaultConfig import defaultConfig
import json
import os

import logging
configLogger=logging.getLogger("ConfigLogger")
logger=logging.getLogger("Logger")

class ConfigHandler():
    def __init__(self, eDict, cfgFile='config.json'):
        self.cfgFile=cfgFile
        self.config=eDict
        self.config.update(defaultConfig)
        self.loadConfig()

    def loadConfig(self):
        try:
            with open(self.cfgFile,'r') as f:
                userConfig=json.load(f)
        except json.decoder.JSONDecodeError as e:
            logger.error(str(e))
        except FileNotFoundError as e:
            print(e)
            userConfig={}
        for key in self.config:#To remove obsolete setting
            if key in userConfig:
                self.config.update({key:userConfig[key]})

        self.config.PURGER_SENSOR=[s if s<self.config.SENSOR_NUM else (self.config.SENSOR_NUM-1) for s in self.config.PURGER_SENSOR]#Limit maximum value of CAM_SENSOR
        self.config.VERSION="2.3.61.5" #Version set in coding, not load from config
        
    def saveBackup(self):
        if not os.path.exists('logs/'):
            os.mkdir('logs/')
        with open('logs/configBackup.json','w') as f:
            json.dump(self.config, f, indent=4)
        print("Back Up Configuration Saved")
    def saveConfig(self):
        with open(self.cfgFile,'w') as f:
            json.dump(self.config, f, indent=4)
        print("Configuration Saved")
    def set(self,key,val):
        self.config[key]=val
        configLogger.info(f'Config Changed | {key}: {val}')
        logger.info(f'Config Changed | {key}: {val}')
        self.saveConfig()
