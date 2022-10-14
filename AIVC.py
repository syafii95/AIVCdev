import cv2
import time
import datetime
import numpy as np
import tensorflow as tf
from tensorflow.keras.mixed_precision import experimental as mixed_precision
import subprocess
import csv
import pymsteams
import atexit
from multiprocessing import Process, Queue, Value, freeze_support
import queue as q
import ipaddress
import os
import sys
import time
import json
import random
import requests
from collections import deque
import smbclient
import psutil    
import weakref
import ctypes
import re
import ssl
import socket
from PIL import Image
from numpy import asarray
from cmath import inf
from tqdm import tqdm
from packaging import version
import hashlib
import zipfile
from pathlib import Path
from easydict import EasyDict
from traceback import format_exception, format_exc
from win32event import CreateMutex
from win32api import CloseHandle, GetLastError
from winerror import ERROR_ALREADY_EXISTS
from base64 import b64encode, b64decode
from urllib import parse
from hmac import HMAC

from utils.AIVCcomponents import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

import core.utils as utils
from core.yolov3 import YOLOv3, decode

from labelImg import MainWindow as LabelWindow
import plcLib
import sqlConnect
from indexer import FixLenIndexer
from utils.AIVCMainWindow import Ui_AIVCMainWindow
from utils.SettingDialog import Ui_SettingDialog
from utils.log import log
from concurrent_log_handler import ConcurrentRotatingFileHandler
import logging
from configHandler import ConfigHandler
from userDialog import UserDialog

from MvImport.CamControl import *
from color_detect_class import ColorDetect

requests.urllib3.disable_warnings(requests.urllib3.exceptions.SubjectAltNameWarning)

if not os.path.exists('data/'):
    os.mkdir('data/')
logging.basicConfig(format="%(asctime)s\t| %(message)s")
recorder = logging.getLogger("Record")
# Use an absolute path to prevent file rotation trouble.
# Rotate log after reaching 512K, keep 5 old copies.
recordHandler = ConcurrentRotatingFileHandler(os.path.abspath("data/record"), "a", 512*1024, 4)
recordHandler.setFormatter(logging.Formatter("%(asctime)s\t| %(message)s"))
recorder.addHandler(recordHandler)
recorder.setLevel(logging.DEBUG)

if not os.path.exists('logs/'):
    os.mkdir('logs/')
logging.basicConfig(format="%(asctime)s\t| %(message)s")
logger = logging.getLogger("Logger")
# Use an absolute path to prevent file rotation trouble.
# Rotate log after reaching 512K, keep 5 old copies.
logHandler = ConcurrentRotatingFileHandler(os.path.abspath("logs/log"), "a", 512*1024, 2)
logHandler.setFormatter(logging.Formatter("%(asctime)s\t| %(message)s"))
logger.addHandler(logHandler)
logger.setLevel(logging.DEBUG)

logging.basicConfig(format="%(asctime)s\t| %(message)s")
configLogger = logging.getLogger("ConfigLogger")
# Use an absolute path to prevent file rotation trouble.
# Rotate log after reaching 512K, keep 5 old copies.
configLogHandler = ConcurrentRotatingFileHandler(os.path.abspath("logs/configChanges"), "a", 512*1024, 2)
configLogHandler.setFormatter(logging.Formatter("%(asctime)s\t| %(message)s"))
configLogger.addHandler(configLogHandler)
configLogger.setLevel(logging.DEBUG)

CFG=EasyDict()
CFG_Handler=ConfigHandler(CFG,'config.json')#Load Config
Cam_Seq=CFG.CAM_SEQ_ALL[CFG.AIVC_MODE]
Former_Interval=CFG.FORMER_INTERVAL_ALL[CFG.AIVC_MODE]
Cam_Delay=CFG.CAM_DELAY_ALL[CFG.AIVC_MODE]
Cam_Sensor=CFG.CAM_SENSOR_ALL[CFG.AIVC_MODE]
Cam_Sensor=[s if s<CFG.SENSOR_NUM else (CFG.SENSOR_NUM-1) for s in Cam_Sensor]#Limit maximum value of Cam_Sensor
Side_Num= 4 if CFG.DOUBLE_FORMER else 2 #Get Side Num
Former_Plc_offset=CFG.FORMER_COUNTER_OFFSET

#AIVC_MODE  #0:AIVC RASM&FKTH; 1:TAC AIVC; 2:ASM AIVC
CAM_NAME=['FKTH_LIT','FKTH_LIB','FKTH_RIT','FKTH_RIB','FKTH_LOT','FKTH_LOB','FKTH_ROT','FKTH_ROB','RASM_LI','RASM_RI','RASM_LO','RASM_RO']
STATE=["Start","Running","Bypassing","Line Stopped", "No PLC Connection", "None Camera"]
STATE_COLOR=[Qt.green,Qt.green,QColor(117,217,139),Qt.darkGray,Qt.red,Qt.white]
SIDE_NAME=["Left In", "Right In", "Left Out", "Right Out", "Total"]
SIDE_SHORT=["LI", "RI", "LO", "RO", "Total"]
FKTH_CAM_SHORT=["LIT", "LIB", "RIT", "RIB", "LOT", "LOB", "ROT", "ROB"]
CAM_SIDE=[[0,0,1,1,2,2,3,3,0,1,2,3],[0,1,2,3],[0,0,0,0,0,0,1,1,1,1,1,1,2,2,2,2,2,2,3,3,3,3,3,3]]
FURS_ADDR=700
ASM_SHIFT_ADDR=650
SIDE_SEP=10000
TOTAL_FORMER=CFG.CHAIN_FORMER_NUM##replace
IMG_FORMAT='jpg'
BASE_DIR='D:/AIVCdata/'
RASM_NO_DETECT_DIR='tag_no_detection_RASM/'
FKTH_NO_DETECT_DIR='tag_no_detection_FKTH/'
SAMPLING_DIR='tag_sampling/'
FKTH_SAMPLING_DIR='tag_sampling_FKTH/'
RASM_SEQ=8
SAVING_PROCESS_NUM=2
PERIPHERAL_NAME=['FURS', 'SARS', 'Half-moon']
NAS_IP='10.39.8.230'
RASM_CLASS=[1,2,4]
CHAIN_CLASSES=[[1,2,3,4,10],[1,2,3,6,7],[1,2,3,4,5]]
CHAIN_CLASS=CHAIN_CLASSES[CFG.AIVC_MODE]
MAX_ASM_LENGTH=6
MAX_CAM_NUM=MAX_ASM_LENGTH*4
FIXED_INPUT_SIZE=512 #CFG.INPUT_SIZE
CLASSES=[]
SMALL_SCREEN=False
NARROW_SCREEN=False
BYPASS_CLASS=5 #5 No glove
PROBLEMATIC_FORMER_URL="https://prod-06.southeastasia.logic.azure.com:443/workflows/7ea0f5d40532405fbf45a2893bf4efa5/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=-emJj8JHuRN4QYeWEqrThpDMkID0Kpf0hzP7KTvqaGA"
IOTHUB_URI="tg-iot-aivc-r1.azure-devices.net/devices/AIVC-Master-01"
IOTHUB_REST_URI= "https://" + IOTHUB_URI + "/messages/events?api-version=2018-06-30"
IOTHUB_KEY= "mOMRhVDnXhk4f0c8zEPlpYDsHgXbjLRdLUXkJsVvlK8="
IOTHUB_URI_FORMER="tg-iot-aivc-r2.azure-devices.net/devices/AIVC-Former-01"
IOTHUB_REST_URI_FORMER = "https://" + IOTHUB_URI_FORMER + "/messages/events?api-version=2018-06-30"
IOTHUB_KEY_FORMER="lujyFDp4COxGQBw8oquyEo+q3M/FyTouw6y/4FMRdus="
try:
    with open('classes.names','r') as names:
        for name in names:
            CLASSES.append(name.strip('\n'))
except FileNotFoundError as e:
    logger.warning("classes.names Missing")
    #classes.names not found, use default name instead
    CLASSES=["Good Glove","Tearing","Single Arm","Double Dip", "Unstripped","No Glove","Stained", "Lump", "Broken Former", "Other"]
CLASS_NUM=len(CLASSES)
Data_Num=CLASS_NUM+2 #All class plus Empty Link and Produced Glove
DATA_NAMES=["Good Glove", "Produced Glove", "Empty Link"]+CLASSES[1:]
class singleinstance:
    def __init__(self):
        self.mutex = CreateMutex(None, False, "mutex_AIVC")
        self.lasterror = GetLastError()
    
    def alreadyrunning(self):
        return (self.lasterror == ERROR_ALREADY_EXISTS)
        
    def remove(self):
        if self.mutex:
            CloseHandle(self.mutex)
def saveStatus(val):
    with open('aivcMonitor/status','w') as f:
        f.write(str(val))
class maxInt():
    def __init__(self, value, max):
        self.value=value
        self.max=max
    def __iadd__(self,val):
        newValue=self.value + val
        if newValue > self.max or newValue<0:
            newValue= newValue % self.max
        self.value=newValue
        return self
    def __add__(self,val):
        newValue=self.value + val
        if newValue > self.max or newValue<0:
            newValue= newValue % self.max
        return newValue
    def __mod__(self,mod):
        return self.value%mod
    def __truediv__(self,den):
        return self.value/den
    def __repr__(self):
        return str(self.value)
    def __eq__(self,_val):
        return self.value==_val

def copyRecords(dst,src):
    for side in range(len(src)):
        for key, arr in src[side].items():
            np.copyto(dst[side][key], arr)

class ArmData():
    def __init__(self, cls=0):
        self.data=np.zeros(CLASS_NUM,dtype=int)
        self.data[cls]=1
    def __iadd__(self,_armData):
        self.data=np.add(self.data,_armData.data)
        return self

def emptyRecords():
    record=[]
    for i in range(4):
        side={}
        for j in range(CFG.RASM_ARM_NUM):
            side[j]=np.zeros(CLASS_NUM,dtype=int)
        record.append(side)
    return record

def makeDirs(dirs):
    for d in dirs:
        if not os.path.exists(d):
            os.makedirs(d)

def isRASM(camSeq):
    if CFG.AIVC_MODE==0 and camSeq>=RASM_SEQ:
        return True
    else:
        return False
def isFKTH(camSeq):
    if CFG.AIVC_MODE==0 and camSeq<RASM_SEQ:
        return True
    else:
        return False
def getSide(camSeq):
    try:
        return CAM_SIDE[CFG.AIVC_MODE][camSeq]
    except IndexError:
        print('Race condition on mode switch') #TODO: pass in side in the payload; mutex check
        return CAM_SIDE[2][camSeq]

def generateSasToken(uri, key, expiry=3600):
    ttl = time.time() + expiry
    sign_key = "%s\n%d" % ((parse.quote_plus(uri)), int(ttl))
    print(sign_key)
    signature = b64encode(HMAC(b64decode(key), sign_key.encode('utf-8'), hashlib.sha256).digest())
    rawtoken = {
        'sr' :  uri,
        'sig': signature,
        'se' : str(int(ttl))
    }
    return 'SharedAccessSignature ' + parse.urlencode(rawtoken)

def convertToAscii(strID):
    elementAppend=[]
    elementAppendFinish=[]
    numElement=48
    listDecimal=[12288,12544,12800,13056,13312,13568,13824,14080,14336,14592]
    for element in strID:
        if element == '0':
            numElement=48
        elif element == '1':
            numElement=49
        elif element == '2':
            numElement=50
        elif element == '3':
            numElement=51
        elif element == '4':
            numElement=52
        elif element == '5':
            numElement=53
        elif element == '6':
            numElement=54
        elif element == '7':
            numElement=55
        elif element == '8':
            numElement=56
        elif element == '9':
            numElement=57
        
        elementAppend.append(numElement)
        if len(elementAppend) == len(strID):
            if elementAppend[2] == 48:
                elementAppend[2] = listDecimal[0]
            elif elementAppend[2] == 49:
                elementAppend[2] = listDecimal[1]
            elif elementAppend[2] == 50:
                elementAppend[2] = listDecimal[2]
            elif elementAppend[2] == 51:
                elementAppend[2] = listDecimal[3]
            elif elementAppend[2] == 52:
                elementAppend[2] = listDecimal[4]
            elif elementAppend[2] == 53:
                elementAppend[2] = listDecimal[5]
            elif elementAppend[2] == 54:
                elementAppend[2] = listDecimal[6]
            elif elementAppend[2] == 55:
                elementAppend[2] = listDecimal[7]
            elif elementAppend[2] == 56:
                elementAppend[2] = listDecimal[8]
            elif elementAppend[2] == 57:
                elementAppend[2] = listDecimal[9]

            if elementAppend[0] == 48:
                elementAppend[0] = listDecimal[0]
            elif elementAppend[0] == 49:
                elementAppend[0] = listDecimal[1]
            elif elementAppend[0] == 50:
                elementAppend[0] = listDecimal[2]
            elif elementAppend[0] == 51:
                elementAppend[0] = listDecimal[3]
            elif elementAppend[0] == 52:
                elementAppend[0] = listDecimal[4]
            elif elementAppend[0] == 53:
                elementAppend[0] = listDecimal[5]
            elif elementAppend[0] == 54:
                elementAppend[0] = listDecimal[6]
            elif elementAppend[0] == 55:
                elementAppend[0] = listDecimal[7]
            elif elementAppend[0] == 56:
                elementAppend[0] = listDecimal[8]
            elif elementAppend[0] == 57:
                elementAppend[0] = listDecimal[9]
            
            elementAppendFinish = np.copy(elementAppend)
            elementAppend.clear()
    return elementAppendFinish

class ShiftCounter():
    def __init__(self,addr, plc, idx, maxlen=300):
        self.addr=addr
        self.plc=plc
        self.idx=idx
        self.maxlen=maxlen
        self.stacks=[deque(maxlen=maxlen) for _ in range(4)]
        self.pointers=[0]*4
        # for i in range(4):
        #     d=deque(maxlen=self.maxlen)
        #     for i in range(maxlen):
        #         d.append(False)
        #     self.stacks.append(d)
        
    def feed(self,val, side):
        self.stacks[side].appendleft(val)
    def checkSide(self,side):
        if self.pointers[side] < CFG.PERI_DISTANCE[self.idx]:
            self.pointers[side]+=1
        elif self.pointers[side] > CFG.PERI_DISTANCE[self.idx]:
            print(self.stacks[side])
            diff=self.pointers[side]-CFG.PERI_DISTANCE[self.idx]
            for _ in range(diff):
                self.stacks[side].pop()
            self.pointers[side]-=diff
            print(self.stacks[side])
            if self.stacks[side].pop():
                self.plc.activateCoilBySide(self.addr,side)
        else:
            if self.stacks[side].pop():
                self.plc.activateCoilBySide(self.addr,side)
            
    def emit(self, spinList):
        for i in range(4):
            if spinList[i]:
                self.stacks[i].appendleft(True)
            else:
                self.stacks[i].appendleft(False)

            if self.stacks[i][CFG.FURS_DISTANCE[i]]:
                self.plc.activateCoilBySide(self.addr,i)

class RepetitionChecker():
    def __init__(self,side):
        self.centerList=deque(maxlen=20)
        self.listsToAlign=[deque(maxlen=20) for _ in range(2)]
        self.count=0
        self.side=side

    def feedCenterList(self, ID):
        self.centerList.append(ID)
        self.count+=1
        if (len(self.centerList)) == 20 and (len(self.listsToAlign[0]) == 20 and self.count>1):
            self.check()
            self.count=0
    def feedListToAlign(self, l, ID):
        self.listsToAlign[l].append(ID)
    def clear(self):
        self.centerList.clear()
        self.listsToAlign[0].clear()
        self.listsToAlign[1].clear()
    def check(self):
        print(f'{SIDE_NAME[self.side]} checking former interval:')
        highestSimilarity=0
        shift=0
        for k in range(2):
            for i in range(-5,5):
                shiftedList=[a+i for a in self.listsToAlign[k]]
                similarity = len(set(self.centerList) & set(shiftedList)) /20 * 100
                print(f'Shifted {i}, Similarity: {similarity}')
                if similarity>highestSimilarity:
                    highestSimilarity=similarity
                    shift=i
            print(f'{k} Highest Similarity {shift}: {highestSimilarity}')
class TimingChecker():
    def __init__(self,name,length=20,tolerance=2):
        self.name=name
        self.length=length
        self.tolerance=tolerance
        self.durations=deque(maxlen=length)
        self.prevTime=None

    def check(self):
        if self.prevTime:
            duration=time.time()-self.prevTime
            if len(self.durations)>0:
                durationAvg=sum(self.durations)/len(self.durations) #Compare before appending
                if duration>(self.tolerance*durationAvg) or duration<(durationAvg/self.tolerance):
                    recorder.debug(f'{self.name} Abnormal Process Timing: {duration:.2f}s. Last {len(self.durations)} Average Timing: {durationAvg:.2f}s')
            self.durations.append(duration)
        self.prevTime=time.time()

class OccuAnalyzer():
    def __init__(self,name,l):
        self.name=name
        self.totalTimes=deque(maxlen=l)
        self.durations=deque(maxlen=l)
        self.startTime=0
        self.endTime=0
    def start(self):
        t=time.time()
        if(self.endTime-self.startTime)<0: # occu.end not called
            print(f"{self.name} OCCU end() not called before the second start()")
            return
        if self.endTime:
            self.durations.append(self.endTime-self.startTime)
            self.totalTimes.append(t-self.startTime)
        self.startTime=t
    def end(self):
        self.endTime=time.time()
    def __str__(self):
        try:
            totalTimeAvg=sum(self.totalTimes)/len(self.totalTimes)
            durationAvg=sum(self.durations)/len(self.durations)
            occuRate=durationAvg/totalTimeAvg
        except ZeroDivisionError: 
            totalTimeAvg=0
            durationAvg=0
            occuRate=0
        return f"{self.name}\tTotal Time: {totalTimeAvg*1000:.2f}ms\tDuration: {durationAvg*1000:.2f}ms\tOccupation Rate: {occuRate*100:.2f}%"

JSON_RPC_PORT=1444
JSON_RPC_IP=CFG.AIVC_SERVER_IP

OTA_HOST=CFG.AIVC_WEB_IP
OTA_PORT=1445
OTA_TCP_BUFFER_SIZE=4096
DOWNLOAD_FILE_NAME='updatePatch.zip'

class OTAClient(Process):
    def __init__(self, host, port):
        super(OTAClient, self).__init__()
        self.host = host
        self.port = port
        self.updated=Value('i',0)
        self.daemon=True
    def run(self):
        try:
            print('OTA Client Started')
            self.directory=Path(__file__).parent.absolute()
            self.context=ssl.create_default_context()
            self.context.load_verify_locations(f'{self.directory}/lib/AIVC.pem')
            self.context.check_hostname=False
            print('OTA Client Creating Connection')
            sock = socket.create_connection((self.host, self.port))
            self.toSSock= self.context.wrap_socket(sock, server_hostname=OTA_HOST)
            self.toSSock.send(CFG.VERSION.encode())
            received=self.toSSock.recv().decode().split(',')
            if received[0]=='0':
                print(f'{CFG.VERSION} already up to date')
                self.toSSock.close()
                return
            newVersion,fileSize,fileDigest=received
            fileSize=int(fileSize)
            progress = tqdm(range(fileSize), f"Downloading {newVersion}", unit="B", unit_scale=True, unit_divisor=1024)
            with open(f'{self.directory}/{DOWNLOAD_FILE_NAME}', 'wb') as f:
                checkSum=hashlib.md5()
                while True:
                    # read 1024 bytes from the socket (receive)
                    try:
                        bytes_read = self.toSSock.recv(OTA_TCP_BUFFER_SIZE)
                    except ConnectionResetError as e:
                        print(f'Connection Closed By Server :{e}')
                        break
                    if not bytes_read:    
                        # nothing is received, file transmitting is done
                        progress.close()
                        break
                    # write to the file the bytes we just received
                    f.write(bytes_read)
                    checkSum.update(bytes_read)
                    # update the progress bar
                    progress.update(len(bytes_read))
            self.toSSock.shutdown(2)
            self.toSSock.close()
            print('Connection Closed')
            checkSum=checkSum.hexdigest()
            if checkSum==fileDigest:
                print(f'Check Sum completed, file is intact. MD5 Digest:{checkSum}')
            else:
                print(f'Check Sum Failed. File Corrupted During Transmission. MD5 Digest:{checkSum}; Server MD5 Digest:{fileDigest}')
                return -1
            #Decompress the file
            with zipfile.ZipFile(f'{self.directory}/{DOWNLOAD_FILE_NAME}') as zf:
                for member in tqdm(iterable=zf.namelist(),total=len(zf.namelist()), desc='Extracting ',position=0, leave=True):
                    try:
                        zf.extract(member, self.directory)
                    except zipfile.error as e:
                        print(f'Decompression Error: {e}')
                        return -1
            self.updated.value=1
            saveStatus(2)#Indicate pending restart update
            logger.info('Update Package Extraction Successfully. Pending AIVC Restart To Complete Update')
        except Exception as e:
            logger.warning(f"OTAClient Exception: {e}")
def get_gpu_memory():
    try:
        _output_to_list = lambda x: x.decode('ascii').split('\r\n')[1]
        COMMAND = "nvidia-smi --query-gpu=memory.free,memory.used,gpu_name --format=csv"
        memory_info = _output_to_list(subprocess.check_output(COMMAND.split())).split()
        free=int(memory_info[0])
        used=int(memory_info[2])
        name=" ".join(memory_info[5:])
        return free,used,name
    except Exception:
        return 505, 505, "Unknown"

class JsonRPCClient(QThread):
    def __init__(self,parent=None):
        super().__init__(parent=parent)
        self.name=f'{CFG.FACTORY_NAME}L{CFG.LINE_NUM}_{CFG.AIVC_MODE}'
        self.reportQue=q.Queue()
        self.producedGlove=-1
        self.response=''
        self.url=f"https://{JSON_RPC_IP}:{JSON_RPC_PORT}/jsonrpc"
        payload = {
            "method": "get",
            "params": [ self.name ],
            "jsonrpc": "2.0",
            "id": 0,
        }
        try: #Fire 1st dummy request because 1st request is slow (around 2 second)
            ret = requests.post(self.url, json=payload, verify='lib/AIVC.pem', timeout=15).json()
        except Exception as e:
            print(e)
        self.start(3)
        self.updated=Value('i',0)
        self.otaClientProcess=OTAClient(OTA_HOST,OTA_PORT)
        self.myProcess=None
            
    def report(self):
        self.reportQue.put(True)
            
    def run(self):
        while True:
            report=self.reportQue.get()
            if report is None:
                break
            # if self.producedGlove==-1:
            #     continue
            
            keysDict={
                'config':json.dumps(CFG),
                'producedGlove':int(self.producedGlove),
                'camNum':Cams_Num,
                'gMem':get_gpu_memory(),
                'lastUpdate':time.strftime("%Y%m%d-%H:%M:%S"),
                'response':self.response,
                'set':'',
                'updateAIVC':False
            }
            payload = {
                "method": "report",
                "params": [ self.name, keysDict],
                "jsonrpc": "2.0",
                "id": 0,
            }
            print("Reporting")
            try:
                ret = requests.post(self.url, json=payload, verify='lib/AIVC.pem', timeout=15).json()
            except requests.exceptions.Timeout:
                print('JsonRPC status get request timeout. Abort status update')
                continue
            except requests.exceptions.SSLError as e:
                print(f'JsonRpcClient SSL Error: {e}')
                continue
            except ConnectionResetError as e:
                print(f'JsonRpcClient Server Connection Closed: {e}')
                continue
            except Exception as e:
                print(e)
                continue
            if not 'result' in ret:
                logger.warning(f'No "result" in from JsonRpcReply: {ret}')
                continue
            result = ret['result']
            t=time.strftime("%Y%m%d-%H:%M:%S")
            prevGloveNum=0
            self.response=""
            if 'set' in result:
                if result['set']:
                    try:
                        key,val=result['set'].split(':',1)
                        key=key.strip()
                        val=val.strip()
                        if key in CFG_Handler.config:
                            val=eval(val)
                            if type(val)==type(CFG[key]):
                                CFG_Handler.set(key,val)
                                self.response=f'Successfully set {key} to {val} | {t}'
                            else:
                                self.response=f"Set Configuration Failed. Type received {type(val)} doesn't match with {key} type {type(CFG[key])} | {t}"
                        else:
                            self.response=f'Set Configuration Failed. {key} is not a configuration | {t}'
                    except (ValueError, NameError) as e:
                        self.response=f'Wrong Format To Set Config. Suppose to be KEY:value. {e} | {t}'
                    except Exception as e:
                        print("Exception")
                        self.response=f'Uncaught Exception: {e} | {t}'
            if 'updateAIVC' in result:
                if result['updateAIVC']==True:
                    try:
                        if not self.otaClientProcess.is_alive() and self.otaClientProcess.updated.value==0:
                            self.otaClientProcess=OTAClient(OTA_HOST,OTA_PORT)
                            self.otaClientProcess.start()
                            self.response+=" Received Update Command."
                        else:
                            self.response+=" On-going OTA Update."
                    except Exception as e:
                        logger.warning(f"OTA Client Process Exception. {e}")

        print("JsonRPC Client Thread Closed")


class SQLHandler(QThread):
    def __init__(self,parent=None):
        super().__init__(parent=parent)
        self.queue = q.Queue()
        self.cache=[]
        self.SQLDisableRetry=False
        self.prevDate=time.strftime("%Y-%m-%d")
        self.prevTime=time.strftime("%H:%M:%S")
        self.prevData=np.zeros((5,Data_Num), dtype = int)
        self.start(3)

    def run(self):
        self.sqlConnector=sqlConnect.SQLConnect(DATA_NAMES)
        while True:
            payload = self.queue.get()
            if payload is None:
                break
            if self.SQLDisableRetry:
                self.cache.append(payload)
                continue
            res=self.sqlConnector.push(*payload)#push current data
            if res == -1:
                logger.warning("Failed To Upload Data To SQL Server")
                self.cache.append(payload)
                print(f'Cached data to upload after network connection resume: {self.cache}')
                self.SQLDisableRetry=True
                continue
            
            while self.cache:#push cached data
                res=self.sqlConnector.push(*(self.cache[0]))
                if res == -1:
                    logger.warning("Failed To Upload Data To SQL Server")
                    self.SQLDisableRetry=True
                    continue
                self.cache.pop(0)
        print('SQLHandler Closed')
    def upload(self, data, databasePrevState):
        self.SQLDisableRetry=False#Re-enable SQL Upload
        dataToUpload=data-self.prevData#prevdata
        _time=time.strftime("%H:%M:%S")
        date=time.strftime("%Y-%m-%d")
        DorS='D' if CFG.DOUBLE_FORMER else 'S'
        for side in range(Side_Num):
            self.queue.put([CFG.FACTORY_NAME,f'L{CFG.LINE_NUM}{DorS}',side,self.prevDate,self.prevTime,date,_time,databasePrevState,dataToUpload[side]])
        np.copyto(self.prevData,data)
        self.prevDate=date
        self.prevTime=_time

class AlertHandler(QThread):
    def __init__(self,parent, iotHubRestURI,teamsMessenger):
        super().__init__(parent=parent)
        self.alertQueue = q.Queue()
        self.iotHubRestURI=iotHubRestURI
        self.teamsMessenger=teamsMessenger
        self.startDateTime=datetime.datetime.now().isoformat()
        self.start(3)

    def run(self):
        while True:
            payload, state, alertEachArm = self.alertQueue.get()
            if payload is None:
                break
            else:
                endDateTime=datetime.datetime.now().isoformat()
                utcDateTime=datetime.datetime.utcnow().isoformat()
                AllIotHubData=[]
                iotHubData = {
                    "StartDateTime": self.startDateTime,
                    "EndDateTime": endDateTime,
                    "UTCDateTime": utcDateTime,
                    "Mode": CFG.AIVC_MODE,
                    "Plant": CFG.FACTORY_NAME,
                    "ProductionLine": f'L{CFG.LINE_NUM}',
                    "ProductionLineStatus": state
                    }
                self.startDateTime=endDateTime
                warningTxt='<div style="color:black;background-color: #ffe4c4; padding:10px"><h2>Warning:</h2><p>'
                send=False
                if alertEachArm:#Sending each arm data
                    currentRecords,lastRecords,eachSideData=payload

                    rasmID=0
                    for side,rasmRecord in enumerate(currentRecords):
                        record=rasmRecord.getAllData()
                        for idx,data in record.items():
                            if rasmRecord.state==0:
                                rasmID=idx
                            else:
                                rasmID=(idx+rasmRecord.offset)%rasmRecord.totalLen
                            iotHubData['ProductionLineRow']=SIDE_NAME[side]
                            iotHubData['CarrierSet']=rasmID
                            armRecord=data-lastRecords[side][idx]
                            gg=armRecord[0]
                            rdg=0
                            odg=0
                            total=0
                            msg=''
                            classData={}
                            for i, record in enumerate(armRecord):
                                classData[CLASSES[i]]=int(record)
                                total+=record
                                if i>0:
                                    if i in RASM_CLASS:
                                        rdg+=record
                                        msg+=f'{CLASSES[i]}:{record} '
                                    else:
                                        odg+=record
                            tdg=rdg+odg
                            msg+=f'Non-RASM-Related:{odg} '
                            rdr=float(rdg)/total if total!=0 else 0
                            tdr=float(tdg)/total if total!=0 else 0
                            msg+=f'Good Glove:{gg} RASM Defective Rate:{rdr*100:.2f}%'

                            if rdr>CFG.RASM_DEFECT_ALERT_THRESHOLD: #Send alert for defective rate > 5 %
                                send=True
                                warningTxt+=f"{CFG.FACTORY_NAME} L{CFG.LINE_NUM} {SIDE_NAME[side]} RASM ARM:{rasmID+1} {msg}<br>"
                            
                            classData['Produced Glove']=int(total)
                            classData['Empty Link']=0
                            iotHubData['Class_Value_JSON']=classData.copy()
                            # iotHubData['rasm_defect_count']=int(rdg)
                            # iotHubData['total_defect_count']=int(tdg)
                            # iotHubData['rasm-defective_rate']=round(rdr*100,2)
                            # iotHubData['total_defective_rate']=round(tdr*100,2)
                            AllIotHubData.append(iotHubData.copy())
                    #Side Data on carrirt_set 999
                    for side, data in enumerate(eachSideData[:4]):##Included col 5 total?
                        iotHubData['CarrierSet']=999
                        iotHubData['ProductionLineRow']=SIDE_NAME[side]

                        gg=data[0]
                        pg=data[1]
                        dr=(pg-gg)/pg if pg != 0 else 0

                        classData={}
                        for i, className in enumerate(DATA_NAMES):
                            classData[className]=int(data[i])

                        iotHubData['Class_Value_JSON']=classData.copy()
                        # iotHubData['total_defect_count']=int(pg-gg)
                        # iotHubData['total_defective_rate']=round(dr*100,2)
                        # iotHubData['rasm_defect_count']=0
                        # iotHubData['rasm-defective_rate']=0
                        recorder.info(str(iotHubData))
                        AllIotHubData.append(iotHubData.copy())

                else:#Sending each side data instead of arm
                    eachSideData=payload
                    for side, data in enumerate(eachSideData[:4]):
                        msg=''
                        gg=data[0]
                        pg=data[1]
                        dr=(pg-gg)/pg if pg != 0 else 0


                        if dr>0.03:
                            send=True
                            msg+=f'Good Glove:{gg} '
                            for i in range(1,len(data)-2):
                                msg+=f'{CLASSES[i]}:{data[i+2]} '
                            msg+=f'Defective Rate:{dr*100:.2f}%'
                            warningTxt+=f"{CFG.FACTORY_NAME} L{CFG.LINE_NUM} {SIDE_NAME[side]} {msg}<br>"
                        #IOThub
                        iotHubData['CarrierSet']=999
                        classData={}
                        for i, className in enumerate(DATA_NAMES):
                            classData[className]=int(data[i])
                        iotHubData['ProductionLineRow']=SIDE_NAME[side]
                        iotHubData['Class_Value_JSON']=classData.copy()
                        # iotHubData['total_defect_count']=int(pg-gg)
                        # iotHubData['total_defective_rate']=round(dr*100,2)
                        AllIotHubData.append(iotHubData.copy())

                if CFG.ENABLE_SHAREPOINT:
                    try:
                        headers={
                            'Authorization' : generateSasToken(IOTHUB_URI,IOTHUB_KEY, expiry=60),
                            'Content-Type' : "application/json"
                        }
                        recorder.info(f"{self.iotHubRestURI} | IotHubData[-12:]=>{AllIotHubData[-12:]}")
                        resp=requests.post(self.iotHubRestURI, json=AllIotHubData, headers=headers)
                        recorder.info(resp)
                    except Exception as e:
                        logger.warning(f'Failed To Upload Data To IotHub {self.iotHubRestURI}: {e}')
                if send:
                    warningTxt+='</p></div>'
                    recorder.info(warningTxt)
                    self.teamsMessenger.emit(warningTxt)
                    print("Sending Teams Alert!")
        print("AlertHandler Closed")


class TeamsHandler(QThread):
    resumePreviousTeamsAddr=pyqtSignal()
    def __init__(self, parent, channel_url):
        super().__init__(parent=parent)
        self.client = pymsteams.connectorcard(channel_url)
        self.queue = q.Queue()
        # # shutdown the worker at process exit
        # atexit.register(self.queue.put, None)
        self.start(3)

    def run(self):
        while True:
            record = self.queue.get()
            if record is None:
                break
            elif record[:15] == 'ChangeTeamsAddr': #change teams address
                addr=record[15:]
                self.client=pymsteams.connectorcard(addr)
                msg=f'<div style="color:black;background-color: #b8d6fd; padding:10px"><h2>New Channel Activated:</h2><p>{CFG.FACTORY_NAME} L{CFG.LINE_NUM} Integrated AIVC System will be sending alert to this channel</p></div>'
                self.client.text(msg)
                try:
                    self.client.send()
                    CFG_Handler.set('TEAMS_ADDR',addr)
                except Exception as e:
                    statusCode=getattr(self.client,'last_http_status','')
                    print(f"Failed to change Teams ADDR. {statusCode.status_code if statusCode else ' '}")
                    print(e)
                    self.resumePreviousTeamsAddr.emit()
                    self.client=pymsteams.connectorcard(CFG.TEAMS_ADDR)
            else: #send alert
                self.client.text(record)
                try:
                    self.client.send()
                except Exception as e:
                    statusCode=getattr(self.client,'last_http_status','')
                    warning=f"Failed to send Teams Alert. {statusCode.status_code if statusCode else ' '} {e}"
                    logger.warning(warning)
        print('TeamsHandler Closed')

    def emit(self, record):
        self.queue.put(record)

class PLCAddrInput(QLineEdit):
    def __init__(self, parent=None, maxD=9999, maxM=4096, hint=None):
        super().__init__(parent=parent)
        self.maxD=maxD
        self.maxM=maxM
        if hint is not None:
            self.setPlaceholderText(str(hint))
        self.textChanged.connect(self.validate)
        self.d=False #Register/Coil
    def validate(self):
        text=self.text()
        if not self.text():
            return 
        if text[0]=='D':
            self.d=True
        elif text[0]=='M':
            self.d=False
        else:
            self.setText('')
            return
        if not text[1:].isnumeric():
            self.setText(text[0])
            return
        else:
            addr=int(text[1:])
        if self.d:
            if addr> self.maxD:
                self.setText(f'D{self.maxD}')
        else:
            if addr> self.maxM:
                self.setText(f'M{self.maxM}')
        self.periThreadRunning=False

class Purging_Thread(QThread):
    updatePurgingDisplay=pyqtSignal(int,str)#side,content
    updateListToPurge=pyqtSignal(int,int,str)
    markDetected=pyqtSignal(int,int,int)
    markPurged=pyqtSignal(int,int)
    markTestMark=pyqtSignal(int,int)
    markMarkFormer=pyqtSignal(int,int)
    markPeriRejected=pyqtSignal(int,int,int)
    markPeri=pyqtSignal(int,int,int)

    def __init__(self, parent, plc, chainIndexers):
        super().__init__(parent=parent)
        self.plc=plc
        self.chainIndexers=chainIndexers
        self.purgingStacks=[{} for _ in range(4)]
        self.periSets=[[set() for _ in range(4)] for _ in CFG.PERI_NAME]
        self.testMarkSets=[set() for _ in range(4)]
        self.markIdSignal=[set() for _ in range(4)]
        self.purgerDistance=[p[0] for p in CFG.PURGER_SETTING]
        self.firstAnchorIDs=[0]*4
        self.verifyMarking=[0]*4
        self.purgerFormerIDs=[-1]*4
        self.purgeThreadRunning=True
        self.purgeQue=q.Queue()
        self.timingChecker=TimingChecker(self.__class__.__name__,tolerance=1.5)
        self.testBin=False
        if CFG.ENABLE_HMPLC:
            self.hmPlc=plcLib.HalfmoonPLC(CFG.HM_PLC_IP)

    def sendFormerLamps(self,IDs,side,rdr):
        if CFG.AIVC_MODE==0:
            markFormerIDs = IDs+CFG.FORMER_MARKING_DISTANCE[side]
            if markFormerIDs >= CFG.CHAIN_FORMER_NUM:
                bal = markFormerIDs - CFG.CHAIN_FORMER_NUM
            else:
                bal = markFormerIDs
            self.markIdSignal[side].add(bal)
            #print(f'=== FormerID: {bal} | Side: {side} | Defective Rate: {rdr*100:.2f} ===')

    def testPurge(self):
        #self.plc.purgeGlove(self.sender().seq)##Purge directly
        self.testBin= not self.testBin
        side=self.sender().seq
        print(f"Test {'Dispose' if self.testBin else 'Rework'}")
        if CFG.AIVC_MODE==0:
            if CFG.ENABLE_PURGE_RASM[side]:
                self.feedPurgingStack(self.purgerFormerIDs[side]+side*SIDE_SEP, self.testBin, Cam_Seq[side])
            else:
                print(f'{SIDE_NAME[side]}RASM Purging Disabled')
        if CFG.ENABLE_PERIPHERAL[side]:
            periRecord=0
            for periIdx,periClass in enumerate(CFG.PERI_CLASS):
                if periClass:
                    periRecord|=(1<<periIdx)
            self.feedPeripheralStack(self.purgerFormerIDs[side]+side*SIDE_SEP, periRecord, Cam_Seq[side])#Sending 1st peripheral signal
        else:
            print(f'{SIDE_NAME[side]}Peripheral Signal Disabled')

    def testMark(self):
        side=self.sender().seq
        formerID=self.purgerFormerIDs[side]+CFG.FORMER_MARKING_DISTANCE[side]
        if formerID >= CFG.CHAIN_FORMER_NUM:
            bal = formerID - CFG.CHAIN_FORMER_NUM
        else:
            bal = formerID
        print(f"Test Mark {SIDE_SHORT[side]} {bal}")
        self.feedTestMarkStack(bal+side*SIDE_SEP)
        self.markTestMark.emit(side,bal)
        
    def closeThread(self):
        self.purgeThreadRunning=False

    def clearStack(self):
        for purgingStack in self.purgingStacks:
            purgingStack.clear()
        for periSet in self.periSets:
            for periSide in periSet:
                periSide.clear()
    def setAnchorID(self,anchorsIDs):
        self.firstAnchorIDs=anchorsIDs
        print(self.purgingStacks)
        for side in range(4):
            newPurgingStack={}
            for formerToPurge,dispose in self.purgingStacks[side].items():
                newPurgingStack[formerToPurge-anchorsIDs[side]]=dispose
            self.purgingStacks[side]=newPurgingStack
        print(self.purgingStacks)

        print(self.periSets)
        for periIdx in range(len(CFG.PERI_NAME)):
            for side in range(4):
                newPeriSet=set()
                for formerToPurge in self.periSets[periIdx][side]:
                    newPeriSet.add(formerToPurge-anchorsIDs[side])
                self.periSets[periIdx][side]=newPeriSet
        print(self.periSets)

    def feedPurgerQue(self,side,formerID):
        self.purgeQue.put([side,formerID])

    @pyqtSlot(int)
    def rejectAsm(self,camSeq):
        print(f"ASM {getSide(camSeq)} {camSeq % MAX_ASM_LENGTH}")
        self.plc.rejectAsm(getSide(camSeq),camSeq % MAX_ASM_LENGTH)

    def feedPurgingStack(self,formerID, dispose, camSeq):
        #convert to formerID on Purger
        side=int(formerID/SIDE_SEP)
        sideID=formerID%SIDE_SEP
        if sideID>self.purgerFormerIDs[side]+Former_Interval[camSeq]:#1st anchor reached thus nid to reassign id 
            sideID-=self.firstAnchorIDs[side]
            recorder.debug(f"feedPurgingStack {sideID+self.firstAnchorIDs[side]} -> {sideID} purgerFormerIDs{self.purgerFormerIDs}")
        formerToPurge=(sideID+self.purgerDistance[side])%TOTAL_FORMER
        self.markDetected.emit(side,sideID, formerToPurge)
        if dispose:#Dispose will replace rework
            self.purgingStacks[side][formerToPurge]=True
        else:#Rework
            if formerToPurge not in self.purgingStacks[side]:#Rework ignored if formerID already in purgingStack
                self.purgingStacks[side][formerToPurge]=False
        self.updateListToPurge.emit(side,formerToPurge,"Dispose" if dispose else "Rework")

    def feedMarkingStack(self,formerID,):
        side=int(formerID/SIDE_SEP)
        sideID=formerID%SIDE_SEP

    def feedPeripheralStack(self,formerID, periRecord, camSeq):
        side=int(formerID/SIDE_SEP)
        sideID=formerID%SIDE_SEP
        if sideID>self.purgerFormerIDs[side]+Former_Interval[camSeq]:#1st anchor reached thus nid to reassign id 
            sideID-=self.firstAnchorIDs[side]
            recorder.debug(f"feedPeripheralStack {sideID+self.firstAnchorIDs[side]} -> {sideID} purgerFormerIDs{self.purgerFormerIDs}")
        for periIdx, periDistance in enumerate(CFG.PERI_DISTANCE):
            if periRecord & (1<<periIdx):
                formerIdOnPeri=(sideID+periDistance[side])%TOTAL_FORMER
                self.periSets[periIdx][side].add(formerIdOnPeri)
                self.markPeri.emit(side,formerIdOnPeri,periIdx)
    def feedTestMarkStack(self,formerID):
        side=int(formerID/SIDE_SEP)
        sideID=formerID%SIDE_SEP
        self.testMarkSets[side].add(sideID)
        print(self.testMarkSets)
    def run(self):
        prevBins=['','','','']
        for i in range(4):
            self.plc.setDualBinFlap(i,False)#Reset All Dual Bin Flap
        while(self.purgeThreadRunning):
            try:
                side,purgerFormerID = self.purgeQue.get(timeout=0.5)
            except q.Empty:
                continue
            self.updatePurgingDisplay.emit(side,f'{purgerFormerID:03d}')
            self.purgerFormerIDs[side]=purgerFormerID
            if purgerFormerID in self.purgingStacks[side]:
                dispose=self.purgingStacks[side].pop(purgerFormerID)
                #Purger
                self.plc.purgeGlove(side) #Delay counting in PLC
                self.markPurged.emit(side, purgerFormerID)
                print(f"Purging {SIDE_NAME[side]}")
                #Dual Bin
            if (purgerFormerID+1) in self.purgingStacks[side]:  #Early Counting Because flip slow
                dispose=self.purgingStacks[side][purgerFormerID+1]  #Early Counting Because flip slow
                if dispose:
                    if prevBins[side]!='R': #DX/DD-> open; DR-> do nothing
                        self.plc.setDualBinFlap(side,True) #Turn the flap
                        print(f"Open Dispose Bin {SIDE_NAME[side]}")
                    prevBins[side]='D'
                else:#Rework
                    if prevBins[side]=='D': #RD-> close; RX/RR -> do nothing
                        self.plc.setDualBinFlap(side,False) #Close the flap
                        print(f"Close Dispose Bin {SIDE_NAME[side]}")
                    prevBins[side]='R'
            else:#No Purge
                prevBins[side]=''
                
            #Check Peripheral Rejection
            for periIdx, periName in enumerate(CFG.PERI_NAME):
                if purgerFormerID in self.periSets[periIdx][side]:
                    self.periSets[periIdx][side].remove(purgerFormerID)
                    self.plc.activatePeri(side,periIdx,CFG.PERI_SIGNAL_ADDR)

                    self.markPeriRejected.emit(side, purgerFormerID,periIdx)
                    print(f'{SIDE_NAME[side]} {periName} Reject')
                    if CFG.ENABLE_HMPLC and periIdx==2:
                        self.hmPlc.activateHM(side)

            #Mark High Defective Rate Former
            """if CFG.ENABLE_FORMER_MARKING: #send here
                targetFormerID=purgerFormerID+CFG.FORMER_MARKING_DISTANCE[side]
                targetFormerRecord=self.chainIndexers[side].get(targetFormerID)
                if targetFormerRecord is not False:
                    pg=np.sum(targetFormerRecord)
                    dg=np.sum(targetFormerRecord[1:])
                    dr=dg/(pg)
                    if dr>0.2 and pg>10:
                        self.plc.sendFormerMarkingSignal(side)
                        print(f"Mark Former {side} {targetFormerID} {dr}%")"""
            #Test mark
            if purgerFormerID  in self.testMarkSets[side]:
                self.testMarkSets[side].remove(purgerFormerID)
                self.markMarkFormer.emit(side,purgerFormerID)
                self.plc.sendFormerMarkingSignal(side)

            #Mark High Defective Rate Former
            if purgerFormerID  in self.markIdSignal[side]:
                self.verifyMarking[side]+=1
                #print(f'******* {purgerFormerID} ********') #print this to see former marking signal to addon lamp
                self.markIdSignal[side].remove(purgerFormerID)
                targetFormerID=purgerFormerID-CFG.FORMER_MARKING_DISTANCE[side] # 20 = 10 - 10
                if targetFormerID < 0:
                    bal = CFG.CHAIN_FORMER_NUM + targetFormerID
                else:
                    bal = targetFormerID
                targetFormerRecord=self.chainIndexers[side].get(bal)
                #print(f'++++++++++++ {targetFormerRecord} | Bal: {bal} +++++++++++++')
                if targetFormerRecord is not False:
                    pg=np.sum(targetFormerRecord)
                    dg=np.sum(targetFormerRecord[1:])
                    dr=dg/(pg)
                    print(f"Mark Former {SIDE_SHORT[side]} {purgerFormerID} {dr*100:.2f}%")
                    #print(f'========== Result: {self.verifyMarking} =============')
                if CFG.ENABLE_FORMER_MARKING:
                    self.plc.sendFormerMarkingSignal(side)
                    
            if side==0:
                self.timingChecker.check()

        self.purgeQue.queue.clear()
        print("Purging Thread Closed")

class OperationInspector(QObject):
    setPlcBypass=pyqtSignal(int,bool)
    def __init__(self, threshould=5,side=0,parent=None):
        super().__init__(parent=parent)
        self.threshould=threshould
        self.side=side
        self.lineBypassing=False
        self.counter=0
    def isRunning(self,hasGlove):
        if not self.lineBypassing:
            if not hasGlove:
                self.counter-=1
            else:
                if self.counter<0:
                    self.counter+=1
            if self.counter<self.threshould*(-1):
                self.setPlcBypass.emit(self.side,True)
                self.lineBypassing=True
                self.counter=0
        else:#Line bypassing state
            if hasGlove:
                self.counter+=1
            else:
                if self.counter>0:
                    self.counter-=1
            if self.counter>self.threshould/3:# 3 times easier to exit bypassing state
                self.setPlcBypass.emit(self.side,False)
                self.lineBypassing=False
                self.counter=0
        return self.lineBypassing


class Saving_Process(Process):
    def __init__(self):
        super(Saving_Process, self).__init__()
        self.savingQue=Queue()
        self.daemon=True
        self.start()
    def run(self):
        while(True):
            try:
                imgName, rawImage= self.savingQue.get()
                if imgName=='Quit':
                    break
                rawImage = cv2.cvtColor(rawImage, cv2.COLOR_RGB2BGR)  #without boxes
                cv2.imwrite(f"{imgName}.{IMG_FORMAT}",rawImage)
            except Exception as e:
                logger.warning(f"Saving Process Exception |{imgName}|: {e}")
                continue
        print('Saving Process Closed')

class MyTimer(QThread):
    timeOut = pyqtSignal()
    def __init__(self, parent=None, interval=60):
        super().__init__(parent=parent)
        self.interval=interval
        self.start(3)
    def closeThread(self):
        self.terminate()
    def run(self):
        while True:
            sec=time.time()%self.interval
            time.sleep(self.interval-sec)
            self.timeOut.emit()

class MinuteDataRecorder(QThread):
    def __init__(self, dHandler):
        super().__init__(parent=dHandler)
        self.dHandler=dHandler
        self.que=q.Queue()
        self.lastRecords=emptyRecords()
        self.lastRecordsCopy=emptyRecords()
        self.previousData=np.copy(self.dHandler.data)
        self.start(priority=3)

    def pushIotHub(self,databasePrevState):
        dataDiff=self.dHandler.data-self.previousData
        self.previousData=np.copy(self.dHandler.data)
        if CFG.AIVC_MODE==0: #Send RASM Arm Set Alert
            rasmRecordsData=[rasmRecord.getAllData() for rasmRecord in self.dHandler.rasmRecords]
            copyRecords(self.lastRecordsCopy, self.lastRecords)#Make a copy to avoid being replaced halfway in other thread
            self.dHandler.alertHandler.alertQueue.put([(self.dHandler.rasmRecords,self.lastRecordsCopy,dataDiff),databasePrevState,True])
            copyRecords(self.lastRecords, rasmRecordsData)
        else: #Send Each Side Alert
            self.dHandler.alertHandler.alertQueue.put([dataDiff,databasePrevState,False])#COPY?

    def run(self):
        while True:
            update=self.que.get()
            if update is None:
                break
                
            #Update total
            self.dHandler.updateTotal()
            if CFG.ENABLE_AUTO_RESTART:
                self.dHandler.refreshStatus.emit()
            self.dHandler.jsonRPCThread.producedGlove=self.dHandler.data[4][0]-self.dHandler.dataMin[4][0]#Total Good Glove
            np.copyto(self.dHandler.dataMin,self.dHandler.data)
            rasmRecordsData=[]
            for rasmRecord in self.dHandler.rasmRecords:
                rasmRecordsData.append(rasmRecord.getAllData())
            copyRecords(self.dHandler.rasmRecordsMin, rasmRecordsData)

            now=datetime.datetime.now()
            if self.dHandler.dataRecordState==4:
                self.dHandler.updateStartTime.emit(time.strftime("%m/%d %H:%M:%S"))

            """if (time.time()//60)%15==0:#Trigger time to send former defect rate to powerBI
                if self.dHandler.state<4:
                    self.dHandler.uploadProblematic()"""
                
            if (time.time()//60)%15==0:#Trigger every 15min
                self.dHandler.trigger15min.emit()
                if self.dHandler.state<6:
                    self.dHandler.save15minSideRecord()
                    self.dHandler.uploadDatabase()

                np.copyto(self.dHandler.data15m,self.dHandler.data)
                copyRecords(self.dHandler.rasmRecords15m, rasmRecordsData)
                if self.dHandler.dataRecordState==3:
                    self.dHandler.updateStartTime.emit(time.strftime("%m/%d %H:%M:%S"))
            if self.dHandler.currentHour!=now.hour:  #Trigger every hour
                CFG_Handler.saveBackup()
                self.dHandler.samplingCountDown=50#Save random sampling images for checking
                self.dHandler.saveSegmentedRecord()#Hourly segmented record with state
                np.copyto(self.dHandler.dataHour,self.dHandler.data)
                copyRecords(self.dHandler.rasmRecordsHour, rasmRecordsData)

                if self.dHandler.dataRecordState==2:
                    self.dHandler.updateStartTime.emit(time.strftime("%m/%d %H:%M:%S"))
            if self.dHandler.currentDay!=now.day:  #Trigger every day
                dateTime=time.strftime("%Y%m%d-%H%M")#Change Image Saving Directory
                global CURRENT_DIR,FKTH_CURRENT_DIR,LOW_CONF_DIR,FKTH_LOW_CONF_DIR
                currentDir=f"{BASE_DIR}tag_{dateTime}/"
                fkthDir=f"{BASE_DIR}tag_{dateTime}_FKTH/"
                lowConfDir=f"{BASE_DIR}tag_low_conf_{dateTime}/"
                fkthLCDir=f"{BASE_DIR}tag_low_conf_{dateTime}_FKTH/"

                #makeDirs([currentDir,fkthDir,lowConfDir,fkthLCDir])
                CURRENT_DIR=currentDir
                FKTH_CURRENT_DIR=fkthDir
                LOW_CONF_DIR=lowConfDir
                FKTH_LOW_CONF_DIR=fkthLCDir

                self.dHandler.saveDailyRecord()
                np.copyto(self.dHandler.dataDay,self.dHandler.data)
                copyRecords(self.dHandler.rasmRecordsDay, rasmRecordsData)
                if self.dHandler.dataRecordState==1:
                    self.dHandler.updateStartTime.emit(time.strftime("%m/%d %H:%M:%S"))
            self.dHandler.currentHour=now.hour
            self.dHandler.currentDay=now.day
            self.dHandler.refreshDataTable()
        print('MinuteDataRecorder Closed')

class DataHandler_Thread(QThread):
    refreshStatus=pyqtSignal()
    trigger15min=pyqtSignal()
    updateCamBox = pyqtSignal(QImage, str, int)
    feedPurgingStack=pyqtSignal(int, bool, int)
    rejectAsm=pyqtSignal(int)
    feedPeripheralStack=pyqtSignal(int, int, int)
    adjustCamDelay=pyqtSignal(int, float)
    clearCamBox= pyqtSignal(int)
    lowConfData= pyqtSignal(list,list,np.ndarray)
    setListItem=pyqtSignal(str,str)
    updateRasmGridOfLine=pyqtSignal(int, int, np.ndarray, str)
    chainGridAddArm=pyqtSignal(int, int, np.ndarray, str)
    updateTable=pyqtSignal(int,int,str)
    refreshChainGrids=pyqtSignal(list,bool)
    updateStartTime=pyqtSignal(str)
    yoloResultQue=q.Queue()
    data=np.zeros((5,Data_Num), dtype = int)
    contGoodBadCycle=pyqtSignal(int, int, int, np.ndarray, np.ndarray, np.ndarray)
    contBadData=np.zeros((4,CFG.CHAIN_FORMER_NUM), dtype = int)
    contGoodData=np.zeros((4,CFG.CHAIN_FORMER_NUM), dtype = int)
    formerEmptyLink=np.zeros((4,CFG.CHAIN_FORMER_NUM), dtype = bool)
    dataLow=np.zeros((5,Data_Num), dtype = int)
    totalLow=np.zeros((5,Data_Num), dtype = int)
    prevData=np.zeros((5,Data_Num), dtype = int)
    prevDataLow=np.zeros((5,Data_Num), dtype = int)
    dataStart=np.zeros((5,Data_Num), dtype = int)
    dataDay=np.zeros((5,Data_Num), dtype = int)
    dataHour=np.zeros((5,Data_Num), dtype = int)
    data15m=np.zeros((5,Data_Num), dtype = int)
    dataMin=np.zeros((5,Data_Num), dtype = int)
    lastData=np.zeros((5,Data_Num), dtype = int)
    #prevDatas=[dataStart,dataDay,dataHour,data15m,dataMin]
    tempDefectRecord={}
    capturing=False
    enableCamDelayAdjustment=False
    dataHandlerRunning=True
    lineBypassings=[False for _ in range(4)]
    dataRecordState=0 # 0:Start 1:Day 2:Hour 3:15Minute  4:Minute
    appendProblematicFormer=[]
    dictFormerSend = []

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.databasePrevState=STATE[0]
        self.operationInspectors=[OperationInspector(5,i,self) for i in range(4)]
        self.gloveDefectionRecords=[np.zeros((SIDE_SEP*4,2), dtype = int)]*4
        self.rasmRecords=[FixLenIndexer(f"RASM {SIDE_NAME[i]}",offset=CFG.RASM_ANCHOR_OFFSET[i],totalLen=CFG.RASM_ARM_NUM) for i in range(4)]
        self.chainIndexers=[FixLenIndexer(f"CHAIN {SIDE_NAME[i]}",totalLen=CFG.CHAIN_FORMER_NUM) for i in range(4)]
        emptyDict={}
        for i in range(CFG.RASM_ARM_NUM):
            emptyDict[i]=np.zeros(2,dtype=int)
        self.rasmRecordsStart=emptyRecords()
        self.rasmRecordsDay=emptyRecords()
        self.rasmRecordsHour=emptyRecords()
        self.rasmRecords15m=emptyRecords()
        self.rasmRecordsMin=emptyRecords()
        self.prevRasmRecords=self.rasmRecordsStart

        self.savingProcesses=[Saving_Process() for i in range(SAVING_PROCESS_NUM)]
        self.minuteDataRecorder=MinuteDataRecorder(self)
        self.currentHour=datetime.datetime.now().hour
        self.currentDay=datetime.datetime.now().day
        self.segmentedRecordStartTime=time.strftime("%Y-%m-%d_%H:%M:%S")
        self.dailyRecordStartTime=time.strftime("%Y-%m-%d_%H:%M:%S")
        self.recordStartTime15min=time.strftime("%Y-%m-%d_%H:%M:%S")
        self.state=1
        self.prevState=1
        self.teamsMessenger=TeamsHandler(self,CFG.TEAMS_ADDR)
        self.teamsMessenger.resumePreviousTeamsAddr.connect(self.parent().resumePreviousTeamsAddr)
        
        self.alertHandler=AlertHandler(self, IOTHUB_REST_URI, self.teamsMessenger)
        self.jsonRPCThread=JsonRPCClient(self)
        self.sqlHandler=SQLHandler()
        self.occu=OccuAnalyzer(self.__class__.__name__,30)
        self.RCs=[RepetitionChecker(i) for i in range(4)]
        self.samplingCountDown=50
        self.nasConnected=False
        self.firstAnchor=False
        self.classDatas=[0]*len(CLASSES)
        self.startCapture()

    def sendFormerNum(self,formerNum):
        self.formerNums = formerNum

    def cycleCount(self,cycleNum,triggerCycle):
        self.numCycle = cycleNum
        self.triggerCycle = triggerCycle
        if self.triggerCycle == 1:
            if self.state == 1:
                if self.numCycle >= 3:
                    self.uploadProblematic()
        #print(f'Number of cycle is: {self.numCycle}')

    def lineSpeedAlert(self, aveSecPerGlove):
        longestPurgingDuration=max([purgerSetting[3] for purgerSetting in CFG.PURGER_SETTING])/10
        if aveSecPerGlove<longestPurgingDuration and aveSecPerGlove > 0.1:
            self.teamsMessenger.emit(f'<div style="color:black;background-color: #ffff00; padding:10px">Warning: {CFG.FACTORY_NAME} L{CFG.LINE_NUM} Purging Duration ({longestPurgingDuration} sec) longer than Second Per Glove ({aveSecPerGlove:.3f} sec)</div>')

    def uploadDatabase(self):
        if CFG.AIVC_MODE==0:#TEMP, waiting database upgrade
            self.sqlHandler.upload(self.data,self.databasePrevState)
        self.minuteDataRecorder.pushIotHub(self.databasePrevState)
        self.databasePrevState=STATE[self.state]
    
    def appendProblematic(self,dictDataDefect):
        self.appendProblematicFormer.append(dictDataDefect)
        
    def uploadProblematic(self):
        if CFG.AIVC_MODE==0:
            utcDateTime=datetime.datetime.utcnow().isoformat()
            DateTime=datetime.datetime.now().isoformat()
            defectDict = {}
            defectDict["Good Glove"]=0
            for i in CHAIN_CLASS:
                defectDict[f"{CLASSES[i]}"]=0
            defectDict["Non-Chain-Related"]=0
            defectDict["Defective Rate"]=0
            try:  
                headers={
                    'Authorization' : generateSasToken(IOTHUB_URI_FORMER,IOTHUB_KEY_FORMER,expiry=60),
                    'Content-Type' : "application/json",
                    'Content-Encoding' : "UTF-8"
                } 
                for i in range (len(self.appendProblematicFormer)):
                    self.appendProblematicFormer[i].update({f'Former Count': self.formerNums})

                if len(self.appendProblematicFormer) == 0:
                    emptyFormer = []
                    for side in range(Side_Num):
                        emptyProblematicFormer = {
                            "UTCDateTime": utcDateTime,
                            "DateTime": DateTime, 
                            "Mode": CFG.AIVC_MODE, 
                            "Factory": CFG.FACTORY_NAME, 
                            "ProductionLine": f'L{CFG.LINE_NUM}', 
                            "ProductionLineRow": SIDE_NAME[side], 
                            "FormerID": 999999,
                            "Continuous Good" : 0,
                            "Continuous Bad" : 0,
                            "Cycle Number" : int(self.numCycle),
                            "Defect_Classes": defectDict
                        }
                        emptyFormer.append(emptyProblematicFormer)
                        for i in range (len(emptyFormer)):
                            emptyFormer[i].update({f'Former Count': self.formerNums})
                    Sample_jsonstring = json.dumps(emptyFormer)
                    resp = requests.post(IOTHUB_REST_URI_FORMER, json=Sample_jsonstring, headers=headers)
                    req = requests.post(PROBLEMATIC_FORMER_URL, data=Sample_jsonstring) #upload to power BI\
                    recorder.info(f'Http Status:{req}')
                    recorder.info(f'IotHub Status:{resp}')
                    recorder.info(f'Succesfully upload {len(emptyFormer)} side Former')
                    recorder.info(emptyFormer)
                else:
                    Sample_jsonstrings = json.dumps(self.appendProblematicFormer)
                    resp = requests.post(IOTHUB_REST_URI_FORMER, json=Sample_jsonstrings, headers=headers)
                    req = requests.post(PROBLEMATIC_FORMER_URL, data=Sample_jsonstrings) #upload to power BI\
                    recorder.info(f'Http Status:{req}')
                    recorder.info(f'IotHub Status:{resp}')
                    recorder.info(f'Succesfully upload {len(self.appendProblematicFormer)} defect Former')
                    recorder.info(self.appendProblematicFormer)
                self.appendProblematicFormer.clear()
            except Exception as e:
                recorder.info(f'Failed to upload Problematic Former data to {PROBLEMATIC_FORMER_URL}')

    def saveSegmentedRecord(self):
        dataSegment=self.data-self.lastData
        endTime=time.strftime("%Y-%m-%d_%H:%M:%S")
        data_to_log = [STATE[self.prevState], self.segmentedRecordStartTime, endTime, CFG.FACTORY_NAME, CFG.LINE_NUM]
        data_to_log.extend(dataSegment[4])

        ## Log data
        if not os.path.exists('logs/'):
            os.mkdir('logs/')
        HourlyDataOfMonthDir=f'logs/{datetime.datetime.now().strftime("%y%B")}_AIVCHourlyData.csv'
        if not os.path.exists(HourlyDataOfMonthDir):
            with open(HourlyDataOfMonthDir, mode='a', newline='') as file:
                writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                writer.writerow(["State", "Start Time","End Time","Factory","Line", "Good Glove", "Produced Glove", "Empty Link"]+CLASSES[1:])
        with open(HourlyDataOfMonthDir, mode='a') as file:
            writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            writer.writerow(data_to_log)
        print(f"Record Saved\n{data_to_log}")
        #reset last data & time
        np.copyto(self.lastData,self.data)
        self.segmentedRecordStartTime=endTime
        self.prevState=self.state

    def save15minSideRecord(self):
        if not os.path.exists('logs/'):
            os.mkdir('logs/')
        if not os.path.exists('logs/AIVC15minData.csv'):
            with open('logs/AIVC15minData.csv', mode='a', newline='') as file:
                writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                writer.writerow(["Start Time","End Time","Factory","Line", "Side", "Good Glove", "Produced Glove", "Empty Link"]+CLASSES[1:])

        dataSegment=self.data-self.data15m
        endTime=time.strftime("%Y-%m-%d_%H:%M:%S")
        for side in range(Side_Num):
            data_to_log = [self.recordStartTime15min, endTime, CFG.FACTORY_NAME, CFG.LINE_NUM, SIDE_SHORT[side]]
            data_to_log.extend(dataSegment[side])
            ## Log data
            with open('logs/AIVC15minData.csv', mode='a', newline='') as file:
                writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                writer.writerow(data_to_log)
        print(f"15min Record Saved\n{data_to_log}")
        self.recordStartTime15min=endTime

    def saveDailyRecord(self):
        dataSegment=self.data-self.dataDay
        endTime=time.strftime("%Y-%m-%d_%H:%M:%S")
        data_to_log = [self.dailyRecordStartTime, endTime, CFG.FACTORY_NAME, CFG.LINE_NUM]
        data_to_log.extend(dataSegment[4])

        ## Log data
        if not os.path.exists('logs/'):
            os.mkdir('logs/')
        if not os.path.exists('logs/AIVCDailyData.csv'):
            with open('logs/AIVCDailyData.csv', mode='a', newline='') as file:
                writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                writer.writerow(["Start Time","End Time","Factory","Line", "Good Glove", "Produced Glove", "Empty Link"]+CLASSES[1:])
        with open('logs/AIVCDailyData.csv', mode='a', newline='') as file:
            writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            writer.writerow(data_to_log)
        print(f"Daily Record Saved\n{data_to_log}")
        #reset last time
        self.dailyRecordStartTime=endTime
    def isRunning(self):
        return True if self.state<=1 else False #return true for either START or RUNNING

    def closeThread(self):
        self.uploadDatabase()#Upload last data segment to SQL & IotHub before closing
        try:
            if len(self.appendProblematicFormer) == 0:
                pass
            else:
                self.uploadProblematic()
        except:
            pass
        self.saveSegmentedRecord()
        self.minuteDataRecorder.que.put(None)
        self.teamsMessenger.queue.put(None)
        self.alertHandler.alertQueue.put([None,None,None])
        self.sqlHandler.queue.put(None)
        self.jsonRPCThread.reportQue.put(None)

        for savingProcess in self.savingProcesses:
            savingProcess.savingQue.put(['Quit',None])##Sending quit to stop saving process

        for savingProcess in self.savingProcesses:
            savingProcess.join()
        #self.sp.terminate()
        self.dataHandlerRunning=False
        self.minuteDataRecorder.wait()
        self.teamsMessenger.wait()
        self.alertHandler.wait()
        self.sqlHandler.wait()
        self.jsonRPCThread.wait()
    def feedYoloResult(self,camSeq,frame,pred_bbox,formerID,isRasmAnchor):
        self.yoloResultQue.put([camSeq,frame,pred_bbox,formerID,isRasmAnchor])
    def updateRasmRecord(self, side, cls, isRasmAnchor):
        if isRasmAnchor==1:
            self.rasmRecords[side].anchorReached()

        # armData=ArmData(cls)
        # self.rasmRecords[side].feed(armData)
        if cls<0:#Empty Link
            self.rasmRecords[side].feed(np.zeros(CLASS_NUM,dtype=int))
        else:
            d=np.zeros(CLASS_NUM,dtype=int)
            d[cls]=1
            self.rasmRecords[side].feed(d)

        rasmID=self.rasmRecords[side].getActualIndex()+1
        armRecord = self.rasmRecords[side].get()-self.prevRasmRecords[side][self.rasmRecords[side].currentIdx] #10 class

        #dr=float(dg)/(dg+gg) if gg!=0 else 1
        label=f"{SIDE_NAME[side]} | {CLASSES[cls]} | RASM ID:{rasmID}" ##May Include Former ID like below
        self.updateRasmGridOfLine.emit(side, rasmID, armRecord, label)

    def incrementData(self, line, row):
        self.data[line][row]+=1
        self.dataLow[line][row]+=1
        self.updateTable.emit(row+1,line, str(self.data[line][row]-self.prevData[line][row]))

    def refreshDataTable(self):
        for line,row in np.ndindex(self.data.shape):
            self.updateTable.emit(row+1,line, str(self.data[line][row]-self.prevData[line][row]))
        self.updateTotal()

    def incrementContBad(self,side,former):
        if self.numCycle >= 1:
            self.contBadData[side][former]+=1
            self.contBadDataSend = self.contBadData[side][former]
            #print(f'FormerID: {former} : Side: {side} | Cont Bad: {self.contBadData[side][former]} | Cont Good: {self.contGoodData[side][former]} | Cycle: {self.numCycle}')

    def incrementContGood(self,side,former):
        if self.numCycle >= 1:
            self.contGoodData[side][former]+=1
            self.contGoodDataSend = self.contGoodData[side][former]
            #print(f'FormerID: {former} : Side: {side} | Cont Bad: {self.contBadData[side][former]} | Cont Good: {self.contGoodData[side][former]} | Cycle: {self.numCycle}')

    def resetConsecutiveCount(self,side,former,condition):
        if condition == 0: #Empty Link
            self.contBadData[side][former] = 0
            self.contGoodData[side][former] = 0
            self.formerEmptyLink[side][former] = True
        elif condition == 1: #Defective Glove
            self.contGoodData[side][former] = 0
            self.formerEmptyLink[side][former] = False
        elif condition == 2: #Good Glove
            self.contBadData[side][former] = 0
            self.formerEmptyLink[side][former] = False
        self.contGoodBadCycle.emit(side, former, self.numCycle, self.contBadData, self.contGoodData, self.formerEmptyLink)

    def setGloveDefectionRecord(self, side, formerID, record, lab, classRecord):
        r=np.zeros(CLASS_NUM,dtype=int)
        if record>1:#Defective glove
            for i in range(1,CLASS_NUM):
                if (1<<i) & record:
                    r[i]=1
        elif record & 1==1:#Good Glove
            r[0]=1
        self.chainIndexers[side].feed(r,formerID%SIDE_SEP)

        if record < 1: #No Detection -> empty link
            self.incrementData(side,2)
            self.resetConsecutiveCount(side,formerID%SIDE_SEP,0)
        else: #Increment Produced Glove
            self.incrementData(side,1) 
        if record >1: #Defective glove
            for i in range(CLASS_NUM-1):
                if record & (1<<i+1) > 0:#Check for class flag ##May need to add priority instead of recording all
                    self.incrementData(side,i+3)#Defection row start on row 4
                    if i+3 == 12: # increase bad count for fkth classes
                        self.incrementContBad(side,formerID%SIDE_SEP)
                        self.resetConsecutiveCount(side,formerID%SIDE_SEP,1)
                    elif i+3 == 6: # increase bad count for us classes
                        self.incrementContBad(side,formerID%SIDE_SEP)
                        self.resetConsecutiveCount(side,formerID%SIDE_SEP,1)
                    elif i+3 == 5: # increase bad count for dd classes
                        self.incrementContBad(side,formerID%SIDE_SEP)
                        self.resetConsecutiveCount(side,formerID%SIDE_SEP,1)
                    elif i+3 == 4: # increase bad count for sa classes
                        self.incrementContBad(side,formerID%SIDE_SEP)
                        self.resetConsecutiveCount(side,formerID%SIDE_SEP,1)
                    elif i+3 == 3: # increase bad count for tr classes
                        self.incrementContBad(side,formerID%SIDE_SEP)
                        self.resetConsecutiveCount(side,formerID%SIDE_SEP,1)

            #Show Chain Defective Arm
            currentFormerRecord=self.chainIndexers[side].get()
            pg=np.sum(currentFormerRecord)
            gg=currentFormerRecord[0]
            dg=np.sum(currentFormerRecord[1:])
            dr=dg/(pg)
            if dr>0.02:
                self.chainGridAddArm.emit(side, formerID%SIDE_SEP, currentFormerRecord, lab)
        elif record & 1 == 1: #Good Glove
            #(TOREDO)self.gloveDefectionRecords[side][formerID][1]+=1
            self.incrementData(side,0)
            self.incrementContGood(side,formerID%SIDE_SEP)
            self.resetConsecutiveCount(side,formerID%SIDE_SEP,2)
            

        if formerID%10==0 and side==0: #calculate total and defective rate every 10 former 
            self.updateTotal()

        # syafii edit
        if formerID%1==0 and side==0: #calculate total and defective rate every 1 former 
            self.updateTotalLowConf()
        # syafii edit

        if formerID==0 and side==0:#update the whole grid once for every former iteration
            chainDefectionRecords=[self.chainIndexers[i].getAllData() for i in range(4)]
            if self.firstAnchor:
                clear=True
                self.firstAnchor=False
            else:
                clear=False
            self.refreshChainGrids.emit(chainDefectionRecords,clear)

    def updateTotal(self):        
        self.data[-1,:]=np.sum(self.data[:-1,:],axis=0)
        self.dataDiff=self.data-self.prevData
        total=self.dataDiff[-1,:]
        for i in range(Data_Num):#Total
            self.updateTable.emit(i+1,4, str(total[i]))
        np.seterr(divide='ignore', invalid='ignore')
        dr=1-self.dataDiff[:,0]/self.dataDiff[:,1]  #1-GoodGlove/ProducedGlove
        for i in range(5):#Defective rate (1st row)
            self.updateTable.emit(0,i, str(f'{dr[i]*100:.2f}%'))

    #syafii edit, add new function
    def updateTotalLowConf(self):
        self.dataLow[-1,:]=np.sum(self.dataLow[:-1,:],axis=0)
        self.dataDiffLow=self.dataLow-self.prevDataLow
        self.totalLow=self.dataDiffLow[-1,:]

    #syafii edit, add new function
    def getLowConfidence(self,classIds):
        total = self.totalLow
        appendLowConfidence=[]
        for i in range (len(DATA_NAMES)):
            if i<1:
                appendLowConfidence.append(total[i])
            elif i>2:
                appendLowConfidence.append(total[i])# total glove
        for i in range(len(CLASSES)):
            if classIds == i:
                self.classDatas[i]+=1 #increase if got low confident 
                differentDataRate = np.nan_to_num((np.subtract(appendLowConfidence,self.classDatas)/appendLowConfidence))*100
                if not -inf in differentDataRate:
                    self.lowConfData.emit(appendLowConfidence,self.classDatas,differentDataRate)

    def startCapture(self):
        self.capturing=not self.capturing
        if self.capturing:
            # tracelog
            logger.info("START CAPTURE")
            #Create directory for image tagging
            dirsToCreate=[BASE_DIR+RASM_NO_DETECT_DIR, BASE_DIR+FKTH_NO_DETECT_DIR, \
            BASE_DIR+SAMPLING_DIR, BASE_DIR+FKTH_SAMPLING_DIR]
            global CURRENT_DIR, FKTH_CURRENT_DIR, LOW_CONF_DIR, FKTH_LOW_CONF_DIR
            dateTime=time.strftime("%Y%m%d-%H%M%S")
            CURRENT_DIR=f"{BASE_DIR}tag_{dateTime}/"
            FKTH_CURRENT_DIR=f"{BASE_DIR}tag_{dateTime}_FKTH/"
            LOW_CONF_DIR=f"{BASE_DIR}tag_low_conf_{dateTime}/"
            FKTH_LOW_CONF_DIR=f"{BASE_DIR}tag_low_conf_{dateTime}_FKTH/"

            #Check NAS Connection
            try:
                smbclient.register_session(NAS_IP,username='AIVCHQ', password='aivchq123456', connection_timeout=0.2)
                self.nasConnected=True
                smbclient.makedirs(NAS_DIR, exist_ok=True)
                print(f"Connected NAS at {NAS_IP}")
            except Exception as e:
                print(f"Can't access NAS: {e}")
                self.nasConnected=False
        else:
            # tracelog
            logger.info("STOP CAPTURE") 

    def setAutoCamDelay(self, enable):
        self.enableCamDelayAdjustment=enable

    def drawBBoxes(self, frame, bboxes, ch, w, h):
        image = utils.draw_bbox(frame, bboxes)
        bytesPerLine = ch * w
        convertToQtFormat = QImage(image.data, w, h, bytesPerLine, QImage.Format_RGB888)
        convertedImg = convertToQtFormat.scaled(440, 330, Qt.KeepAspectRatio)
        return convertedImg
    def saveImg(self, imgName, img, label=None):
        #send img to saving queue, will be save by savingProcess in another core
        os.makedirs(os.path.dirname(imgName), exist_ok=True)
        if label:
            with open(imgName+'.txt', "w") as f:
                f.write(label)
        sn=random.randint(0,SAVING_PROCESS_NUM-1)
        if not self.savingProcesses[sn].is_alive():#Check if it is closed somehow
            self.savingProcesses[sn]=Saving_Process()#Restart
            logger.info("Saving Process Restarted")
        self.savingProcesses[sn].savingQue.put([imgName,img])
        
    def noneCamera(self):
        recorder.info("No Camera Found, Changed State To 'None Camera'")
        self.state=5#None Camera State
    def firstChainAnchorReached(self):
        for chainIndexer in self.chainIndexers:
            chainIndexer.anchorReached()
        self.firstAnchor=True
    def run(self):
        b=[0,0,0,0,0,100]# dummy class for initial start
        while self.dataHandlerRunning:
            try:
                camSeq, frame, pred_bbox, formerID, isRasmAnchor= self.yoloResultQue.get(timeout=0.5) 
            except q.Empty:
                continue
            self.occu.start()
            side=getSide(camSeq)
            h, w, ch = frame.shape
            frame_size = frame.shape[:2]
            pred_bbox = [tf.reshape(x, (-1, tf.shape(x)[-1])) for x in pred_bbox]  
            pred_bbox = tf.concat(pred_bbox, axis=0)
            bboxes = utils.postprocess_boxes(pred_bbox, frame_size, FIXED_INPUT_SIZE, 0.3)
            bboxes = utils.nms2(bboxes, 0.45, method='nms')
            rawImage=frame.copy() ##Better way?
            classStr=""
            classFlag=0b0
            for b in bboxes:
                #change unstripped in fkth to good glove
                if(int(b[5])==4):
                    if isFKTH(camSeq):
                        b[5]=0
                classFlag=classFlag | (1<< int(b[5]))
                classStr += CLASSES[int(b[5])] + " "
                self.lineBypassings[side]=self.operationInspectors[side].isRunning(False if b[5]==BYPASS_CLASS else True)
            if formerID == -2:#No PLC connection, skip data recording
                img=self.drawBBoxes(frame, bboxes, ch, w, h)
                self.updateCamBox.emit(img, f'{SIDE_NAME[side]} No PLC Connection. Image captured on timeout.', camSeq)
                self.state=4 #No PLC connection state
                print('No PLC Connection')
            elif formerID == -1: #Line Stopped
                img=self.drawBBoxes(frame, bboxes, ch, w, h)
                self.updateCamBox.emit(img, f'{SIDE_NAME[side]} Line Stopped. Image captured on timeout.', camSeq)
                self.state=3 #line stopped state
            elif self.lineBypassings[side]:#Skip data recording
                img=self.drawBBoxes(frame, bboxes, ch, w, h)
                rasmID2=self.rasmRecords[side].getActualIndex()+1
                self.updateCamBox.emit(img, f'{SIDE_NAME[side]} Bypassing. | Former ID: {formerID} | RASM ID: {rasmID2}', camSeq)
                if self.lineBypassings==[True,True,True,True]:
                    self.state=2 #bypassing state
                else:
                    self.state=1
            else:
                self.state=1

            #checking line state change 
            if self.state!=self.prevState:
                try:
                    if len(self.appendProblematicFormer) == 0:
                        pass
                    else:
                        if self.prevState == 1:
                            self.uploadProblematic()
                except:
                    pass
                self.saveSegmentedRecord()
                self.uploadDatabase()

            if not self.isRunning():
                self.occu.end()
                continue #Skip data recording
            #Check Former Interval by observing empty link
            if CFG.CHECK_REPETITION and classFlag==0:
                if isRASM(camSeq):
                    self.RCs[side].feedCenterList(formerID)
                elif isFKTH(camSeq):
                    self.RCs[side].feedListToAlign(camSeq%2,formerID)

            if self.lineBypassings[side]:
                self.occu.end()
                continue #Skip data recording for this side


            #rasm tearing camera
            if isRASM(camSeq):
                self.updateRasmRecord(side, int(bboxes[0][5] if bboxes else -1), isRasmAnchor) #RASM ID updated here
            rasmID1=self.rasmRecords[side].getActualIndex()+1
            camStr=f"{SIDE_NAME[side]} | {classStr}| Former ID: {formerID}{f' | RASM ID: {rasmID1}' if isRASM(camSeq) else ''}"
            #Update tempDefectRecord 
            previousRecord=0
            if formerID in self.tempDefectRecord:
                previousRecord=self.tempDefectRecord[formerID]
                self.tempDefectRecord[formerID]=previousRecord | classFlag #Accumulate defection
            else:
                self.tempDefectRecord[formerID]=classFlag
            image = utils.draw_bbox(frame, bboxes)
            ######put class text on img
            # if isRASM(camSeq):
            #     prevClassStr=''
            #     for i in range(CLASS_NUM):
            #         if previousRecord & 1 == 1:
            #             prevClassStr+=CLASSES[i]
            #         previousRecord=previousRecord>>1
            #     cv2.putText(image, prevClassStr, (20, 60), cv2.FONT_HERSHEY_SIMPLEX,
            #                 2, (255, 255, 255), 3, lineType=cv2.LINE_AA)
            ##############################
            bytesPerLine = ch * w
            convertToQtFormat = QImage(image.data, w, h, bytesPerLine, QImage.Format_RGB888)
            p = convertToQtFormat.scaled(440, 330, Qt.KeepAspectRatio)
            self.updateCamBox.emit(p, camStr, camSeq)

            if not isFKTH(camSeq): #last cam, update data, pop temp
                record=self.tempDefectRecord.pop(formerID)
                self.setGloveDefectionRecord(side, formerID, record, camStr, int(b[5]))
            #if classFlag>1: #Defective Glove
            rework=False
            dispose=False
            periRecord=0
            for b in bboxes:
                if b[4]>CFG.CONF_LEVEL_TO_PURGE:
                    if (1 << (int(b[5])) & CFG.CLASS_TO_REWORK):
                        rework=True
                    if (1 << (int(b[5])) & CFG.CLASS_TO_DISPOSE):
                        dispose=True
                    for idx, periClass in enumerate(CFG.PERI_CLASS):
                        if (1 << (int(b[5])) & periClass):
                            periRecord|=(1<<idx)
            if CFG.AIVC_MODE==0:#Feed purging signal
                if rework or dispose:
                    if (isRASM(camSeq) and CFG.ENABLE_PURGE_RASM[side]) or (isFKTH(camSeq) and CFG.ENABLE_PURGE_FKTH[side]):
                        self.feedPurgingStack.emit(formerID, not rework, camSeq)#rework priority
                    else:
                        print(f'{CAM_NAME[camSeq]} Purging Disabled {formerID}')

            if periRecord and CFG.ENABLE_PERIPHERAL[side]:
                self.feedPeripheralStack.emit(formerID,periRecord,camSeq)

            if CFG.AIVC_MODE==2:#ASM
                if dispose or rework:
                    if CFG.ENABLE_PERIPHERAL[side]:
                        self.rejectAsm.emit(camSeq)#A#Assume individual belt control
                    else:
                        print(f"{SIDE_NAME[side]} ASM Reject Disabled")

            if self.capturing:
                milliseconds = int(round(time.time() * 100))
                milliseconds%=100
                timestr=time.strftime("%Y%m%d-%H%M%S")
                name=f'img{timestr}-{milliseconds}_{CAM_NAME[camSeq]}_{formerID}'
                imgName=''
                lowConfName=''
                foundObject=False
                lowConfidence=False
                empty=True
                label=''
                labelLow=''
                for b in bboxes:
                    empty=False
                    xc=(b[0]+b[2])*0.5/w
                    yc=(b[1]+b[3])*0.5/h
                    width=(b[2]-b[0])/w
                    height=(b[3]-b[1])/h
                    classId=int(b[5])
                    if( classId>0 ): #Defect glove
                        foundObject=True
                        label+=f"{classId} {xc} {yc} {width} {height}\n"
                        if not imgName: #
                            if not isFKTH(camSeq):
                                imgName=f"{CURRENT_DIR}{name}_{int(b[4]*100)}"
                            else:
                                if(classId==4):#skip unstripped in fkth
                                    foundObject=False
                                    continue
                                imgName=f"{FKTH_CURRENT_DIR}{name}_{int(b[4]*100)}"
                        if CFG.AIVC_MODE==2:
                            s=str(camSeq % MAX_ASM_LENGTH)
                        elif not isFKTH(camSeq):
                            s=f'{(rasmID1):02d}'
                        else:
                            s=CAM_NAME[camSeq][-1]#Either T or B
                        listStr=f'{CLASSES[classId]}\t{b[4]*100:.2f}%    {time.strftime("%H:%M:%S")}    {SIDE_SHORT[side]}{s}    {formerID:05d}'
                        self.setListItem.emit(listStr, f"{imgName}.{IMG_FORMAT}")
                    
                    #syafii edit
                    try:
                        if b[4]<0.90:
                            self.getLowConfidence(classId)
                    except:
                        pass
                    #syafii edit    

                    if b[4]<CFG.LOW_CONF_THRESHOLD: #Any low confidence inference
                        labelLow+=f"{classId} {xc} {yc} {width} {height}\n"
                        lowConfidence=True
                        if not lowConfName:
                            if not isFKTH(camSeq):
                                lowConfName=f"{LOW_CONF_DIR}{name}_{int(b[4]*100)}"
                            else:
                                lowConfName=f"{FKTH_LOW_CONF_DIR}{name}_{int(b[4]*100)}"

                if(foundObject):
                    self.saveImg(imgName,rawImage,label)
                if(lowConfidence):
                    self.saveImg(lowConfName,rawImage,labelLow)
                    if CFG.ENABLE_NAS_SHARE and self.nasConnected:
                        if(random.random()<0.1):
                            try:
                                fName=f"{NAS_DIR}{CFG.FACTORY_NAME}L{CFG.LINE_NUM}_{name}_{int(b[4]*100)}"
                                self.saveImg(fName,rawImage,labelLow)
                            except PermissionError as e:
                                print(f"Can't access NAS, pls login: {e}")
                            except Exception as e:
                                self.nasConnected=False
                                logger.warning(f"NAS Unhandled Error: {e}")
                                print('Stop Uploading To NAS')

                if(empty):
                    if not isFKTH(camSeq):
                        emptyName=f"{BASE_DIR}{RASM_NO_DETECT_DIR}{name}"
                    else:
                        emptyName=f"{BASE_DIR}{FKTH_NO_DETECT_DIR}{name}"
                    self.saveImg(emptyName,rawImage)
                #sampling

                if(self.samplingCountDown>0):
                    if(random.random()<0.01):
                        self.samplingCountDown-=1
                        if not isFKTH(camSeq):
                            samplingName=f"{BASE_DIR}{SAMPLING_DIR}{name}"
                        else:
                            samplingName=f"{BASE_DIR}{FKTH_SAMPLING_DIR}{name}"
                        if empty:
                            lab=' '
                        else:
                            lab=f"{int(b[5])} {xc} {yc} {width} {height}\n"
                        self.saveImg(samplingName,rawImage,lab)
            #print(f'total time: {total_time}')

            if(self.enableCamDelayAdjustment):
                widest=0
                for b in bboxes:
                    wid=b[2]-b[0]
                    if wid>widest:
                        widest=wid
                        xc=(b[2]+b[0])*0.5/w

                self.adjustCamDelay.emit(camSeq, xc)
            self.occu.end()
        self.yoloResultQue.queue.clear()
        print('Data Handler Thread Closed')

class Camera_Thread(QThread):
    feedCaptureQue=pyqtSignal(int, np.ndarray, np.ndarray, int, int)
    def __init__(self, parent, camControl,camNum,seq,camDetails,plc):
        super().__init__(parent=parent)
        self.que=q.Queue()
        self.camNum=camNum
        self.seq=seq
        self.camDetails=camDetails
        self.plc=plc
        self.camRunning=True
        self.camControl=camControl
        self.colorDetector=ColorDetect()
        self.capture=False
        self.occu=OccuAnalyzer(self.__class__.__name__,30)
        self.t=time.time()

    def run(self):
        while True:
            formerID=self.que.get()
            #print(f'Capture que get{self.t-time.time()}')
            self.t=time.time()
            if formerID == None: #End Thread
                print(f"Cam{self.camNum} thread closed")
                break

            self.occu.start()
            ret, frame, camIP = self.camControl.capture(self.camNum)
            camSeq=Cam_Seq[self.seq]
            side=getSide(camSeq)
            isRasmAnchor=False
            if isRASM(camSeq):
                if CFG.RASM_ANCHOR_INSTALLED:
                    isRasmAnchor=self.plc.readRasmAnchor(side)
                else:
                    isRasmAnchor=self.colorDetector.detect(frame) #Color sticker anchor

            if ret==0:#Sucess read
                if frame.shape[0]==0:
                    logger.warning("CAPTURED EMPTY IMAGE!")
                    self.occu.end()
                    continue
                if CFG.ROTATE:
                    frame=cv2.rotate(frame, cv2.ROTATE_90_COUNTERCLOCKWISE)
                image_processed = np.asarray(utils.image_preporcess(frame, [FIXED_INPUT_SIZE, FIXED_INPUT_SIZE])[np.newaxis, ...],dtype=np.float32)
                self.feedCaptureQue.emit(camSeq, frame, image_processed, formerID, isRasmAnchor)
            else:
                print(f'Fatal: Cam {SIDE_NAME[getSide(camSeq)]} Lost Connection')
                self.que.queue.clear()
            self.occu.end()

class Capture_Thread(QThread):
    feedPurgerQue=pyqtSignal(int,int)
    sendAveLineSpeed=pyqtSignal(float)
    camCapture=pyqtSignal(int)
    setCurLineSpeedTxt=pyqtSignal(str)
    setAveLineSpeedTxt=pyqtSignal(str)
    resetPlc=pyqtSignal()
    noneCamera=pyqtSignal()
    firstChainAnchorReached=pyqtSignal()
    setAnchorID=pyqtSignal(list)
    cycleCount=pyqtSignal(int,int)
    sendFormerNum=pyqtSignal(int)
    camThreadRunning=True
    cycleNum=0
    formerNum=0
    sendCycle=True


    def __init__(self, parent, plc):
        super().__init__(parent=parent)
        self.plc=plc
        self.timingChecker=TimingChecker(self.__class__.__name__,length=30,tolerance=10)
        self.camControl=CamControl()
        camRet= self.camControl.init(CFG.IP_RANGE)#return connected cam numbers sorted by IP
        global Cams_Num
        Cams_Num=self.camControl.getCamsNum()
        self.camThreads=[]
        self.secPerGloves=[0 for i in range(CFG.SENSOR_NUM)]
        self.triggerInterval=[0 for i in range(CFG.PERI_SENSOR_NUM)]
        self.secPerGloveList=deque(maxlen=20)
        self.secPerPeriList=deque(maxlen=20)
        self.aveSecPerGlove=0
        self.aveSecPerPeri=0
        self.plcDisconnected=False
        if CFG.AIVC_MODE==2:#ASM
            self.formerPerTrigger=CFG.ASM_LENGTH
        else:
            self.formerPerTrigger=1


        if camRet==-1:
            print(f"Failed To Init CamControl")
        else:
            camListByIp, camDetails=camRet
            print(f"INIT{camListByIp}")
            for seq,camNum in enumerate(camListByIp):
                camThread=Camera_Thread(self,self.camControl,camNum,seq,camDetails[seq],self.plc)
                camThread.start(priority=6)
                self.camThreads.append(camThread)

    def getAveLineSpeed(self):
        if self.aveSecPerGlove:
            self.sendAveLineSpeed.emit(self.aveSecPerGlove)

    #Obsolete
    def adjustCamDelay(self, camSeq, xc):
        if xc > 0.40 and xc < 0.60:
            return
        if camSeq%2==0: ##Right side, glove move to left (-x)
            return
        #displacement: how much the glove move toward -x axis because of additional delay to capture
        num_cam=Cam_Seq.index(camSeq)
        try:
            displacement=self.indiviDelay[num_cam]/self.secPerGlove
        except ZeroDivisionError:
            displacement = 0
        #xc: center x of bounding box
        distanceFromCenter=xc-0.5
        if xc > 0.5: #glove at right half of the view
            if displacement > 0.9:
                self.indiviDelay[num_cam]=0.1*self.secPerGlove
            else:
                self.indiviDelay[num_cam]+=0.1*distanceFromCenter*distanceFromCenter
        else: #glove at left half of the view
            if displacement < 0.001:
                self.indiviDelay[num_cam]=0.3*self.secPerGlove
            else:
                self.indiviDelay[num_cam]-=0.1*distanceFromCenter*distanceFromCenter

    def closeThread(self):
        self.camThreadRunning=False
        for camThread in self.camThreads:
            camThread.que.put(None)
    def run(self):
        CFormerIDs=[-1]*CFG.SENSOR_NUM
        if Cams_Num>len(Cam_Seq):
            logger.error(f'ERROR: Number Of Camera Connected ({Cams_Num}) More Than AIVC Camera Slot ({len(Cam_Seq)})')
        if not self.camThreads:
            self.noneCamera.emit()
        #Initialise camera individual delay [index,delay in sec]
        self.indiviDelay=np.zeros(MAX_CAM_NUM)
        for numCam in range(Cams_Num):
            self.indiviDelay[numCam]=Cam_Delay[Cam_Seq[numCam]]/1000
        firstAnchor=True
        #Encoder
        averageRotationDeque=deque(maxlen=50)
        prevRotaryCodes=[-1]*4
        averageRotation=CFG.ENCODER_PULSE_PER_FORMER
        rotation=-1
        #Image Capturing Loop 
        triggerTimes=[0]*CFG.SENSOR_NUM
        camTriggereds=[False]*Cams_Num
        prev_times=[0 for _ in range(CFG.SENSOR_NUM)]
        countDown=1000
        stringID=[]
        strID=[]
        sendFormer=[]
        encoderT=time.time()
        pt=time.time()
        self.plc.clearFlags()
        while self.camThreadRunning:
            startT=time.time()
            gloveSensors=self.plc.readSensors(CFG.SENSOR_M)
            readT=time.time()
            if gloveSensors is not -1:  #has plc connection
                if self.plcDisconnected==True:#plc reconnected
                    self.plcDisconnected=False
                    self.resetPlc.emit()#reset purger timing because plc memory lost due to power reset
                for s in range(CFG.SENSOR_NUM):
                    if gloveSensors[s]:#one former past
                        self.secPerGloves[s] = time.time() - prev_times[s]

                        if self.secPerGloves[s] >0.15: #Valid Sensor Trigger #Debouncing 
                            prev_times[s] = time.time()
                            #TEMP#Encoder----------------
                            miscountNum=0
                            try:
                                if CFG.ENCODER_INSTALLED:
                                    encoderRet=self.plc.readEncoder(s)
                                    encoderT=time.time()
                                    if encoderRet!=-1:
                                        rotaryCode=encoderRet
                                        if prevRotaryCodes[s]!=-1:#Skip 1st reading
                                            rotation=rotaryCode-prevRotaryCodes[s]
                                            if rotation<-1000:
                                                rotation+=10000
                                            # if rotation>400: #lost connection check #May not need
                                            #     rotation=-1
                                            if len(averageRotationDeque)>30:
                                                averageRotation=sum(averageRotationDeque)/len(averageRotationDeque)
                                            if rotation < 0.6*averageRotation:#Extra count
                                                recorder.debug(f"Extra Count: {rotaryCode,averageRotation,s,rotation,CFormerIDs}")
                                            elif rotation > 1.4*averageRotation: #missed count
                                                encoderDiff=(rotation/averageRotation)
                                                recorder.debug(f"{rotaryCode,averageRotation,s,rotation,CFormerIDs,encoderDiff}")
                                                miscountNum= round(encoderDiff)-1#missed counted, add back
                                                if miscountNum>0:
                                                    recorder.info(f"{rotaryCode} Miscount detected. Average_rotation:{averageRotation} Current_rotation:{rotation} Counting_added:{miscountNum}")
                                            else:#valid
                                                #print(f"{rotaryCode} Ave:{averageRotation} Sensor{s} Rot:{rotation} {CFormerIDs}")#zan
                                                averageRotationDeque.append(rotation)
                                        prevRotaryCodes[s]=rotaryCode
                            except Exception as e:
                                recorder.debug(f"Encoder Exception: {e}\n{format_exc()}")
                            #-----------------------
                                
                            if s == 0:#Check Chain Anchor
                                self.formerNum+=1
                                self.sendFormerNum.emit(self.formerNum)
                                if self.cycleNum == 0 and self.sendCycle == True: #pass initial cycle which is 0
                                    self.cycleCount.emit(self.cycleNum,0)
                                    self.sendCycle=False
                                    self.formerNum=0
                                if self.plc.readChainAnchor(CFG.AIVC_MODE) ==1: #1:anchor 0:none -1:error
                                    recorder.debug(f"Reached Chain Anchor {CFormerIDs} {CFG.CHAIN_FORMER_NUM}")
                                    self.cycleNum+=1
                                    self.cycleCount.emit(self.cycleNum,1)
                                    self.formerNum=0
                                    if firstAnchor:
                                        recorder.debug("First Anchor")
                                        firstAnchor=False
                                        self.firstChainAnchorReached.emit()
                                        anchorIDs=[CFormerIDs[CFG.PURGER_SENSOR[side]]+(1+miscountNum)*self.formerPerTrigger for side in range(4)]
                                        self.setAnchorID.emit(anchorIDs)
                                    CFormerIDs=[-1]*CFG.SENSOR_NUM
                                    
                            CFormerIDs[s]+=(1+miscountNum)*self.formerPerTrigger
                            if(CFormerIDs[s]>=TOTAL_FORMER):
                                CFormerIDs[s]=CFormerIDs[s]-TOTAL_FORMER
                            for side in range(4):
                                if CFG.PURGER_SENSOR[side] == s:
                                    self.feedPurgerQue.emit(side,CFormerIDs[CFG.PURGER_SENSOR[side]])#Purge glove if defected glove reached purger#T#

                            if self.secPerGloves[s] < 4: #Avoid record first trigger after line started moving
                                self.secPerGloveList.append(self.secPerGloves[s])
                                try:
                                    self.aveSecPerGlove=sum(self.secPerGloveList)/len(self.secPerGloveList)
                                except ZeroDivisionError:
                                    self.aveSecPerGlove=0
                                if self.aveSecPerGlove: #Check Abnormal
                                    if self.secPerGloves[s]<0.4*self.aveSecPerGlove or self.secPerGloves[s]>1.6*self.aveSecPerGlove:
                                        logger.warning(f"M{s+CFG.SENSOR_M} Abnormal Trigger Time: {self.secPerGloves[s]:.3f} sec. Last 20 Average Trigger Time: {self.aveSecPerGlove:.3f} sec.")
                                    if s == 0: #Display Line Speed By X0
                                        gloveSpeed=Side_Num/self.secPerGloves[0]
                                        self.setCurLineSpeedTxt.emit(f"{gloveSpeed:.3f} pc/s")
                                        aveGloveSpeed=Side_Num/self.aveSecPerGlove
                                        self.setAveLineSpeedTxt.emit(f"{aveGloveSpeed:.3f} pc/s")
                        elif self.secPerGloves[s] >0: #Avoid Windows auto adjust time resulting negative value here => 0~0.25s
                            print(f"Warning: M{s+CFG.SENSOR_M} Sensor Bouncing! {self.secPerGloves[s]:.3f} sec")
                        for num_cam in range(Cams_Num):
                            camSensor=Cam_Sensor[Cam_Seq[num_cam]]
                            if s==camSensor and prev_times[s]!=0:
                                camTriggereds[num_cam]=True
                                triggerTimes[camSensor]=time.time()
                                countDown=1000
                processT=time.time()
                for num_cam, camTrigered in enumerate(camTriggereds):
                    if camTrigered:
                        if time.time() - triggerTimes[Cam_Sensor[num_cam]]>self.indiviDelay[num_cam]:
                            camSeq=Cam_Seq[num_cam]
                            side=getSide(camSeq)
                            #R#
                            id=(CFormerIDs[CFG.PURGER_SENSOR[side]]+Former_Interval[camSeq])
                            if CFG.AIVC_MODE==2:#ASM
                                id+=camSeq % MAX_ASM_LENGTH
                            formerID=id % TOTAL_FORMER + side*SIDE_SEP
                            self.camThreads[num_cam].que.put(formerID)#Capture Image
                            """stringID = str(formerID%SIDE_SEP).zfill(4) #0001
                            for i in stringID:
                                if len(stringID) == 4:
                                    strID.append(i)
                            sendFormer = convertToAscii(strID)
                            self.plc.formerCounting(sendFormer)
                            strID.clear()"""
                            if CFG.COUNTER_INSTALLED:
                                if CFG.AIVC_MODE==0:
                                    if camSeq == 8 or camSeq == 9 or camSeq == 10 or camSeq == 11:
                                        if camSeq == 8:
                                            idPLC=(CFormerIDs[CFG.PURGER_SENSOR[side]]+Former_Interval[camSeq]+Former_Plc_offset[0])
                                        elif camSeq ==9:
                                            idPLC=(CFormerIDs[CFG.PURGER_SENSOR[side]]+Former_Interval[camSeq]+Former_Plc_offset[1])
                                        elif camSeq ==10:
                                            idPLC=(CFormerIDs[CFG.PURGER_SENSOR[side]]+Former_Interval[camSeq]+Former_Plc_offset[2])
                                        elif camSeq ==11:
                                            idPLC=(CFormerIDs[CFG.PURGER_SENSOR[side]]+Former_Interval[camSeq]+Former_Plc_offset[3])
                                    
                                        formerIDplc=idPLC % TOTAL_FORMER + side*SIDE_SEP
                                        stringID = str(formerIDplc%SIDE_SEP).zfill(4) #0001
                                        for i in stringID:
                                            if len(stringID) == 4:
                                                strID.append(i)
                                        if strID:
                                            sendFormer = convertToAscii(strID)
                                            self.plc.formerCounting(sendFormer,camSeq)
                                            strID.clear()
                            
                            camTriggereds[num_cam]=False

                countDown-=1
                if countDown<1:
                    countDown=2000
                    print("Production Line Stopped")
                    for cam in self.camThreads:
                        cam.que.put(-1)#Line Stopped
                self.timingChecker.check()
                t=time.time()
                if (t-pt)>0.1:
                    recorder.debug(f'Warning: Slow Reading From PLC: {(t-pt):.3f}s. sleep:{(startT-pt):.3f} read:{(readT-startT):.3f} encoder:{(encoderT-readT):.3f} process:{(t-processT):.3f}')
                pt=time.time()
                time.sleep(0.0015)
            else:
                self.plcDisconnected=True
                for cam in self.camThreads:
                    cam.que.put(-2)#None PLC Connection
        print("Capture Thread Closed")

class Inference_Thread(QThread):
    feedYoloResult = pyqtSignal(int, np.ndarray, list, int, int)
    clearCamBox = pyqtSignal(int)
    inferenceRunning=True
    captureQue=q.Queue()
    payload=[]

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.occu=OccuAnalyzer(self.__class__.__name__,100)
        
        input_layer  = tf.keras.layers.Input([FIXED_INPUT_SIZE, FIXED_INPUT_SIZE, 3])
        feature_maps = YOLOv3(input_layer)

        bbox_tensors = []
        for i, fm in enumerate(feature_maps):
            bbox_tensor = decode(fm, i)
            bbox_tensors.append(bbox_tensor)

        self.model = tf.keras.Model(input_layer, bbox_tensors)
        utils.load_weights(self.model, "./yolov3_glove.weights")

        #model.summary()
        dummyArray=np.zeros((1,FIXED_INPUT_SIZE,FIXED_INPUT_SIZE,3))
        dummy_bbox = self.model.predict_on_batch(dummyArray)#Fire first inference to warm up (first inference is slow)

    def feedCaptureQue(self, camSeq, image, image_processed, formerID, isRasmAnchor):
        self.captureQue.put([camSeq, image, image_processed, formerID, isRasmAnchor])

    def closeThread(self):
        self.inferenceRunning=False

    def batchProcessYolo(self):
        self.occu.start()
        images_data=[p[0] for p in self.payload]
        images_data=np.vstack(images_data)
        t=time.time()
        try:
            pred_bboxes = self.model.predict_on_batch(images_data)
        except Exception as e:
            logger.error(f"Cuda Failed: {e}")
            return -1
        for i in range(len(self.payload)):
            self.feedYoloResult.emit(self.payload[i][1],self.payload[i][2],[pred_bbox[i] for pred_bbox in pred_bboxes],self.payload[i][3],self.payload[i][4]) ##let data handler handle
        self.payload.clear()
        self.occu.end()

    def run(self):
        while self.inferenceRunning:
            try:
                camSeq, frame, image_processed, formerID, isRasmAnchor= self.captureQue.get(timeout=0.1) 
            except q.Empty:
                if self.inferenceRunning and self.payload: #not empty
                    #print(f'BATCH_SIZE:{CFG.BATCH_SIZE}, images intake: {len(self.payload)}')
                    self.batchProcessYolo()
                continue
            if frame is None:#Clear Cam View
                self.clearCamBox.emit(camSeq)
                continue
            self.payload.append([image_processed, camSeq, frame, formerID, isRasmAnchor]) #store img for batch prediction
            if len(self.payload)==CFG.BATCH_SIZE:#Straight go prediction if batch_size reached
                self.batchProcessYolo()
        self.captureQue.queue.clear()
        print("Inference Thread Closed")


class MainWindow(QMainWindow):
    camBoxes=[]
    rasmDefectionGrids=[]
    gloveDefectionGrids=[]
    capturing=True
    refreshDataTable=pyqtSignal()

    def __init__(self):
        super(MainWindow, self).__init__()
        # tracelog
        logger.info("APPLICATION LAUNCH")
        self.setAttribute(Qt.WA_DeleteOnClose)

        self.user=None
        self.accessLvl=10

        global NAS_DIR
        NAS_DIR=f"\\\\{NAS_IP}\\Public\\{CFG.FACTORY_NAME}\\"
        self.setStyleSheet("""QToolTip { 
                           background-color: black; 
                           color: white; 
                           border: black solid 1px
                           }""")

        self.ui = Ui_AIVCMainWindow()
        self.ui.setupUi(self)
        self.showFullScreen()
        self.ui.table_defect_data.setRowCount(CLASS_NUM+3)
        for i in range(CLASS_NUM-1):
            item = QTableWidgetItem()
            item.setText(CLASSES[i+1])
            self.ui.table_defect_data.setVerticalHeaderItem(i+4, item)
            for j in range(5):
                item = QTableWidgetItem()
                item.setText("0")
                self.ui.table_defect_data.setItem(i+4, j, item)

        self.ui.label_title.setText(f'Integrated AIVC System  {CFG.FACTORY_NAME} LINE {CFG.LINE_NUM}')
        #self.ui.label_title.setText(f'AIVC System DEVELOPER MODE DO NOT CLOSED')
        self.ui.label_version.setText(f'V2.3.62.7n')
        self.ui.select_duration.currentIndexChanged.connect(self.changeRecordDuration)
        self.camBoxes=[CamBox(i) for i in range(MAX_CAM_NUM)]
        #Populate Camera View
        for i in range(8):
            self.ui.grid_fingertip_cam.addWidget(self.camBoxes[i], i/2, i%2, 1, 1)

        for i in range(4):
            self.ui.grid_rasm_cam.addWidget(self.camBoxes[i+8], i/2,i%2, 1, 1)
            rasmDefectionGrid=DefectionGrid(i,parent=self,armNum=CFG.RASM_ARM_NUM)
            self.ui.grid_rasm_data.addWidget(rasmDefectionGrid, i/2, i%2, 1, 1)
            self.rasmDefectionGrids.append(rasmDefectionGrid)

            gloveDefectionGrid=DefectionGrid(i,parent=self)
            self.ui.grid_chain_data.addWidget(gloveDefectionGrid, i/2, i%2, 1, 1)
            self.gloveDefectionGrids.append(gloveDefectionGrid)
            gloveDefectionGrid.sendProblematic.connect(self.receiveProblematic)
            gloveDefectionGrid.sendFormerLamp.connect(self.sendFormerLamps)
        self.authenticated=False
        self.pPressures=[deque(maxlen=10) for _ in range(4)]

        self.plc=plcLib.PLC(CFG.PLC_IP,CFG.SENSOR_M,CFG.PERI_SENSOR_ADDR,CFG.PERI_SIGNAL_ADDR,CFG.AIVC_MODE)
        self.inferenceThread=Inference_Thread(self)
        self.captureThread= Capture_Thread(self, self.plc)
        self.dataThread=DataHandler_Thread(self)
        self.purgingThread= Purging_Thread(self, self.plc, self.dataThread.chainIndexers)
        self.dataThread.refreshStatus.connect(self.refreshStatus)
        self.dataThread.trigger15min.connect(self.captureThread.getAveLineSpeed)
        self.captureThread.sendAveLineSpeed.connect(self.dataThread.lineSpeedAlert)
        self.dataThread.updateCamBox.connect(self.setCamBoxWithID)
        self.dataThread.setListItem.connect(self.setListItem)
        self.dataThread.adjustCamDelay.connect(self.captureThread.adjustCamDelay)
        self.dataThread.feedPurgingStack.connect(self.purgingThread.feedPurgingStack)
        self.dataThread.feedPeripheralStack.connect(self.purgingThread.feedPeripheralStack)
        self.dataThread.updateRasmGridOfLine.connect(self.updateRasmGridOfLine)
        self.dataThread.chainGridAddArm.connect(self.chainGridAddArm)
        self.dataThread.contGoodBadCycle.connect(self.contGoodBadCycle)
        self.dataThread.updateTable.connect(self.updateTable)
        self.dataThread.refreshChainGrids.connect(self.refreshChainGrids)
        self.dataThread.updateStartTime.connect(self.updateStartTime)
        self.dataThread.rejectAsm.connect(self.purgingThread.rejectAsm)
        for oi in self.dataThread.operationInspectors:
            oi.setPlcBypass.connect(self.setPlcBypass)
        self.captureThread.setAveLineSpeedTxt.connect(self.setAveLineSpeedTxt)
        self.captureThread.setCurLineSpeedTxt.connect(self.setCurLineSpeedTxt)
        self.captureThread.resetPlc.connect(self.initializePLC)
        self.captureThread.noneCamera.connect(self.dataThread.noneCamera)
        self.captureThread.firstChainAnchorReached.connect(self.dataThread.firstChainAnchorReached)
        self.captureThread.setAnchorID.connect(self.purgingThread.setAnchorID)
        self.captureThread.cycleCount.connect(self.dataThread.cycleCount)

        self.captureThread.sendFormerNum.connect(self.dataThread.sendFormerNum)
        self.inferenceThread.feedYoloResult.connect(self.dataThread.feedYoloResult)
        self.inferenceThread.clearCamBox.connect(self.clearCamBox)
        for camThread in self.captureThread.camThreads:
            camThread.feedCaptureQue.connect(self.inferenceThread.feedCaptureQue)
        self.captureThread.feedPurgerQue.connect(self.purgingThread.feedPurgerQue)
        self.purgingThread.updatePurgingDisplay.connect(self.updatePurgingDisplay)
        self.purgingThread.updateListToPurge.connect(self.updateListToPurge)
        self.purgingThread.markDetected.connect(self.markDetected)
        self.purgingThread.markPurged.connect(self.markPurged)
        self.purgingThread.markMarkFormer.connect(self.markMarkFormer)
        self.purgingThread.markPeri.connect(self.markPeri)
        self.purgingThread.markPeriRejected.connect(self.markPeriRejected)
        self.purgingThread.markTestMark.connect(self.markTestMark)

        self.refreshDataTable.connect(self.dataThread.refreshDataTable)
        self.dataThread.start(priority=4)
        self.inferenceThread.start(priority=4)#HighPriority
        self.captureThread.start(priority=6)#TimeCriticalPriority
        self.purgingThread.start(priority=5)

        ## Login Window
        self.userDialog = UserDialog(self)
        self.userDialog.userLoggedIn.connect(self.loginUpdateUI)
        self.userDialog.userLoggedOut.connect(self.logoutUpdateUI)

        self.settingDialog = QDialog(self, flags=Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
        self.imgDialog=ImgDialog(self)
        self.tableDialog=TableDialog(self)
        self.plcDialog=PLCDialog(self,self.plc)
        self.dataHistoryDialog=DataHistoryDialog(self)
        self.modelLowConfident=ModelLowConfident(self)# syafii edit
        self.dataThread.lowConfData.connect(self.modelLowConfident.display)# syafii edit
        self.infoDialog=InfoDialog(self)
        for rcw in self.infoDialog.rejectCountWidgets:
            rcw.resetRejectCount.connect(self.resetRejectCount)
        self.setting_ui=Ui_SettingDialog()
        self.setting_ui.setupUi(self.settingDialog)
        self.purgerforms=[self.setting_ui.form_plc_0, self.setting_ui.form_plc_1, self.setting_ui.form_plc_2, self.setting_ui.form_plc_3 ]
        for idx, form in enumerate(self.purgerforms):
            form.setWidget(0,QFormLayout.FieldRole, LineEditLimInt(max=50, hint="num of former"))
            if CFG.FACTORY_NAME == "F06":
                form.setWidget(1,QFormLayout.FieldRole, LineEditLimInt(max=7,hint='100ms'))
            else:
                form.setWidget(1,QFormLayout.FieldRole, LineEditLimInt(max=4,hint='100ms'))
            form.setWidget(2,QFormLayout.FieldRole, LineEditLimInt(max=5,hint='100ms'))
            form.setWidget(3,QFormLayout.FieldRole, LineEditLimInt(max=10,hint='100ms'))
            enableRASMPurgeCB=IndexedCheckBox(idx,"Enable RASM")
            enableRASMPurgeCB.setChecked(CFG.ENABLE_PURGE_RASM[idx])
            enableRASMPurgeCB.stateChanged.connect(self.setPurgeEnableRASM)
            form.setWidget(5,QFormLayout.LabelRole, enableRASMPurgeCB)
            enableFKTHPurgeCB=IndexedCheckBox(idx,"Enable FKTH")
            enableFKTHPurgeCB.setChecked(CFG.ENABLE_PURGE_FKTH[idx])
            enableFKTHPurgeCB.stateChanged.connect(self.setPurgeEnableFKTH)
            form.setWidget(5,QFormLayout.FieldRole, enableFKTHPurgeCB)
            enablePeriCB=IndexedCheckBox(idx,"Enable PERI")
            enablePeriCB.setChecked(CFG.ENABLE_PERIPHERAL[idx])
            enablePeriCB.stateChanged.connect(self.setPeriEnable)
            form.setWidget(4,QFormLayout.LabelRole, enablePeriCB)
            testPurgeButton=IndexedButton(idx,"Test")
            testPurgeButton.clicked.connect(self.purgingThread.testPurge)
            form.setWidget(4,QFormLayout.FieldRole, testPurgeButton)
        availableSensorStr="Purger: "
        for i in range(CFG.SENSOR_NUM):
            availableSensorStr+=f' M{CFG.SENSOR_M+i}'
        self.setting_ui.grid_sensor.addWidget(QLabel(availableSensorStr),0,0,1,8)
        for i in range(4):
            sideLab=QLabel(SIDE_SHORT[i])
            sideLab.setMaximumWidth(25)
            sideLab.setAlignment(Qt.AlignRight)
            self.setting_ui.grid_sensor.addWidget(sideLab,1,i*2,1,1)
            spinBox=IndexedSpinBox(i,_min=CFG.SENSOR_M,_max=CFG.SENSOR_M+CFG.SENSOR_NUM-1, parent=self)
            spinBox.setValue(CFG.PURGER_SENSOR[i]+CFG.SENSOR_M)
            spinBox.setFixedWidth(45)
            spinBox.valueChanged.connect(self.setPurgerSensor)
            self.setting_ui.grid_sensor.addWidget(spinBox,1,i*2+1,1,1)
        self.text_factory=QLineEdit()
        self.text_factory.setPlaceholderText('e.g. F39')
        self.text_factory.returnPressed.connect(self.changeFactorynLineName)
        self.text_line=LineEditLimInt(max=50, hint="line number")
        self.text_line.returnPressed.connect(self.changeFactorynLineName)
        self.text_plcIP=QLineEdit()
        self.text_plcIP.setPlaceholderText('e.g. 10.39.0.2')
        self.text_plcIP.returnPressed.connect(self.changePLCIP)
        self.text_rasmNum=LineEditLimInt(max=50, hint="Total number of RASM arm set")
        self.text_rasmNum.returnPressed.connect(self.changeRasmLen)
        self.text_teamsAddr=QLineEdit()
        self.text_teamsAddr.setPlaceholderText("Teams > Connector > Incoming Webhook")
        self.text_teamsAddr.returnPressed.connect(self.setTeamsAddr)
        self.setting_ui.form_general.setWidget(0,QFormLayout.FieldRole, self.text_factory)
        self.setting_ui.form_general.setWidget(1,QFormLayout.FieldRole, self.text_line)
        self.setting_ui.form_general.setWidget(2,QFormLayout.FieldRole, self.text_plcIP)
        self.setting_ui.form_general.setWidget(3,QFormLayout.FieldRole, self.text_rasmNum)
        self.setting_ui.form_general.setWidget(4,QFormLayout.FieldRole, self.text_teamsAddr)
        #Low: 1st Bin ; High: 2nd Bin
        lab1=QLabel("Purger Rework:")
        lab1.setMaximumHeight(13)
        self.setting_ui.grid_classToPurge.addWidget(lab1,0,0,1,4)
        self.checkBoxToRework=[]
        for i in range(CLASS_NUM-1):
            checkBox=IndexedCheckBox(i+1,CLASSES[i+1])
            if(CFG.CLASS_TO_REWORK & 1<<i+1):
                checkBox.setChecked(True)
            checkBox.stateChanged.connect(self.setClassToRework)
            self.setting_ui.grid_classToPurge.addWidget(checkBox,i/4+1,i%4)
            self.checkBoxToRework.append(checkBox)

        lab2=QLabel("Purger Dispose:")
        lab2.setMaximumHeight(13)
        self.setting_ui.grid_classToPurge.addWidget(lab2,4,0,1,4)
        self.checkBoxToDispose=[]
        for i in range(CLASS_NUM-1):
            checkBox=IndexedCheckBox(i+1,CLASSES[i+1])
            if(CFG.CLASS_TO_DISPOSE & 1<<i+1 ):
                checkBox.setChecked(True)
            checkBox.stateChanged.connect(self.setClassToDispose)
            self.setting_ui.grid_classToPurge.addWidget(checkBox,i/4+5,i%4)
            self.checkBoxToDispose.append(checkBox)
        self.setting_ui.grid_classToPurge.addWidget(QLabel("Confidence Level To Purge:"),8,0,1,2)
        text_confLevel=LineEditLimInt(max=100, hint="0%~100%")
        text_confLevel.setText(str(int(CFG.CONF_LEVEL_TO_PURGE*100)))
        text_confLevel.returnPressed.connect(self.setConfLevel)
        self.setting_ui.grid_classToPurge.addWidget(text_confLevel,8,2,1,2)

        self.setting_ui.grid_classToPurge.addWidget(QLabel("Sorting Flap Duration:"),9,0,1,2)
        text_SFduration=LineEditLimInt(max=50, hint="Dispose Bin Open Duration(100ms)")
        text_SFduration.setText(str(CFG.FLIP_DURATION))
        text_SFduration.returnPressed.connect(self.setSFduration)
        self.setting_ui.grid_classToPurge.addWidget(text_SFduration,9,2,1,2)

        self.setting_ui.grid_classToPurge.addWidget(QLabel("Sorting Flap Delay:"),10,0,1,2)
        text_SFdelay=LineEditLimInt(max=50, hint="Turning Early Delay(100ms)")
        text_SFdelay.setText(str(CFG.FLIP_DELAY))
        text_SFdelay.returnPressed.connect(self.setSFdelay)
        self.setting_ui.grid_classToPurge.addWidget(text_SFdelay,10,2,1,2)

        self.setting_ui.grid_classToPurge.addWidget(QLabel("Purger Pressure Threshold (Bar*100):"),11,0,1,2)
        text_pressureThres=LineEditLimInt(max=1000, hint="e.g. 3.1bar=>310 | Put 0 If Not Installed")
        text_pressureThres.setText(str(CFG.PURGER_PRESSURE_ALERT_THRESHOLD))
        text_pressureThres.returnPressed.connect(self.setPressureThres)
        self.setting_ui.grid_classToPurge.addWidget(text_pressureThres,11,2,1,2)

        self.cb_autoRestart=QCheckBox('Enable AIVC Auto Restart')
        self.cb_autoRestart.setChecked(CFG.ENABLE_AUTO_RESTART)
        self.cb_autoRestart.stateChanged.connect(lambda:self.setEnableAutoRestart(self.cb_autoRestart.isChecked()))
        self.setting_ui.grid_classToPurge.addWidget(self.cb_autoRestart,12,0,1,2)

        if SMALL_SCREEN:
            self.ui.table_defect_data.setMaximumHeight(170)
        if NARROW_SCREEN:
            font = QFont('Arial',12)
            font.setBold(True)
            self.ui.label_title.setFont(font)
        self.ui.table_defect_data.doubleClicked.connect(self.showTable)

        #Peripheral Setting Tab
        self.periWidgets=[]
        for i in range(4):
            periWidget=PeripheralWidget(CFG.PERI_NAME[i], CFG.PERI_SIGNAL_ADDR+i*10, i, parent=self)
            for j, cb in enumerate(periWidget.checkBoxes):
                if(CFG.PERI_CLASS[i] & 1<<j+1):
                    cb.setChecked(True)
                cb.stateChanged.connect(self.setClassPeri)
            for j, td in enumerate(periWidget.text_distances):
                td.setText(str(CFG.PERI_DISTANCE[i][j]))
                td.returnPressed.connect(self.setPeriDistance)
            self.periWidgets.append(periWidget)
            self.setting_ui.periVLayout.addWidget(periWidget)
        
        #Former Setting Tab
        self.setting_ui.formerMarkingCheckBox.setChecked(CFG.ENABLE_FORMER_MARKING)
        self.setting_ui.formerMarkingCheckBox.setText(f"Enable Former Marking Signal (M{950+CFG.AIVC_MODE*10})")
        self.setting_ui.formerMarkingCheckBox.stateChanged.connect(lambda:self.enableFormerMarking(self.setting_ui.formerMarkingCheckBox.isChecked()))
        formerMarkingWidget=FormerMarkingWidget()
        self.setting_ui.formerVLayout.addWidget(formerMarkingWidget)
        self.setting_ui.formerVLayout.addItem(QSpacerItem(5,5, QSizePolicy.Preferred, QSizePolicy.MinimumExpanding))
        for i, td in enumerate(formerMarkingWidget.text_distances):
            td.setText(str(CFG.FORMER_MARKING_DISTANCE[i]))
            td.returnPressed.connect(self.setFormerMarkingDistance)
        for tb in formerMarkingWidget.testButtons:
            tb.clicked.connect(self.purgingThread.testMark)
        for i, to in enumerate(formerMarkingWidget.text_offsets):
            to.setText(str(CFG.CHAIN_ANCHOR_OFFSET[i]))
            to.returnPressed.connect(self.setChainAnchorOffset)
        self.setting_ui.camDelayCheckBox.stateChanged.connect(lambda:self.showCamDelaySpinBox(self.setting_ui.camDelayCheckBox.isChecked()))
        self.setting_ui.camSeqCheckBox.stateChanged.connect(lambda:self.showCamSeqSpinBox(self.setting_ui.camSeqCheckBox.isChecked()))
        self.setting_ui.formerIntCheckBox.stateChanged.connect(lambda:self.showFormerSpinBox(self.setting_ui.formerIntCheckBox.isChecked()))
        self.setting_ui.sensorCheckBox.stateChanged.connect(lambda:self.showSensorSpinBox(self.setting_ui.sensorCheckBox.isChecked()))
        self.setting_ui.rasmOffsetCheckBox.stateChanged.connect(lambda:self.showRasmOffsetCheckBox(self.setting_ui.rasmOffsetCheckBox.isChecked()))
        self.setting_ui.buttonBox.button(QDialogButtonBox.Apply).clicked.connect(self.applyPurgerSetting)
        self.setting_ui.buttonBox.accepted.connect(self.acceptedPurgerSetting)
        self.setting_ui.buttonBox.rejected.connect(self.hidePurgerSetting)
        self.ui.listWidget.setAlternatingRowColors(True)
        self.ui.listWidget.currentItemChanged.connect(self.setView)
        self.ui.listWidget.itemDoubleClicked.connect(self.showImg)

        self.ui.btn_start.clicked.connect(self.dataThread.startCapture)
        self.ui.btn_start.clicked.connect(self.changeButtonText)

        self.ui.btn_label.clicked.connect(self.openLabelWindow)
        self.ui.btn_setting.clicked.connect(self.openSettingWindow)
        if CFG.LOCK_SETTING:
            self.ui.btn_setting.setEnabled(False)
            self.ui.btn_setting.setToolTip("Require User AuthorityLvl 8")
        self.ui.btn_login.clicked.connect(self.openUserDialog)
        self.ui.btn_login.clicked.connect(self.printOccu)
        self.ui.btn_history.clicked.connect(self.showDataHistory)
        #self.ui.btn_login.clicked.connect(self.changeAIVCMode)#H#
        self.ui.btn_plc.clicked.connect(self.showPLC)
        self.ui.btn_model.clicked.connect(self.showModelLowConfident)# syafii edit
        self.ui.btn_info.clicked.connect(self.showInfo)
        self.ui.btn_exit.clicked.connect(self.close)

        for idx,cam in enumerate(self.captureThread.camThreads):
            self.camBoxes[Cam_Seq[idx]].setToolTip(cam.camDetails)
        for camBox in self.camBoxes:
            camBox.camDelaySpinBox.spinBox.valueChanged.connect(self.setCamDelay)
            camBox.camSeqSpinBox.leftButton.clicked.connect(self.moveCamToLeft)
            camBox.camSeqSpinBox.rightButton.clicked.connect(self.moveCamToRight)
            camBox.formerSpinBox.spinBox.valueChanged.connect(self.setFormerInterval)
            camBox.sensorSpinBox.spinBox.valueChanged.connect(self.setCamSensor)

        for rasmDefectionGrid in self.rasmDefectionGrids:
            rasmDefectionGrid.rasmOffsetEdit.lineEdit.textChanged.connect(self.setRasmOffset)
        self.destroyed.connect(lambda: print("Main Window Destroyed"))
        self.startTime=time.strftime("%Y-%m-%d_%H:%M:%S")
        self.recordStartTime=time.strftime("%m/%d %H:%M:%S")
        self.ui.label_startTime.setText(self.recordStartTime)
        self.create_timer()
        self.initializePLC() 
        self.tabs_stacking=[CameraTab() for _ in range(4)]
        self.tab_camera= CameraTab()
        self.loadAIVCMode()
    
    def setPlcBypass(self,side,bypass):
        self.plc.setBypass(side,bypass)
            
    def updatePurgingDisplay(self,side,content):
        item=QListWidgetItem(content,self.infoDialog.purgingDisplays[side])
        if self.infoDialog.purgingDisplays[side].count()>20:
            self.infoDialog.purgingDisplays[side].takeItem(0)
            self.infoDialog.purgingDisplays[side].scrollToBottom()

    def updateListToPurge(self,side,formerID, content):
        item=QListWidgetItem(f'{formerID} {content}',self.infoDialog.listToPurge[side])
        if self.infoDialog.listToPurge[side].count()>5:
            self.infoDialog.listToPurge[side].takeItem(0)
            self.infoDialog.listToPurge[side].scrollToBottom()

    def markDetected(self,side,detectedID,purgeID):
        item=QListWidgetItem(f'On {detectedID:03d} Detected {purgeID:03d}',self.infoDialog.purgingDisplays[side])
        item.setBackground( QColor('Yellow'))
        if self.infoDialog.purgingDisplays[side].count()>20:
            self.infoDialog.purgingDisplays[side].takeItem(0)
            self.infoDialog.purgingDisplays[side].scrollToBottom()

        # matchedItems=self.infoDialog.purgingDisplays[side].findItems(f'{formerID:03d}',Qt.MatchContains)
        # for item in matchedItems:
        #     item.setBackground( QColor('Blue'))
        #     item.setText(item.text()+'  Detected')

    def markPurged(self,side,formerID):
        item=QListWidgetItem(f'Purged {formerID:03d}',self.infoDialog.purgingDisplays[side])
        item.setBackground( QColor('Red'))
        if self.infoDialog.purgingDisplays[side].count()>20:
            self.infoDialog.purgingDisplays[side].takeItem(0)
            self.infoDialog.purgingDisplays[side].scrollToBottom()

    def markPeri(self,side,formerID,periIdx):
        item=QListWidgetItem(f'{CFG.PERI_NAME[periIdx]} Marked {formerID:03d}',self.infoDialog.purgingDisplays[side])
        item.setBackground( QColor('Green'))
        if self.infoDialog.purgingDisplays[side].count()>20:
            self.infoDialog.purgingDisplays[side].takeItem(0)
            self.infoDialog.purgingDisplays[side].scrollToBottom()

    def markPeriRejected(self,side,formerID,periIdx):
        item=QListWidgetItem(f'{CFG.PERI_NAME[periIdx]} Rejected {formerID:03d}',self.infoDialog.purgingDisplays[side])
        item.setBackground( QColor('Orange'))
        if self.infoDialog.purgingDisplays[side].count()>20:
            self.infoDialog.purgingDisplays[side].takeItem(0)
            self.infoDialog.purgingDisplays[side].scrollToBottom()

    def markTestMark(self,side,formerID):
        item=QListWidgetItem(f'Test Mark {formerID:03d}',self.infoDialog.purgingDisplays[side])
        item.setBackground( QColor('Yellow'))
        if self.infoDialog.purgingDisplays[side].count()>20:
            self.infoDialog.purgingDisplays[side].takeItem(0)
            self.infoDialog.purgingDisplays[side].scrollToBottom()

    def markMarkFormer(self,side,formerID):
        item=QListWidgetItem(f'Mark Former {formerID:03d}',self.infoDialog.purgingDisplays[side])
        item.setBackground( QColor('Magenta'))
        if self.infoDialog.purgingDisplays[side].count()>20:
            self.infoDialog.purgingDisplays[side].takeItem(0)
            self.infoDialog.purgingDisplays[side].scrollToBottom()

    def showDataHistory(self):
        self.dataHistoryDialog.show()

    def showModelLowConfident(self):# syafii edit
        self.modelLowConfident.show()

    def showPLC(self):
        self.plcDialog.show()

    def showInfo(self):
        self.infoDialog.show()

    def changeAIVCMode(self):
        CFG.AIVC_MODE+=1
        if CFG.AIVC_MODE>2:
            CFG.AIVC_MODE=0
        CFG_Handler.set('AIVC_MODE',CFG.AIVC_MODE)
        self.loadAIVCMode()

    def loadAIVCMode(self):
        global Cam_Seq,Former_Interval,Cam_Delay,Cam_Sensor
        Cam_Seq=CFG.CAM_SEQ_ALL[CFG.AIVC_MODE]
        Former_Interval=CFG.FORMER_INTERVAL_ALL[CFG.AIVC_MODE]
        Cam_Delay=CFG.CAM_DELAY_ALL[CFG.AIVC_MODE]
        Cam_Sensor=CFG.CAM_SENSOR_ALL[CFG.AIVC_MODE]
        for i in range(len(Cam_Seq)):
            self.camBoxes[i].update()
        if CFG.AIVC_MODE==2:#ASM
            #Remove AIVC tab
            for i in range(self.ui.tab_main.count()):
                self.ui.tab_main.removeTab(0)
            #Load ASM tab
            for side, tab in enumerate(self.tabs_stacking):
                self.ui.tab_main.addTab(tab,SIDE_NAME[side])
                for i in range(CFG.ASM_LENGTH):
                    tab.grid.addWidget(self.camBoxes[side*CFG.ASM_LENGTH + i], i/2,i%2, 1, 1)
            self.ui.tab_main.addTab(self.ui.tab_chain_data,'Data')
            self.ui.label_title.setText(f'Stacking AIVC System  {CFG.FACTORY_NAME} LINE {CFG.LINE_NUM}')
            for pf in self.purgerforms:
                for i in range(0,4):
                    pf.itemAt(i,QFormLayout.FieldRole).widget().hide()
                    pf.itemAt(i,QFormLayout.LabelRole).widget().hide()
                pf.itemAt(4,QFormLayout.FieldRole).widget().hide()
                pf.itemAt(5,QFormLayout.FieldRole).widget().hide()
                pf.itemAt(5,QFormLayout.LabelRole).widget().hide()

        elif CFG.AIVC_MODE==0:#AIVC RASM&FKTH
            for i in range(self.ui.tab_main.count()):
                self.ui.tab_main.removeTab(0)
            self.ui.tab_main.addTab(self.ui.tab_fingertip,'FKTH')
            self.ui.tab_main.addTab(self.ui.tab_rasm,'RASM')
            self.ui.tab_main.setCurrentIndex(1)
            for i in range(8):
                self.ui.grid_fingertip_cam.addWidget(self.camBoxes[i], i/2, i%2, 1, 1)

            for i in range(4):
                self.ui.grid_rasm_cam.addWidget(self.camBoxes[i+8], i/2,i%2, 1, 1)
            self.ui.label_title.setText(f'Integrated AIVC System  {CFG.FACTORY_NAME} LINE {CFG.LINE_NUM}')
            #self.ui.label_title.setText(f'AIVC System DEVELOPER MODE DO NOT CLOSED')
            for pf in self.purgerforms:
                for i in range(1,4):
                    pf.itemAt(i,QFormLayout.FieldRole).widget().show()
                    pf.itemAt(i,QFormLayout.LabelRole).widget().show()
                pf.itemAt(5,QFormLayout.FieldRole).widget().show()
                pf.itemAt(5,QFormLayout.LabelRole).widget().show()
            
        elif CFG.AIVC_MODE==1:#TAC
            for i in range(self.ui.tab_main.count()):
                self.ui.tab_main.removeTab(0)
            self.ui.tab_main.addTab(self.tab_camera,'Camera')
            self.ui.tab_main.addTab(self.ui.tab_chain_data,'Data')
            for i in range(4):
                self.tab_camera.grid.addWidget(self.camBoxes[i], i/2,i%2, 1, 1)
            self.ui.label_title.setText(f'TAC AIVC System  {CFG.FACTORY_NAME} LINE {CFG.LINE_NUM}')
            for pf in self.purgerforms:
                for i in range(1,4):
                    pf.itemAt(i,QFormLayout.FieldRole).widget().hide()
                    pf.itemAt(i,QFormLayout.LabelRole).widget().hide()
                pf.itemAt(5,QFormLayout.FieldRole).widget().hide()
                pf.itemAt(5,QFormLayout.LabelRole).widget().hide()

    def setEnableAutoRestart(self,enable):
        CFG_Handler.set('ENABLE_AUTO_RESTART',enable)
    def refreshStatus(self):
        if "AIVC_Monitor.exe" in (p.name() for p in psutil.process_iter()):
            pass
        else:
            print('Opening AIVC Monitor.')
            try:
                os.startfile("aivcMonitor\\AIVC_Monitor.exe")
            except FileNotFoundError:
                logger.error("aivcMonitor\\AIVC_Monitor.exe missing, can't enable AIVC Auto Restart")
                CFG_Handler.set('ENABLE_AUTO_RESTART',False)
                self.cb_autoRestart.setChecked(False)
                return
            print('AIVC Monitor Started!!')

    def initializePLC(self):
        if CFG.AIVC_MODE==0:
            for i in range(4):
                self.purgingThread.purgerDistance[i] = CFG.PURGER_SETTING[i][0]
                self.plc.setPurgeDelay_100ms(i,CFG.PURGER_SETTING[i][1])
                self.plc.setPurgeInterval_100ms(i,CFG.PURGER_SETTING[i][2])
                self.plc.setPurgeDuration_100ms(i,CFG.PURGER_SETTING[i][3])
            self.plc.setFlipDelay_100ms(CFG.FLIP_DELAY)
            self.plc.setFlipDuration_100ms(CFG.FLIP_DURATION)
        for addrTxt, name, val in CFG.PLC_CONFIG:
            addr=int(addrTxt[1:])
            if type(val)==bool:
                self.plc.writeCoil(addr,val)
            else:
                self.plc.writeRegister(addr,val)


    def resumePreviousTeamsAddr(self):
        self.text_teamsAddr.setText(CFG.TEAMS_ADDR)

    def focusInEvent(self, event):
        self.showFullScreen()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.showMinimized()

    def setPeriDistance(self):
        idx=self.sender().parent().idx
        seq=self.sender().idx
        distance=self.sender().val
        CFG.PERI_DISTANCE[idx][seq]=distance
        CFG_Handler.set('PERI_DISTANCE',CFG.PERI_DISTANCE)
        
    def setFormerMarkingDistance(self):
        seq=self.sender().idx
        distance=self.sender().val
        CFG.FORMER_MARKING_DISTANCE[seq]=distance
        CFG_Handler.set('FORMER_MARKING_DISTANCE',CFG.FORMER_MARKING_DISTANCE)

    def setChainAnchorOffset(self):
        seq=self.sender().idx
        offset=self.sender().val
        CFG.CHAIN_ANCHOR_OFFSET[seq]=offset
        CFG_Handler.set('CHAIN_ANCHOR_OFFSET',CFG.CHAIN_ANCHOR_OFFSET)

    def printOccu(self):
        print(self.dataThread.occu)
        print(self.inferenceThread.occu)
        try:
            print(self.captureThread.camThreads[0].occu)
        except IndexError:
            print("None Camera Connected")

    def armClicked(self,matchStr):
        print(matchStr)#print defect former id
        matchedItems=self.ui.listWidget.findItems(matchStr,Qt.MatchContains)# 1 for MatchContains
        if matchedItems:
            self.imgDialog.setTraceList(matchedItems)
            self.imgDialog.traceList.setCurrentRow(0)
            self.imgDialog.show()
    def showTable(self):
        self.tableDialog.load()
        self.tableDialog.show()

    def showImg(self, item):
        imgPath=item.data(32)
        matchStr=item.text()[-13:-9]
        matchedItems=self.ui.listWidget.findItems(matchStr,Qt.MatchContains)# 1 for MatchContains

        self.imgDialog.setTraceList(matchedItems,text=item.text())
        self.imgDialog.view.setPhoto(QPixmap(imgPath))
        # if CFG.ROTATE:
        #     self.imgDialog.view.setPhoto(QPixmap(imgPath).scaled(720,960))
        # else:
        #     self.imgDialog.view.setPhoto(QPixmap(imgPath).scaled(960,720))
        self.imgDialog.show()

    def setAveLineSpeedTxt(self, text):
        self.ui.text_aveLineSpeed.setText(text)

    def setCurLineSpeedTxt(self, text):
        self.ui.text_curLineSpeed.setText(text)

    def setTeamsAddr(self):
        addr=self.text_teamsAddr.text().rstrip()
        if addr == CFG.TEAMS_ADDR:
            return
        self.dataThread.teamsMessenger.emit("ChangeTeamsAddr"+addr)

    def changeRasmLen(self):
        length=self.sender().val
        if length != CFG.RASM_ARM_NUM:
            for rasmRecord in self.dataThread.rasmRecords:
                rasmRecord.changeLength(length)
            CFG_Handler.set('RASM_ARM_NUM',length)
            for rasmDefectionGrid in self.rasmDefectionGrids:
                rasmDefectionGrid.clear()
            self.dataThread.rasmRecordsStart=emptyRecords()
            self.dataThread.rasmRecordsDay=emptyRecords()
            self.dataThread.rasmRecordsHour=emptyRecords()
            self.dataThread.rasmRecords15m=emptyRecords()
            self.dataThread.rasmRecordsMin=emptyRecords()
            #Reassign prevRasmRecords
            idx=self.ui.select_duration.currentIndex()
            if idx==0:
                self.dataThread.prevRasmRecords=self.dataThread.rasmRecordsStart
            elif idx==1:
                self.dataThread.prevRasmRecords=self.dataThread.rasmRecordsDay
            elif idx==2:
                self.dataThread.prevRasmRecords=self.dataThread.rasmRecordsHour
            elif idx==3:
                self.dataThread.prevRasmRecords=self.dataThread.rasmRecords15m
            else :
                self.dataThread.prevRasmRecords=self.dataThread.rasmRecordsMin
            print(self.dataThread.prevRasmRecords)

    def updateStartTime(self, timeStr):
        self.ui.label_startTime.setText(timeStr)

    def changeRecordDuration(self):
        idx=self.sender().currentIndex()
        if idx==0:
            self.dataThread.prevData=self.dataThread.dataStart
            self.dataThread.prevRasmRecords=self.dataThread.rasmRecordsStart
            self.ui.label_startTime.setText(self.recordStartTime)
        elif idx==1:
            self.dataThread.prevData=self.dataThread.dataDay
            self.dataThread.prevRasmRecords=self.dataThread.rasmRecordsDay
            self.ui.label_startTime.setText(time.strftime("%m/%d 00:00:00"))
        elif idx==2:
            self.dataThread.prevData=self.dataThread.dataHour
            self.dataThread.prevRasmRecords=self.dataThread.rasmRecordsHour
            self.ui.label_startTime.setText(time.strftime("%m/%d %H:00:00"))
        elif idx==3:
            self.dataThread.prevData=self.dataThread.data15m
            self.dataThread.prevRasmRecords=self.dataThread.rasmRecords15m
            min15=int(((time.time()//60)%60)//15)*15
            t=f'{time.strftime("%m/%d %H")}:{min15:02d}:00'
            self.ui.label_startTime.setText(t)
        else :
            self.dataThread.prevData=self.dataThread.dataMin
            self.dataThread.prevRasmRecords=self.dataThread.rasmRecordsMin
            self.ui.label_startTime.setText(time.strftime("%m/%d %H:%M:00"))
        self.refreshDataTable.emit()
        self.dataThread.dataRecordState=idx

    def setConfLevel(self):
            CFG_Handler.set('CONF_LEVEL_TO_PURGE',self.sender().val/100.0)

    def setSFduration(self):
        CFG_Handler.set('FLIP_DURATION',self.sender().val)
        self.plc.setFlipDuration_100ms(CFG.FLIP_DURATION)

    def setSFdelay(self):
        CFG_Handler.set('FLIP_DELAY',self.sender().val)
        self.plc.setFlipDelay_100ms(CFG.FLIP_DELAY)

    def setPressureThres(self):
        CFG_Handler.set('PURGER_PRESSURE_ALERT_THRESHOLD',self.sender().val)

    def setClassToDispose(self):
        val=self.sender().isChecked()
        seq=self.sender().seq
        mask = 1<<seq
        if val:
            CFG.CLASS_TO_DISPOSE |= mask
            self.checkBoxToRework[seq-1].setChecked(False)
        else:
            CFG.CLASS_TO_DISPOSE &= ~mask
        CFG_Handler.set('CLASS_TO_DISPOSE', CFG.CLASS_TO_DISPOSE)

    def setClassToRework(self):
        val=self.sender().isChecked()
        seq=self.sender().seq
        mask = 1<<seq
        if val:
            CFG.CLASS_TO_REWORK |= mask
            self.checkBoxToDispose[seq-1].setChecked(False)
        else:
            CFG.CLASS_TO_REWORK &= ~mask
        CFG_Handler.set('CLASS_TO_REWORK', CFG.CLASS_TO_REWORK)

    def setClassPeri(self):
        idx=self.sender().parent().idx
        val=self.sender().isChecked()
        seq=self.sender().seq
        mask = 1<<seq
        if val:
            CFG.PERI_CLASS[idx] |= mask
        else:
            CFG.PERI_CLASS[idx] &= ~mask
        CFG_Handler.set('PERI_CLASS', CFG.PERI_CLASS)

    def changeFactorynLineName(self):
        # if self.text_factory.text() in FACTORY_LIST:
        #     CFG.FACTORY_NAME=self.text_factory.text()
        # else:
        #     print(f"{self.text_factory.text()} is not a valid factory name")
        #     self.text_factory.setText([CFG.FACTORY_NAME])
        CFG_Handler.set('FACTORY_NAME',self.text_factory.text()) 
        CFG_Handler.set('LINE_NUM',self.text_line.val) 
        self.ui.label_title.setText(f'Integrated AIVC System  {CFG.FACTORY_NAME} LINE {CFG.LINE_NUM}')
        #self.ui.label_title.setText(f'AIVC System DEVELOPER MODE DO NOT CLOSED')

    def changePLCIP(self):
        ip=self.text_plcIP.text()
        try:
            ipaddress.ip_address(ip)
            CFG_Handler.set('PLC_IP',ip)
            print(f"valid{CFG.PLC_IP}")
            self.plc.connectIP(CFG.PLC_IP)
            # tracelog
            logger.info(f"PLC ADDRESS CHANGED {CFG.PLC_IP}")
        except ValueError:
            print(f"Invalid IPv4Address {CFG.PLC_IP}")
            self.text_plcIP.setText(CFG.PLC_IP)

    def create_timer(self):
        self.secTimer=MyTimer(self,1)
        self.secTimer.timeOut.connect(self.update_time)
        self.secTimer.timeOut.connect(self.secTimerCheck)
        self.minTimer=MyTimer(self,60)#60sec Timer
        self.minTimer.timeOut.connect(self.recordDataMin)
        self.minTimer.timeOut.connect(self.minTimerCheck)
        self.randomTimer=QTimer(self)
        self.randomTimer.timeout.connect(self.dataThread.jsonRPCThread.report)
        self.randomTimer.timeout.connect(self.checkUpdateRestart)   
        self.randomTimer.start(60000)

    def recordDataMin(self):
        self.dataThread.minuteDataRecorder.que.put(True)

    def update_time(self):
        self.ui.label_clock.setText(time.strftime("%d/%m/%Y    %H:%M:%S"))

    def secTimerCheck(self):
        self.checkPlc()
        pressures=self.plc.readAirPressures()
        if pressures == -1:
            for i in range(4):
                self.infoDialog.sideLabels[i].setText(f'{SIDE_SHORT[i]} No Connection')
                return
        else:
            for i in range(4):
                if pressures[i]==0:
                    self.infoDialog.sideLabels[i].setText(f'{SIDE_SHORT[i]} Not Installed')
                    continue
                self.infoDialog.sideLabels[i].setText(f'{SIDE_SHORT[i]}   {pressures[i]/100} bar')
                self.pPressures[i].append(pressures[i])
        countings=self.plc.readRejectCount()
        if countings==-1:
            return
        for i in range(4):
            self.infoDialog.rejectCountWidgets[i].reworkCountLbl.setText(f"Rework:{countings[i*2]}")
            self.infoDialog.rejectCountWidgets[i].disposeCountLbl.setText(f"Dispose:{countings[i*2+1]}")
    def resetRejectCount(self,side):
        self.plc.resetRejectCount(side)
    def minTimerCheck(self):
        #Check Pressure Alert
        for i in range(4):
            try:
                avePressure=sum(self.pPressures[i])/len(self.pPressures[i])
            except ZeroDivisionError:
                return
            if avePressure<CFG.PURGER_PRESSURE_ALERT_THRESHOLD:
                msg=f"Warning! {SIDE_NAME[i]} Purger Ave Pressure Low: {avePressure} (Threshold:{CFG.PURGER_PRESSURE_ALERT_THRESHOLD} Bar*100)"
                logger.warning(msg)
                self.dataThread.teamsMessenger.emit(msg)
    def checkPlc(self):
        if self.plc.checkPlcReset(CFG.AIVC_MODE):
            print("INIT PLC")
            self.captureThread.ready=False
            self.purgingThread.clearStack()
            self.initializePLC() 
    def setRasmOffset(self):
        seq=self.sender().parent().seq
        try:
            val=int(self.sender().text())
        except ValueError:
            val=0
        self.dataThread.rasmRecords[seq].offset=val
        CFG.RASM_ANCHOR_OFFSET[seq]=val
        CFG_Handler.set('RASM_ANCHOR_OFFSET',CFG.RASM_ANCHOR_OFFSET)

    def refreshChainGrids(self, chainDefectionRecords,clear):
        for index, gloveGrid in enumerate(self.gloveDefectionGrids):
            gloveGrid.updateAllChain(chainDefectionRecords[index],clear)

    def updateTable(self, row, line, val):
        self.ui.table_defect_data.item(row,line).setText(val)

    def receiveProblematic(self,dictDataDefect):
        self.dataThread.appendProblematic(dictDataDefect)
    
    def sendFormerLamps(self,ID,side,rdr):
        self.purgingThread.sendFormerLamps(ID,side,rdr)

    def updateRasmGridOfLine(self, line, index, armRecord, label):
        self.rasmDefectionGrids[line].updateRasmGrid(index, armRecord, label)
    def chainGridAddArm(self, line, index, record, label):
        self.gloveDefectionGrids[line].addChainArm(index, line, record, label)
    def contGoodBadCycle(self, line, former, cycle, contBad, contGood, emptyLink):
        self.gloveDefectionGrids[line].addContGoodBadCycle(line, former, cycle, contBad, contGood, emptyLink)

    def moveCamToRight(self):
        seq=self.sender().parent().seq
        if seq==len(Cam_Seq)-1:
            nextSeq=0
        else:
            nextSeq=seq+1
        currentIdx=Cam_Seq.index(seq)
        nextIdx=Cam_Seq.index(nextSeq)
        Cam_Seq[nextIdx]=seq
        Cam_Seq[currentIdx]=nextSeq
        self.sender().parent().lineEdit.setText(str(nextIdx))
        self.camBoxes[nextSeq].camSeqSpinBox.lineEdit.setText(str(currentIdx))
        self.camBoxes[seq].camView.setToolTip(self.captureThread.camThreads[nextIdx].camDetails)
        self.camBoxes[nextSeq].camView.setToolTip(self.captureThread.camThreads[currentIdx].camDetails)
        self.inferenceThread.captureQue.put([seq, None, None, None, None]) #Clear CamBox
        CFG_Handler.set('CAM_SEQ_ALL',CFG.CAM_SEQ_ALL)

    def moveCamToLeft(self):
        seq=self.sender().parent().seq
        if seq==0:
            prevSeq=len(Cam_Seq)-1
        else:
            prevSeq=seq-1
        currentIdx=Cam_Seq.index(seq)
        prevIdx=Cam_Seq.index(prevSeq)
        Cam_Seq[prevIdx]=seq
        Cam_Seq[currentIdx]=prevSeq
        self.sender().parent().lineEdit.setText(str(prevIdx))
        self.camBoxes[prevSeq].camSeqSpinBox.lineEdit.setText(str(currentIdx))
        self.camBoxes[seq].camView.setToolTip(self.captureThread.camThreads[prevIdx].camDetails)
        self.camBoxes[prevSeq].camView.setToolTip(self.captureThread.camThreads[currentIdx].camDetails)
        self.inferenceThread.captureQue.put([seq, None, None, None, None]) #Clear CamBox
        CFG_Handler.set('CAM_SEQ_ALL',CFG.CAM_SEQ_ALL)

    def saveRecord(self):
        data=self.dataThread.data[4].tolist()
        data_to_log = [self.startTime, time.strftime("%Y-%m-%d_%H:%M:%S"), CFG.FACTORY_NAME, CFG.LINE_NUM]
        data_to_log.extend(data)

        ## Log data
        if not os.path.exists('logs/'):
            os.mkdir('logs/')
        if not os.path.exists('logs/AIVCdata.csv'):
            with open('logs/AIVCdata.csv', mode='a', newline='') as file:
                writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                writer.writerow(["Start Time","End Time","Factory","Line", "Good Glove", "Produced Glove", "Empty Link"]+CLASSES[1:])
        with open('logs/AIVCdata.csv', mode='a', newline='') as file:
            writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            writer.writerow(data_to_log)
        print(f"Record Saved\n{data_to_log}")

    def setPurgeEnableRASM(self):
        seq=self.sender().seq
        val=self.sender().isChecked()
        CFG.ENABLE_PURGE_RASM[seq]=val
        CFG_Handler.set('ENABLE_PURGE_RASM',CFG.ENABLE_PURGE_RASM)
    def setPurgeEnableFKTH(self):
        seq=self.sender().seq
        val=self.sender().isChecked()
        CFG.ENABLE_PURGE_FKTH[seq]=val
        CFG_Handler.set('ENABLE_PURGE_FKTH',CFG.ENABLE_PURGE_FKTH)
    def setPeriEnable(self):
        seq=self.sender().seq
        val=self.sender().isChecked()
        CFG.ENABLE_PERIPHERAL[seq]=val
        CFG_Handler.set('ENABLE_PERIPHERAL',CFG.ENABLE_PERIPHERAL)

    def enableFormerMarking(self,enable):
        CFG_Handler.set('ENABLE_FORMER_MARKING',enable)

    def showCamDelaySpinBox(self, enable):
        for camBox in self.camBoxes:
            if enable:
                camBox.camDelaySpinBox.show()
            else:
                camBox.camDelaySpinBox.hide()

    def showFormerSpinBox(self, enable):
        for camBox in self.camBoxes:
            if enable:
                camBox.formerSpinBox.show()
            else:
                camBox.formerSpinBox.hide()
    def showSensorSpinBox(self, enable):
        for camBox in self.camBoxes:
            if enable:
                camBox.sensorSpinBox.show()
            else:
                camBox.sensorSpinBox.hide()

    def showCamSeqSpinBox(self, enable):
        for camBox in self.camBoxes:
            if enable:
                camBox.camSeqSpinBox.show()
            else:
                camBox.camSeqSpinBox.hide()

    def showRasmOffsetCheckBox(self, enable):
        for rasmDefectionGrid in self.rasmDefectionGrids:
            if enable:
                rasmDefectionGrid.rasmOffsetEdit.show()
            else:
                rasmDefectionGrid.rasmOffsetEdit.hide()

    def setFormerInterval(self):
        seq=self.sender().parent().seq
        interval=self.sender().value()
        if seq in Cam_Seq:
            Former_Interval[seq]=interval
            self.dataThread.RCs[getSide(seq)].clear()
        CFG_Handler.set('FORMER_INTERVAL_ALL',CFG.FORMER_INTERVAL_ALL)

    def setCamSensor(self):
        seq=self.sender().parent().seq
        Cam_Sensor[seq]=self.sender().value()
        CFG_Handler.set('CAM_SENSOR_ALL',CFG.CAM_SENSOR_ALL)

    def setPurgerSensor(self):
        seq=self.sender().seq
        CFG.PURGER_SENSOR[seq]=self.sender().value()-self.sender()._min
        CFG_Handler.set('PURGER_SENSOR',CFG.PURGER_SENSOR)

    def setCamDelay(self):
        seq=self.sender().parent().seq
        delay=self.sender().value()
        if seq in Cam_Seq:
            self.captureThread.indiviDelay[Cam_Seq.index(seq)]=delay/1000
            Cam_Delay[seq]=delay
        CFG_Handler.set('CAM_DELAY_ALL',CFG.CAM_DELAY_ALL)
    def checkUpdateRestart(self):
        if self.dataThread.jsonRPCThread.otaClientProcess.updated.value:
            if "AIVC_Monitor.exe" in (p.name() for p in psutil.process_iter()):
                self.close()
            else:
                logger.warning('AIVC Pending Update Restart But AIVC Monitor Is Not On.')
                CFG_Handler.set('ENABLE_AUTO_RESTART',True) 
    def closeEvent(self, event):
        #Wait for last thread loop to finish
        if self.user:
            self.userDialog.logout()#Logout for logging purpose
        toUpdate=self.dataThread.jsonRPCThread.otaClientProcess.updated.value
        self.saveRecord()
        self.captureThread.closeThread()
        self.inferenceThread.closeThread()
        self.dataThread.closeThread()
        self.purgingThread.closeThread()
        self.secTimer.closeThread()
        self.minTimer.closeThread()
        self.settingDialog.close()
        self.imgDialog.close()
        self.tableDialog.close()
        self.infoDialog.close()
        self.plcDialog.close()
        self.dataHistoryDialog.close()
        self.userDialog.close()
        self.plc.close()
        self.modelLowConfident.close()
        if toUpdate:
            saveStatus(2)#Indicate pending update
        else:
            saveStatus(0)#Indicate clean close
        while not (self.inferenceThread.isFinished() and \
            self.dataThread.isFinished() and self.captureThread.isFinished() and \
            self.purgingThread.isFinished() and self.minTimer.isFinished()) and \
            self.secTimer.isFinished() :
            pass
        # tracelog
        logger.info("APPLICATION CLOSED")
        event.accept()

    def hidePurgerSetting(self):
        self.settingDialog.hide()

    def acceptedPurgerSetting(self):
        self.applyPurgerSetting()
        self.settingDialog.hide()

    def applyPurgerSetting(self):
        for i in range(4):
            for j in range(4):
                CFG.PURGER_SETTING[i][j]= self.purgerforms[i].itemAt(j,QFormLayout.FieldRole).widget().val
            self.purgingThread.purgerDistance[i] = CFG.PURGER_SETTING[i][0]
            if CFG.AIVC_MODE==0:
                self.plc.setPurgeDelay_100ms(i,CFG.PURGER_SETTING[i][1])
                self.plc.setPurgeInterval_100ms(i,CFG.PURGER_SETTING[i][2])
                self.plc.setPurgeDuration_100ms(i,CFG.PURGER_SETTING[i][3])
        CFG_Handler.set('PURGER_SETTING',CFG.PURGER_SETTING)

    def setCamBoxWithID(self, image, label, camSeq):
        self.camBoxes[camSeq].setCamBox(QPixmap.fromImage(image), label)

    def clearCamBox(self,camSeq):
        self.camBoxes[camSeq].camView.setPixmap(QPixmap(""))

    def setListItem(self, name, img):
        item=QListWidgetItem(name,self.ui.listWidget)
        #self.ui.listWidget.addItem(item) 
        #Store image path in item's role 32(Application specific role)
        item.setData(32,img)
        if self.ui.listWidget.count()>3000:#Remove item after there's more than 2000
            for i in range(50):
                self.ui.listWidget.takeItem(0)
            self.ui.listWidget.scrollToItem(self.ui.listWidget.currentItem())

    def setView(self, current, previews):
        imgPath=current.data(32)
        pixmap=QPixmap(imgPath)
        self.ui.img_view.setPixmap(pixmap.scaled(self.ui.img_view.width(),self.ui.img_view.height(),Qt.KeepAspectRatio))

    def openUserDialog(self):
        self.userDialog.show()

    def loginUpdateUI(self):
        user=self.userDialog.user
        self.user=user['email']
        self.accessLvl=user['authorityLvl']
        userName=self.user
        if len(userName)>15:
            userName=userName[:13]+'...'
        self.ui.label_user.setText(f"{userName} [{self.accessLvl}]")
        if CFG.LOCK_SETTING:
            if self.accessLvl<=8:
                self.ui.btn_setting.setEnabled(True)
                self.ui.btn_setting.setToolTip("Setting")


    def logoutUpdateUI(self):
        self.user=None
        self.accessLvl=10
        self.ui.label_user.setText("User")
        if CFG.LOCK_SETTING:
            self.settingDialog.hide()
            self.ui.btn_setting.setEnabled(False)
            self.ui.btn_setting.setToolTip("Require User AuthorityLvl 8")

            self.setting_ui.camDelayCheckBox.setChecked(False)
            self.setting_ui.camSeqCheckBox.setChecked(False)
            self.setting_ui.formerIntCheckBox.setChecked(False)
            self.setting_ui.sensorCheckBox.setChecked(False)
            self.setting_ui.rasmOffsetCheckBox.setChecked(False)

    def changeButtonText(self):
        self.capturing= not self.capturing
        if self.capturing:
            self.ui.btn_start.setText("Stop Capturing")
        else:
            self.ui.btn_start.setText("Start Capture")

    def openLabelWindow(self):
        if self.ui.listWidget.currentItem():
            imgPath=self.ui.listWidget.currentItem().data(32).replace(os.sep, '/')
            labelWindow=LabelWindow(parent=self,defaultImg=imgPath,onAIVC=True,factory=CFG.FACTORY_NAME,line=CFG.LINE_NUM,userDL=self.userDialog)
        else:
            labelWindow=LabelWindow(parent=self,defaultFilename=LOW_CONF_DIR,onAIVC=True,factory=CFG.FACTORY_NAME,line=CFG.LINE_NUM,userDL=self.userDialog)
        labelWindow.show()
        print("Open Label Window")

    def openSettingWindow(self):
        self.settingDialog.show()
        #Load previous setting data

        for i in range(4):
            for j in range(4):
                self.purgerforms[i].itemAt(j,QFormLayout.FieldRole).widget().setText(str(CFG.PURGER_SETTING[i][j]))
        self.text_factory.setText(CFG.FACTORY_NAME)
        self.text_line.setText(str(CFG.LINE_NUM))
        self.text_plcIP.setText(CFG.PLC_IP)
        self.text_rasmNum.setText(str(CFG.RASM_ARM_NUM))
        self.text_teamsAddr.setText(str(CFG.TEAMS_ADDR))

class CameraTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent=parent)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(1, 1, 1, 1)
        self.setLayout(layout)
        self.scrollArea = QScrollArea(self)
        self.scrollWidget=QWidget(self.scrollArea)

        #self.scrollWidget.setGeometry(QRect(0, 0, 1035, 800))
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setWidget(self.scrollWidget)
        self.grid=QGridLayout(self.scrollWidget)
        self.grid.setContentsMargins(5, 5, 5, 5)
        self.scrollWidget.setLayout(self.grid)
        layout.addWidget(self.scrollArea)


class CamBox(QWidget):
    def __init__(self, seq, parent=None):
        super().__init__(parent=parent)
        self.seq=seq
        vbox=QVBoxLayout()
        self.camLabel=QLabel("Left In | Classes | Former ID")
        self.camView=QLabel()
        if SMALL_SCREEN:#1360*768
            self.camLabel.setFont(QFont('Arial', 9)) 
            cWidth=440
            cHeight=330
            maxHeight=380
        else:#Big Screen 1920*1080
            self.camLabel.setFont(QFont('Arial', 12)) 
            vbox.setContentsMargins(30,0,0,0)
            cWidth=700
            cHeight=430
            maxHeight=480
        if NARROW_SCREEN:
            cWidth=cWidth//1.7
            cHeight=cHeight//1.7
        if CFG.ROTATE:#Vertical Image
            self.camView.setFixedSize(QSize(cWidth, int(cWidth*1.333)))
            self.setMaximumHeight(int(cWidth*1.333)+50)
        else:#Horizontal Image
            self.camView.setFixedSize(QSize(cWidth, cHeight))
            self.setMaximumHeight(maxHeight)
        self.camView.setFrameShape(QFrame.Box)
        self.camView.setFrameShadow(QFrame.Sunken)
        self.camView.setScaledContents(True)
        vbox.addWidget(self.camView)
        self.setLayout(vbox)
        hbox=QHBoxLayout()
        hbox.setContentsMargins(0,0,20,0)
        vbox.addLayout(hbox)
        hbox.addWidget(self.camLabel)
        hbox.addItem(QSpacerItem(5,5))
        self.camSeqSpinBox=LRSpinBox(self.seq, 'Cam Seq:')
        hbox.addWidget(self.camSeqSpinBox)
        self.camDelaySpinBox=MySpinBox(self.seq, 'Cam Delay:',_min=0,_max=200,step=10)
        hbox.addWidget(self.camDelaySpinBox)
        self.formerSpinBox=MySpinBox(self.seq, 'Former Dis:',_min=-10,_max=200,step=1)
        hbox.addWidget(self.formerSpinBox)
        self.sensorSpinBox=MySpinBox(self.seq,'Sensor:',_max=CFG.SENSOR_NUM-1, parent=self)
        hbox.addWidget(self.sensorSpinBox)
        self.update()
    def setCamBox(self, image, label):
        self.camLabel.setText(label)
        self.camView.setPixmap(image.scaled(self.camView.width(),self.camView.height(),Qt.KeepAspectRatio))
    
    def update(self):
        if self.seq < len(Cam_Seq):
            self.camSeqSpinBox.lineEdit.setText(str(Cam_Seq.index(self.seq)))
            self.camDelaySpinBox.spinBox.setValue(Cam_Delay[self.seq])
            self.formerSpinBox.spinBox.setValue(Former_Interval[self.seq])
            self.sensorSpinBox.spinBox.setValue(Cam_Sensor[self.seq])



class DefectionGrid(QWidget):
    preColor='lightgreen'
    sendProblematic=pyqtSignal(dict)
    sendFormerLamp=pyqtSignal(int,int,float)
    def __init__(self, seq, parent=None, armNum=0):
        super(DefectionGrid,self).__init__(parent=parent)
        self.parent=parent
        self.seq=seq
        self.label=QLabel("")
        self.frame=QFrame()
        vbox=QVBoxLayout()
        if SMALL_SCREEN:
            cWidth=440
            cHeight=330
            maxHeight=400
            self.label.setFont(QFont('Arial', 9)) 
        else: #for 1280 and others
            cWidth=700
            cHeight=430
            maxHeight=450
            vbox.setContentsMargins(30,0,0,0)
            self.label.setFont(QFont('Arial', 12)) 

        self.probleMaticFormer={}
        self.setMaximumHeight(maxHeight)
        self.armsID=[]
        self.items=[]
        self.side=0
        self.emptyLink=np.zeros((4,CFG.CHAIN_FORMER_NUM), dtype = bool)
        self.cycle=0
        self.contBad=np.zeros((4,CFG.CHAIN_FORMER_NUM), dtype = int)
        self.contGood=np.zeros((4,CFG.CHAIN_FORMER_NUM), dtype = int)
        self.setLayout(vbox)
        self.frame.setFixedSize(cWidth,cHeight)
        self.frame.setFrameStyle(6)
        self.gridLayout=QGridLayout(self.frame)
        self.frame.setLayout(self.gridLayout)
        self.loadRasmArm(armNum)
        vbox.addWidget(self.frame)
        hbox=QHBoxLayout()
        vbox.addLayout(hbox)
        hbox.addWidget(self.label)
        hbox.addItem(QSpacerItem(5,5))
        self.rasmOffsetEdit=RasmAnchorOffsetLineEdit(self.seq, self)
        self.rasmOffsetEdit.lineEdit.setText(str(CFG.RASM_ANCHOR_OFFSET[self.seq]))
        hbox.setContentsMargins(0,0,10,0)
        hbox.addWidget(self.rasmOffsetEdit)
    def loadRasmArm(self, armNum):
        col=int(armNum/10)
        for i in range(col+1): 
            for j in range(10 if i!=col else armNum%10):
                arm=Arm(i*10+j+1, self.seq, parent=self.frame)
                arm.armClicked.connect(self.parent.armClicked)
                self.gridLayout.addWidget(arm,i,j)
                self.items.append(arm)

    def updateArm(self, index, armID, armRecord, side=0, emptyLink=False, cycle=0, contBad=0, contGood=0, lab='',highlight=False,chain=False,updateData=True):
        gg=armRecord[0]
        rdg=0
        odg=0
        tt=''
        defectRecord={}
        total=0
        defectRecord.update({f'Good Glove': int(gg)})
        if chain:
            rClass=CHAIN_CLASS
            name='Chain'
        else:
            rClass=RASM_CLASS
            name='RASM'

        for i,record in enumerate(armRecord):
            recordInt = int(record)
            total+=recordInt
            if i >0:
                if i in rClass:
                    rdg+=record
                    tt+=f'{CLASSES[i]}: {recordInt}\n'
                    defectRecord.update({CLASSES[i]: int(recordInt)})             
                else:
                    odg+=recordInt
        defectRecord.update({f'Non-{name}-Related': odg})
        tt+=f'Non-{name}-Related: {odg}\n'
        rdr=float(rdg)/(total) if total!=0 else 1
        tt+=f'Good Glove: {gg}\n{name} Defective Rate: {rdr*100:.2f}%'
        defectRecord.update({f'Defective Rate': float(f'{rdr*100:.2f}')})

        if name == 'Chain' and updateData:
            if cycle >= 3:
                if(rdr<0.05):
                    if contBad >= 3:
                        #print(f'==============ID: {armID} | Rate: {rdr*100:.2f}% ===================')
                        self.updateProblematicFormer(self.seq, armID, defectRecord)
                        self.sendFormerLamp.emit(armID,side,rdr)                  
                elif(rdr<0.1):
                    if contBad >= 3:
                        #print(f'==============ID: {armID} | Rate: {rdr*100:.2f}% ===================')
                        self.updateProblematicFormer(self.seq, armID, defectRecord)
                        self.sendFormerLamp.emit(armID,side,rdr)  
                elif(rdr<0.3):
                    if contBad >= 3:
                        #print(f'==============ID: {armID} | Rate: {rdr*100:.2f}% ===================')
                        self.updateProblematicFormer(self.seq, armID, defectRecord)
                        self.sendFormerLamp.emit(armID,side,rdr)
                else:
                    """if contBad >= 3:
                        #print(f'==============ID: {armID} | Rate: {rdr*100:.2f}% ===================')
                        self.updateProblematicFormer(self.seq, armID, defectRecord)
                        self.sendFormerLamp.emit(armID,side,rdr)"""
                    if contGood <= 3:
                        #print(f'==============ID: {armID} | Rate: {rdr*100:.2f}% ===================')
                        self.updateProblematicFormer(self.seq, armID, defectRecord)
                        self.sendFormerLamp.emit(armID,side,rdr)
        if chain:
            if CFG.AIVC_MODE == 0:
                tt+=f'\nNum. of Cycle: {cycle}\nContinuous Bad: {contBad}\nContinuous Good: {contGood}'
        if lab:
            self.label.setText(lab)
        self.items[index].id=armID
        self.items[index].defectiveRate=rdr
        self.items[index].setToolTip(tt)
        self.items[index].setText( f"<span style='font-size:8pt; font-weight:500;'>{armID}\n</span><br><span style='font-size:7pt; font-weight:400;'>{rdr*100:.2f}%</span>" )

        if not chain:#Set Color by Defective Rate for RASM
            if(rdr<0.05):
                color='lightgreen'
            elif(rdr<0.1):
                color='yellow'
            elif(rdr<0.3):
                color='orange'
            else:
                color='red'

        else:#Set Color by Defective Rate for FKTH
            if(rdr<0.05):
                if contBad >= 3:
                    color='red'
                    if emptyLink == True:
                        color='cyan'
                else:
                    color='lightgreen'
                    if emptyLink == True:
                        color='cyan'
            elif(rdr<0.1):
                if contBad >= 3:
                    color='red'
                    if emptyLink == True:
                        color='cyan'
                else:
                    color='yellow'
                    if emptyLink == True:
                        color='cyan'
            elif(rdr<0.3):
                if contBad >= 3:
                    color='red'
                    if emptyLink == True:
                        color='cyan'
                else:
                    color='orange'
                    if emptyLink == True:
                        color='cyan'
            else:
                if contGood >= 3:
                    color='gray'
                    if emptyLink == True:
                        color='cyan'
                else:
                    color='red'
                    if emptyLink == True:
                        color='cyan'

        if highlight:
            self.items[index].setStyleSheet(f"QLabel {{background-color: {color}; border: 3px solid orange; border-radius: 5px;}}") 
        else:
            self.items[index].setStyleSheet(f"QLabel {{background-color: {color}; border: 2px solid black; border-radius: 5px;}}") 

        self.preColor=color

    def updateProblematicFormer(self,seq,armID,defectRecord):
        utcDateTime=datetime.datetime.utcnow().isoformat()
        DateTime=datetime.datetime.now().isoformat()
        self.probleMaticFormer = {
                "UTCDateTime": utcDateTime,
                "DateTime": DateTime, 
                "Mode": CFG.AIVC_MODE, 
                "Factory": CFG.FACTORY_NAME, 
                "ProductionLine": f'L{CFG.LINE_NUM}', 
                "ProductionLineRow": SIDE_NAME[seq], 
                "FormerID": armID,
                "Continuous Good" : int(self.contGood[self.side][armID]),
                "Continuous Bad" : int(self.contBad[self.side][armID]),
                "Cycle Number" : int(self.cycle),
                "Defect_Classes": defectRecord
            }
        self.sendProblematic.emit(self.probleMaticFormer)
        

    def addChainArm(self, formerID, side, record, lab):
        if formerID in self.armsID:
            self.updateArm(self.armsID.index(formerID), formerID, record, side, self.emptyLink[self.side][formerID], self.cycle, self.contBad[self.side][formerID], self.contGood[self.side][formerID], lab, highlight=True, chain=True)
        else:
            lastIndex=len(self.armsID)
            self.armsID.append(formerID)
            print(f"AddArm {formerID}")
            arm=Arm(formerID, self.seq, isChainArm=True, parent=self.frame)
            arm.armClicked.connect(self.parent.armClicked)
            self.gridLayout.addWidget(arm,int(lastIndex/10),lastIndex%10)
            self.items.append(arm)
            self.updateArm(lastIndex, formerID, record, side, self.emptyLink[self.side][formerID], self.cycle, self.contBad[self.side][formerID], self.contGood[self.side][formerID], lab, highlight=True, chain=True)

    def addContGoodBadCycle(self, side, former, cycle, contBad, contGood, emptyLink):
        self.side = side
        self.former = former
        self.cycle = cycle
        self.contBad = contBad
        self.contGood = contGood
        self.emptyLink = emptyLink

    def updateRasmGrid(self, rasmID1, armRecord, lab):
        #Remove previous border highlight
        itemNum=len(self.items)
        if rasmID1>itemNum:
            arm=Arm(rasmID1, self.seq, parent=self.frame)
            arm.armClicked.connect(self.parent.armClicked)
            self.gridLayout.addWidget(arm,int(itemNum/10),itemNum%10)
            self.items.append(arm)
            self.updateArm(rasmID1-1, rasmID1, armRecord, lab, highlight=True)
        else:
            if(rasmID1==1):
                self.items[-1].setStyleSheet(f"QLabel {{background-color: {self.preColor}; border: 2px solid black; border-radius: 5px;}}")
            else:
                self.items[rasmID1-2].setStyleSheet(f"QLabel {{background-color: {self.preColor}; border: 2px solid black; border-radius: 5px;}}")
            self.updateArm(rasmID1-1, rasmID1, armRecord, lab, highlight=True)#for RASM ID is the same as index

    def updateAllChain(self, gloveDefectionRecord,clear=False):
        if clear:
            self.armsID=[]
            for item in self.items:
                item.deleteLater()
            self.items=[]
        else:
            t=time.time()
            self.armsID.sort()
            idxsToRemove=[]
            for index, armID in enumerate(self.armsID):
                removedNum=len(idxsToRemove)
                try:
                    record=gloveDefectionRecord[armID]
                    gg=np.sum(record[0])
                    dg=np.sum(record[1:])
                    dr=float(dg)/(dg+gg)# if pg!=0 else 1
                    if(dr <0.2): #Remove from grid
                        idxsToRemove.append(index-removedNum)
                    else:
                        self.updateArm(index-removedNum, armID, record, self.side, self.emptyLink[self.side][armID], self.cycle, self.contBad[self.side][armID], self.contGood[self.side][armID], highlight=False, chain=True, updateData=False)
                except KeyError as e:
                    recorder.debug(f"updateAllChain Key Error :{e}")
            for idx in idxsToRemove:
                del self.armsID[idx]
                self.items[-1].deleteLater()
                del self.items[-1]
            print(f"updateAllChain took {time.time()-t}s")

    def clear(self):
        for item in self.items:
            item.deleteLater()
        self.items.clear()
        self.loadRasmArm(CFG.RASM_ARM_NUM)

class Arm(QLabel):
    armClicked=pyqtSignal(str)
    def __init__(self, id, side, isChainArm=False, parent=None):
        super().__init__(str(id), parent)
        self.id=id
        self.side=side
        self.isChainArm=isChainArm
        self.defectiveRate=0
        myFont=QFont("Helvetica", 10, QFont.Bold)
        self.setFont(myFont)
        self.setAlignment(Qt.AlignCenter)
        self.setFixedSize(35,38)
        self.setToolTip('No data')
        self.setStyleSheet("QLabel {background-color: lightgreen; border: 2px solid black; border-radius: 5px;}") 
        self.mousePressEvent=self.emitClick
        
    def emitClick(self,event):
        if self.isChainArm:
            matchStr=f"{(self.id+SIDE_SEP*self.side):05d}"
        else:
            matchStr=f"{SIDE_SHORT[self.side]}{self.id:02d}"
        self.armClicked.emit(matchStr)
        
TIME_SEGMENT_HEIGHT=20
ROW_HEIGHT=TIME_SEGMENT_HEIGHT+10
PIXEL_PER_HOUR=10
DATA_STR=["State", "Start Time","End Time","Factory","Line", "Good Glove", "Produced Glove", "Empty Link"]+CLASSES[1:]
class DataHistoryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent, flags=Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
        self.parent=parent
        self.setWindowTitle("AIVC Data History")
        vLayout=QVBoxLayout()
        self.setLayout(vLayout)
        hLayout=QHBoxLayout()
        vLayout.addLayout(hLayout)
        self.monthSelect=QDateEdit()
        self.monthSelect.setMaximumWidth(100)
        self.monthSelect.setDisplayFormat("yy MMMM")
        self.monthSelect.setCalendarPopup(True)
        self.monthSelect.setMinimumDate(QDate.currentDate().addDays(-70))
        self.monthSelect.setMaximumDate(QDate.currentDate())
        self.monthSelect.currentSection=QDateTimeEdit.MonthSection
        self.monthSelect.dateChanged.connect(self.setDisplay)
        hLayout.addWidget(self.monthSelect)
        self.label=QLabel('Please select the month to review')
        hLayout.addWidget(self.label)
        # hLayout.addItem(QSpacerItem(20, 20, QSizePolicy.MinimumExpanding, QSizePolicy.Preferred))
        # legend=QLabel()
        # legend.setPixmap(QPixmap(":/utils/icons/legend.png").scaled(300,40,Qt.KeepAspectRatio))
        # hLayout.addWidget(legend)
        vLayout.addItem(QSpacerItem(20, 20, QSizePolicy.Preferred, QSizePolicy.MinimumExpanding))
        self.setFixedSize(QSize(820, 600))
        self.scene  =QGraphicsScene()
        self.scene.installEventFilter(self)
        self.graphicView = QGraphicsView(self.scene, self)
        self.graphicView.setGeometry(10,40,800,550)
        self.graphicView.show()
    def eventFilter(self, obj, event):
        if obj is self.scene and event.type()==QEvent.GraphicsSceneMouseRelease:
            if self.scene.selectedItems():
                if type(self.scene.selectedItems()[0]) is TimeSegment:
                    self.textItem.setHtml(self.scene.selectedItems()[0].dataStr)
        return super().eventFilter(obj, event)
    def setDisplay(self,qDate):
        stateDuration=[0 for _ in STATE]
        self.scene.clear()
        monthStartTime=datetime.datetime(qDate.year(),qDate.month(),1)
        dataHistoryDir=f'logs/{monthStartTime.strftime("%y%B")}_AIVCHourlyData.csv'
        self.label.setText(dataHistoryDir)
        self.textItem=QGraphicsTextItem()
        self.textItem.setHtml(f'<h3>{dataHistoryDir}</h3>')
        self.textItem.setPos(30,350)
        self.textItem.setTextWidth(700)
        self.scene.addItem(self.textItem)
        if os.path.exists(dataHistoryDir):
            if qDate.month()==12:
                nextMonth=datetime.datetime(qDate.year()+1,1,1)
            else:
                nextMonth=datetime.datetime(qDate.year(),qDate.month()+1,1)
            totalSecond=(nextMonth-monthStartTime).total_seconds()
            legend=QGraphicsPixmapItem(QPixmap(":/utils/icons/legend.png"))
            legend.setPos(400, ROW_HEIGHT*10)
            self.scene.addItem(legend)
            with open(dataHistoryDir, mode='r') as file:
                reader=csv.reader(file)
                records=[record for record in reader if len(record)>2] #Remove empty line
                records.pop(0)
                #Add black strip for AIVC closed time
                j=0
                while(True):
                    if((monthStartTime+datetime.timedelta(days=(j+1)*3)).month==qDate.month()):
                        bs=BlackStrip(ROW_HEIGHT*j)
                        self.scene.addItem(bs)
                        j+=1
                    else:
                        leftDays=(nextMonth-(monthStartTime+datetime.timedelta(days=j*3))).days
                        width=leftDays/3*720
                        bs=BlackStrip(ROW_HEIGHT*j,width=width)
                        self.scene.addItem(bs)
                        break
                for record in records:
                    stateStr,startTimeStr,endTimeStr,factory,line,*data=record
                    startT=datetime.datetime.strptime(startTimeStr,"%Y-%m-%d_%H:%M:%S")
                    endT=datetime.datetime.strptime(endTimeStr,"%Y-%m-%d_%H:%M:%S")
                    durationSec=(endT-startT).total_seconds()
                    durationHour=durationSec/3600
                    width=round(durationHour*PIXEL_PER_HOUR)
                    hourInMonth=(startT-monthStartTime).total_seconds()/3600
                    positionX=round(hourInMonth*PIXEL_PER_HOUR)%720+20 #3 Day Per Row
                    positionY=int(hourInMonth/72)*(ROW_HEIGHT)
                    state=STATE.index(stateStr)
                    stateDuration[state]+=durationSec
                    dataStr='<h3>'
                    try:
                        for i, dataType in enumerate(DATA_STR):
                            dataStr+=f'{dataType}: {record[i]}, '
                    except IndexError:
                        print(f'Data Segment Wrong Format: {record}')
                    dataStr=dataStr[:-2]+'</h3>'
                    timeSegment=TimeSegment(positionX,positionY,width,TIME_SEGMENT_HEIGHT,state,dataStr)
                    self.scene.addItem(timeSegment)
                #Draw Total
                bs=BlackStrip(480)#Black Strip for total status
                self.scene.addItem(bs)
                stateDuration[1]+=stateDuration[0]#Combine Start & Running
                xPos=20
                statusStr='<h2>'
                onPercentage=0
                for i in range(1,5):
                    percentage=stateDuration[i]/totalSecond
                    onPercentage+=percentage
                    statusStr+=f'{STATE[i]}:{percentage*100:.2f}%  '
                    width=round(percentage*720)
                    totalSegment=QGraphicsRectItem(xPos,480,width,TIME_SEGMENT_HEIGHT)
                    brush=QBrush(STATE_COLOR[i])
                    totalSegment.setBrush(brush)
                    totalSegment.update()
                    self.scene.addItem(totalSegment)
                    xPos+=width
                #AIVC closed status

                statusStr+=f'AIVC Closed:{(1-onPercentage)*100:.2f}%</h2>'
                self.statusTextItem=QGraphicsTextItem()
                self.statusTextItem.setHtml(statusStr)
                self.statusTextItem.setPos(30,420)
                self.statusTextItem.setTextWidth(700)
                self.scene.addItem(self.statusTextItem)
        else:
            self.label.setText(f'No Data for {monthStartTime.strftime("%y%B")}')

class ModelLowConfident(QDialog): # syafii edit, add new classes
    def __init__(self, parent=None):
        super().__init__(parent, flags=Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
        self.parent=parent
        self.setWindowTitle("AIVC Model Performance")
        #self.setFixedSize(350,150)
        vLayout=QVBoxLayout()
        self.setLayout(vLayout)
        hLayout=QHBoxLayout()
        vLayout.addLayout(hLayout)
        self.table=QTableWidget(self)
        vLayout.addWidget(self.table)
        self.table.setColumnCount(3)
        self.table.setRowCount(len(CLASSES))
        self.table.setSizePolicy(QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred))
        sizePolicy=QSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.MinimumExpanding)
        self.setSizePolicy(sizePolicy)
        self.table.setHorizontalHeaderLabels(("Total Glove","Low Conf. Found","High Conf. Rate"))
        self.table.setVerticalHeaderLabels((CLASSES))
        self.table.setColumnWidth(0,100)
        self.table.setColumnWidth(1,120)
        self.table.setColumnWidth(2,100)
        self.resize(vLayout.sizeHint().width(),vLayout.sizeHint().height())
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        #self.table.setMinimumSize(QSize(710, 600))
        self.resize(470,420)
         
    def display(self,appendData,classData,differentDataRate):
        combineData=[]
        split=len(CLASSES)
        for i in range (len(CLASSES)):
            combineData.append(appendData[i])
            combineData.append(classData[i])
            combineData.append(differentDataRate[i])
        self.newData=np.array_split(combineData,split)
        rows=-1
        columns=-1
        for row in self.newData:
            rows+=1
            for column in row:
                columns+=1
                intColumn = int(column)
                item = QTableWidgetItem()
                if columns == 0 or columns == 1:
                    item.setText(str(intColumn))
                    self.table.setItem(rows,columns,item)
                if columns == 2:
                    strColumn = f'{column:.2f}%'
                    item.setText(strColumn)
                    self.table.setItem(rows,columns,item)
                    columns=-1

class BlackStrip(QGraphicsRectItem):
    def __init__(self,y,width=720,qtParent=None):
        super().__init__(20,y,width,TIME_SEGMENT_HEIGHT,parent=qtParent)
        brush=QBrush(Qt.black)
        self.setBrush(brush)
        self.update()
        #self.setFlag(QGraphicsItem.ItemIsSelectable)

class TimeSegment(QGraphicsRectItem):
    def __init__(self,x,y,width,height=TIME_SEGMENT_HEIGHT,state=5,dataStr="",qtParent=None):
        super().__init__(x,y,width,height,parent=qtParent)
        self.dataStr=dataStr
        self.state=state
        brush=QBrush(STATE_COLOR[state])
        self.setBrush(brush)
        self.update()
        self.setFlag(QGraphicsItem.ItemIsSelectable)

class TableDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent, flags=Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
        self.parent=parent
        self.setWindowTitle("Defect Data Snapshot")
        vLayout=QVBoxLayout()
        self.setLayout(vLayout)
        self.label=QLabel('From')
        self.label.setFont(QFont('Arial', 14))
        self.label.setFixedSize(QSize(710, 20))
        vLayout.addWidget(self.label)
        self.table=QTableWidget(self)
        vLayout.addWidget(self.table)
        self.table.setColumnCount(6)
        self.table.setRowCount(CLASS_NUM+3)
        self.table.setSizePolicy(QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred))
        sizePolicy=QSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.MinimumExpanding)
        self.setSizePolicy(sizePolicy)
        #self.resize(vLayout.sizeHint().width(),vLayout.sizeHint().height())
        self.table.setMinimumSize(QSize(710, 150))
        self.resize(710, 500)
        for col in range(5):
            item = QTableWidgetItem()
            item.setText(self.parent.ui.table_defect_data.horizontalHeaderItem(col).text())
            self.table.setHorizontalHeaderItem(col,item)

        item = QTableWidgetItem('Percentage')
        self.table.setHorizontalHeaderItem(5,item)
        for row in range(CLASS_NUM+3):
            item = QTableWidgetItem()
            item.setText(self.parent.ui.table_defect_data.verticalHeaderItem(row).text())
            self.table.setVerticalHeaderItem(row,item)
        item = QTableWidgetItem('-')
        self.table.setItem(0,5,item)

    def load(self):
        self.label.setText(f'From   {self.parent.ui.label_startTime.text()}  Till   {time.strftime("%m/%d %H:%M:%S")}')
        for row in range(CLASS_NUM+3):
            for col in range(5):
                item = QTableWidgetItem()
                item.setText(self.parent.ui.table_defect_data.item(row,col).text())
                self.table.setItem(row,col,item)
        total=int(self.table.item(2,4).text()) #Produced Glove
        for row in range(1,CLASS_NUM+3):
            number=int(self.table.item(row,4).text())
            try:
                percentage=number/total
            except ZeroDivisionError:
                percentage=0
            item = QTableWidgetItem()
            item.setText(f"{percentage*100:.2f}%")
            self.table.setItem(row,5,item)

class PLCData():
    def __init__(self,seq,d,addrTxt,name="Not Assigned",value=0,parent=None):
        self.seq=seq
        self.d=d
        self.addrTxt=addrTxt
        self.name=name
        self.value=value
        self.addr=int(addrTxt[1:])
        self.addrLabel=QLabel(addrTxt)
        self.nameLabel=QLabel(name)
        if self.d:#register
            self.input=LineEditLimInt(max=32767,hint='0~32767',upper=self)
            self.input.setFixedWidth(40)
        else:#coil
            self.input=ChildCheckBox(upper=self)

        self.btn_delete=ChildButton(upper=self)
        self.btn_delete.setAutoDefault(False)
        self.btn_delete.setFixedSize(25,25)
        icon = QIcon()
        icon.addPixmap(QPixmap(":/utils/icons/no.png"))
        self.btn_delete.setIcon(icon)
        self.btn_delete.setIconSize(QSize(20, 20))
    
class PLCDialog(QDialog):
    def __init__(self, parent, plc):
        super().__init__(parent, flags=Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
        self.parent=parent
        self.plc=plc
        self.setFixedSize(350,500)
        self.setWindowTitle("PLC Control")
        vLayout=QVBoxLayout()
        self.setLayout(vLayout)
        self.grid=QGridLayout()
        vLayout.addLayout(self.grid)
        spacerItem = QSpacerItem(20, 20, QSizePolicy.Preferred, QSizePolicy.MinimumExpanding)
        vLayout.addItem(spacerItem)
        label=QLabel('Address:')
        label.setFixedWidth(105)
        self.grid.addWidget(label,0,0,1,1)
        label=QLabel('Name:')
        label.setFixedWidth(170)
        self.grid.addWidget(label,0,1,1,1)
        label=QLabel('Value:')
        label.setFixedWidth(40)
        self.grid.addWidget(label,0,2,1,1)
        self.input_addr=PLCAddrInput(parent=self,maxD=4096,maxM=2048,hint='D0~4096/M0~2048')
        self.grid.addWidget(self.input_addr,1,0,1,1)
        self.input_name=QLineEdit()
        self.input_name.setPlaceholderText('Name')
        self.grid.addWidget(self.input_name,1,1,1,1)
        self.btn_add=QPushButton()
        self.btn_add.setFixedSize(25,25)
        self.btn_add.setAutoDefault(False)
        icon1 = QIcon()
        icon1.addPixmap(QPixmap(":/utils/icons/new.png"))
        self.btn_add.setIcon(icon1)
        self.btn_add.setIconSize(QSize(20, 20))
        self.btn_add.clicked.connect(self.addRow)
        self.grid.addWidget(self.btn_add,1,3,1,1)
        self.deleteButtons=[]
        self.plcDatas=[]
        self.loadHistory()
    def addRow(self):
        addrTxt=self.input_addr.text()
        name=self.input_name.text()
        if self.loadRow(addrTxt,name): #Success load row
            self.input_addr.clear()
            self.input_name.clear()
            plcData=self.plcDatas[-1]
            if plcData.d:
                val=plcData.input.val
            else:
                val=plcData.input.isChecked()
            CFG.PLC_CONFIG.append([plcData.addrTxt,plcData.name,val])#beware here didn't save config immediately
            CFG_Handler.set('PLC_CONFIG',CFG.PLC_CONFIG)
            
    def loadRow(self, addrTxt, name, val=None):
        #validate input
        if len(addrTxt)<=1:
            print('Invalid PLC Address')
            return False
        for plcData in self.plcDatas:
            if plcData.addrTxt==addrTxt:
                print('Repeated PLC Address')
                return False
        seq=len(self.plcDatas)
        d= True if addrTxt[0]=='D' else False
        plcData=PLCData(seq,d,addrTxt,name)
        if d:
            if val:
                self.plc.writeRegister(plcData.addr,val)
            ret=self.plc.readRegister(plcData.addr)
            if ret !=-1:
                plcData.input.setText(str(ret))
            plcData.input.returnPressed.connect(self.writePLC)
        else:
            if val:
                self.plc.writeCoil(plcData.addr,val)
            ret=self.plc.readCoil(plcData.addr)
            if ret!=-1:
                plcData.input.setChecked(ret)
            plcData.input.stateChanged.connect(self.writePLC)
        self.plcDatas.append(weakref.proxy(plcData))
        row=seq+2
        self.grid.addWidget(plcData.addrLabel, row,0,1,1)
        self.grid.addWidget(plcData.nameLabel, row,1,1,1)
        self.grid.addWidget(plcData.input, row,2,1,1)
        self.grid.addWidget(plcData.btn_delete, row,3,1,1)
        plcData.btn_delete.clicked.connect(self.deleteRow)
        return True

    def loadHistory(self):
        for addrTxt, name, val in CFG.PLC_CONFIG:
            self.loadRow(addrTxt, name, val)

    def deleteRow(self):
        plcData=self.sender().upper
        print(plcData.seq)
        plcData.addrLabel.deleteLater()
        plcData.nameLabel.deleteLater()
        plcData.input.deleteLater()
        plcData.btn_delete.deleteLater()
        CFG.PLC_CONFIG.pop(plcData.seq)
        CFG_Handler.set('PLC_CONFIG',CFG.PLC_CONFIG)
        self.plcDatas.remove(plcData)
        for i in range(plcData.seq,len(self.plcDatas)):
            row=i+2
            self.grid.addWidget(self.plcDatas[i].addrLabel, row,0,1,1)
            self.grid.addWidget(self.plcDatas[i].nameLabel, row,1,1,1)
            self.grid.addWidget(self.plcDatas[i].input, row,2,1,1)
            self.grid.addWidget(self.plcDatas[i].btn_delete, row,3,1,1)
            self.plcDatas[i].seq-=1

    def writePLC(self):
        d=self.sender().upper.d
        addr=self.sender().upper.addr
        seq=self.sender().upper.seq
        if d:
            value = self.sender().val
            self.plc.writeRegister(addr,value)
        else:
            value = self.sender().isChecked()
            self.plc.writeCoil(addr,value) 
        CFG.PLC_CONFIG[seq][2]=value
        CFG_Handler.set('PLC_CONFIG',CFG.PLC_CONFIG)
        
class RejectCountWidget(QWidget):
    resetRejectCount=pyqtSignal(int)
    def __init__(self, parent,side):
        super().__init__(parent)
        self.side=side
        hLayout=QHBoxLayout()
        hLayout.setContentsMargins(0,0,0,0)
        self.setLayout(hLayout)
        vLayout=QVBoxLayout()
        vLayout.setContentsMargins(0,0,0,0)
        hLayout.addLayout(vLayout)
        self.reworkCountLbl=QLabel("Rework:0")
        self.disposeCountLbl=QLabel("Dispose:0")
        vLayout.addWidget(self.reworkCountLbl)
        vLayout.addWidget(self.disposeCountLbl)
        self.resetBtn=QPushButton()
        hLayout.addWidget(self.resetBtn)
        self.resetBtn.clicked.connect(self.reset)
        self.resetBtn.setIcon(QIcon(':/utils/icons/cleanup.png'))
        self.resetBtn.setIconSize(QSize(26,26))
        self.resetBtn.setFixedSize(QSize(33,33))
    def reset(self):
        self.reworkCountLbl.setText("Rework:0")
        self.disposeCountLbl.setText("Dispose:0")
        self.resetRejectCount.emit(self.side)
        
class InfoDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent, flags=Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
        self.parent=parent
        self.resize(600,620)
        self.setWindowTitle("Rejection")
        self.sideLabels=[QLabel(f"{SIDE_SHORT[i]} Not Installed") for i in range(4)]
        self.rejectCountWidgets=[RejectCountWidget(self,i) for i in range(4)]
        vLayout=QVBoxLayout()
        self.setLayout(vLayout)
        hLayout0 = QHBoxLayout()
        hLayout1 = QHBoxLayout()
        hLayout2 = QHBoxLayout()
        hLayout3 = QHBoxLayout()
        for rcw in self.rejectCountWidgets:
            hLayout0.addWidget(rcw)
        for i in range(4):
            hLayout1.addWidget(self.sideLabels[i])

        self.purgingDisplays=[QListWidget(self) for _ in range(4)]
        for pd in self.purgingDisplays:
            pd.setMinimumWidth(100)
            hLayout2.addWidget(pd)

        self.listToPurge=[QListWidget(self) for _ in range(4)]
        for lp in self.listToPurge:
            lp.setMaximumHeight(100)
            lp.setMinimumWidth(100)
            hLayout3.addWidget(lp)
        vLayout.addLayout(hLayout0)
        vLayout.addLayout(hLayout1)
        vLayout.addLayout(hLayout2)
        vLayout.addLayout(hLayout3)

class ImgDialog(QDialog):   #trace windows
    def __init__(self, parent):
        super().__init__(parent, flags=Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
        self.parent=parent
        self.setWindowTitle("Trace")
        hLayout = QHBoxLayout()
        self.view=PhotoViewer(self)
        if CFG.ROTATE:
            self.view.setMinimumSize(QSize(540, 720))
        else:
            self.view.setMinimumSize(QSize(960, 720))
        hLayout.addWidget(self.view)
        self.traceList=QListWidget(self)
        self.traceList.setMinimumWidth(360)
        self.traceList.clear()
        vLayout=QVBoxLayout()
        vLayout.addWidget(self.traceList)
        self.classButtonGrid=QGridLayout()
        vLayout.addLayout(self.classButtonGrid)
        hLayout.addLayout(vLayout)
        self.setStyleSheet("""QPushButton {border: 2px solid #8f8f91; 
            border-radius: 3px; 
            background-color: #70fff1;
            min-width: 60px;}
            QPushButton:pressed {
            background-color: #5ed3e0;
            }
            QPushButton:flat {
            border: none; /* no border for a flat push button */
            }
            QPushButton:default {
            background-color: #61ddff;
            border-color: navy; /* make the default button prominent */
            }
            QPushButton#button_label {
            background-color: #d1cede;
            }
            """)

        for i in range(CLASS_NUM-1):
            classButton=IndexedButton(i+1,CLASSES[i+1])
            classButton.clicked.connect(self.filterClass)
            classButton.setMinimumHeight(25)
            classButton.setFont(QFont('Arial', 10))
            self.classButtonGrid.addWidget(classButton,i/4,i%4)
        labelButton=QPushButton("Label")
        labelButton.clicked.connect(self.directOpenLabelWindow)
        labelButton.setObjectName("button_label")
        labelButton.setFont(QFont('Arial', 12))
        labelButton.setIcon(QIcon(':/utils/icons/create.png'))
        labelButton.setIconSize(QSize(33,33))

        self.classButtonGrid.addWidget(labelButton,3,0,2,2)
        self.setLayout(hLayout)

        self.traceList.currentItemChanged.connect(self.setImg)
        #self.hide()

    def directOpenLabelWindow(self):
        if self.traceList.currentItem():
            imgPath=self.traceList.currentItem().data(32).replace(os.sep, '/')

        labelWindow=LabelWindow(parent=self,defaultImg=imgPath)
        labelWindow.show()
        print("Open Label Window")

    def setTraceList(self,itemList,text=None):
        self.traceList.clear()
        #self.traceList.setCurrentRow(1)
        for item in itemList:
            self.traceList.addItem(item.clone())
        if text:
            thisItem=self.traceList.findItems(text,Qt.MatchContains)# 1 for MatchContains
            self.traceList.setCurrentItem(thisItem[0])
    def filterClass(self):
        seq=self.sender().seq
        clsStr=CLASSES[seq]
        matchedItems=self.parent.ui.listWidget.findItems(clsStr,Qt.MatchContains)
        if matchedItems:
            self.setTraceList(matchedItems)
            self.traceList.setCurrentRow(0)
            self.show()

    def setImg(self, current, previews):
        if current:
            imgPath=current.data(32)
            self.view.setPhoto(QPixmap(imgPath))
            # if CFG.ROTATE:
            #     self.view.setPhoto(QPixmap(imgPath).scaled(720,960))
            # else:
            #     self.view.setPhoto(QPixmap(imgPath).scaled(960,720))

class PhotoViewer(QGraphicsView):

    def __init__(self, parent):
        super(PhotoViewer, self).__init__(parent)
        self._zoom = 0
        self._empty = True
        self._scene = QGraphicsScene(self)
        self._photo = QGraphicsPixmapItem()
        self._scene.addItem(self._photo)
        self.setScene(self._scene)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.AnchorUnderMouse)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setBackgroundBrush(QBrush(QColor(30, 30, 30)))
        self.setFrameShape(QFrame.NoFrame)

    def hasPhoto(self):
        return not self._empty

    def fitInView(self, scale=True):
        rect = QRectF(self._photo.pixmap().rect())
        if not rect.isNull():
            self.setSceneRect(rect)
            if self.hasPhoto():
                unity = self.transform().mapRect(QRectF(0, 0, 1, 1))
                self.scale(1 / unity.width(), 1 / unity.height())
                viewrect = self.viewport().rect()
                scenerect = self.transform().mapRect(rect)
                factor = min(viewrect.width() / scenerect.width(),
                             viewrect.height() / scenerect.height())
                self.scale(factor, factor)
            self._zoom = 0

    def setPhoto(self, pixmap=None):
        self._zoom = 0
        if pixmap and not pixmap.isNull():
            self._empty = False
            self.setDragMode(QGraphicsView.ScrollHandDrag)
            self._photo.setPixmap(pixmap)
        else:
            self._empty = True
            self.setDragMode(QGraphicsView.NoDrag)
            self._photo.setPixmap(QPixmap())
        #self.fitInView()

    def wheelEvent(self, event):
        if self.hasPhoto():
            if event.angleDelta().y() > 0:
                factor = 1.25
                self._zoom += 1
            else:
                factor = 0.8
                self._zoom -= 1
            if self._zoom > 0:
                self.scale(factor, factor)
            elif self._zoom == 0:
                self.fitInView()
            else:
                self._zoom = 0

    def mousePressEvent(self, event):
        super(PhotoViewer, self).mousePressEvent(event)

class FormerMarkingWidget(QWidget):
    def __init__(self, maxDist=299, parent=None):
        super().__init__(parent=parent)
        self.grid=QGridLayout(self)
        self.setLayout(self.grid)
        self.text_distances=[]
        self.testButtons=[]
        self.text_offsets=[]
        self.grid.addWidget(QLabel("Side"),0,0,1,1)
        self.grid.addWidget(QLabel("Distance"),1,0,1,1)
        self.grid.addWidget(QLabel("Mark"),2,0,1,1)
        self.grid.addWidget(QLabel("Offset"),3,0,1,1)
        for i in range(4):
            self.grid.addWidget(QLabel(SIDE_NAME[i]),0,i+1,1,1)
            text_distance=IndexedLELI(max=maxDist, hint="Distance", idx=i)
            self.grid.addWidget(text_distance,1,i+1,1,1)
            self.text_distances.append(text_distance)
            testButton=IndexedButton(i,"Test")
            self.grid.addWidget(testButton,2,i+1,1,1)
            self.testButtons.append(testButton)
            text_offset=IndexedLELI(max=maxDist, hint="Offset", idx=i)
            self.grid.addWidget(text_offset,3,i+1,1,1)
            self.text_offsets.append(text_offset)


class PeripheralWidget(QWidget):
    def __init__(self, name, addr, idx , maxDist=299,parent=None):
        super().__init__(parent=parent)
        self.name=name
        self.addr=addr
        self.idx=idx
        self.grid=QGridLayout(self)
        self.grid.setContentsMargins(0,0,0,10)
        self.setLayout(self.grid)
        self.grid.addWidget(QLabel(f"{self.name} (M{self.addr}~M{self.addr+3}):"),0,0,1,2)
        self.text_distances=[]
        for i in range(4):
            text_distance=IndexedLELI(max=maxDist, hint=SIDE_SHORT[i], idx=i)
            #text_distance.returnPressed.connect(self.setFursDistance)
            #text_distance.setText(str(DISTANCES[i]))
            self.grid.addWidget(text_distance,1,i,1,1)
            self.text_distances.append(text_distance)
        self.checkBoxes=[]
        for i in range(CLASS_NUM-1):
            checkBox=IndexedCheckBox(i+1,CLASSES[i+1],self)
            # if(CLSES & 1<<i+1):
            #     checkBox.setChecked(True)
            #checkBox.stateChanged.connect(self.setClassFurs)
            self.grid.addWidget(checkBox,i/4+2,i%4)
            self.checkBoxes.append(checkBox)

def forceExit(exctype, value, tb):
    logger.critical(f'Uncaught Exception | {format_exception(exctype, value, tb)}')
    sys.exit(-1)
    #os._exit(-1)

if __name__ == "__main__":
    freeze_support()
    sys._excepthook = sys.excepthook 
    def exception_hook(exctype, value, traceback):
        print("Exception Hook")
        print(exctype, value, traceback)
        sys._excepthook(exctype, value, traceback) 
        sys.exit(1) 
    sys.excepthook = exception_hook 
    mainP=psutil.Process()
    mainP.nice(psutil.HIGH_PRIORITY_CLASS)
    if CFG.DUAL_BOOT:
        try:
            gpus = tf.config.experimental.list_physical_devices('GPU')
            tf.config.experimental.set_virtual_device_configuration(gpus[0],[tf.config.experimental.VirtualDeviceConfiguration(memory_limit=3096)])
        except Exception as e:
            logger.critical(f'Nvidea GPU not found. {e}')
            sys.exit(-1)
    else:
        instance=singleinstance()
        if instance.alreadyrunning():
            logger.critical("FATAL: Another Instance Of AIVC.exe Is Running.")
            sys.exit(-1)
        sys.excepthook = forceExit
    policy=mixed_precision.Policy('mixed_float16')
    mixed_precision.set_policy(policy)

    app = QApplication(sys.argv)
    screenWidth = app.desktop().screenGeometry().width()
    screenHeight = app.desktop().screenGeometry().height()
    saveStatus(1)#Indicate AIVC On
    SMALL_SCREEN = screenWidth <1800 #1920/1366/1024
    NARROW_SCREEN = (screenWidth/screenHeight)<1.5 #1.77/1.33
    window = MainWindow()
    window.show()
    ret=app.exec_()
    if not CFG.DUAL_BOOT:
        try:
            instance.remove()
        except Exception as e:
            logger.warning(f"Instance Removed: {e}")
    sys.exit(ret)