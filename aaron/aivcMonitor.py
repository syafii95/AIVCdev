import json
import time
import sys
import os
import psutil    
import datetime
from signal import signal, SIGINT
from utils.log import log
import shutil
from glob import glob
from pathlib import Path

#Status 0:Clean Closed 1:Not Clean Closed 2:Pending Update
STATUS_FILE='aivcMonitor/status'
SECOND_TO_CHECK=2

class AIVC_Monitor():
	def __init__(self):
		self.directory=Path(__file__).parent.parent.absolute()
		signal(SIGINT, self.handler)
		log('AIVC Monitor Started')
		self.monitor()
	def handler(self, signal_received, frame):
		# Handle any cleanup here
		print('SIGINT or CTRL-C detected. Exiting gracefully')
		log('AIVC Monitor Closed')
		time.sleep(1)
		sys.exit(0)

	def loadStatus(self):
		try:
			with open(STATUS_FILE,'r') as f:
				self.status=int(f.read())
				print(self.status)
		except FileNotFoundError as e:
			log("AIVC Monitor: Can't Find status File. Closing AIVC Monitor")
			sys.exit(0)
	def monitor(self):
		while True:
			if "AIVC.exe" in (p.name() for p in psutil.process_iter()):
				pass
			else:
				print('AIVC Closed')
				self.loadStatus()
				if self.status==1:#AIVCexe not found but AIVC status is 1 -> AIVC Crashed
					os.startfile("AIVC.exe")
					log('AIVC Restarted After Crash!!!')
				elif self.status==2:#Pending Update
					self.replace()
					os.startfile("AIVC.exe")
					log('AIVC Restarted After Completed Update')
				else:
					print('AIVC Closed By User')
					break
			time.sleep(SECOND_TO_CHECK) #Check AIVCexe every 2 sec
		print('AIVC Monitor Closing in 5 sec')
		time.sleep(5)
		
		#Rename it when AIVC is closed
	def replace(self):
		try:
			with open('config.json','r') as f:
				currentVersion=json.load(f)['VERSION']
		except FileNotFoundError as e:
			log("Cant find config.json. Set previous version to '0.0.0.0'")
			currentVersion='0.0.0.0'
		print(currentVersion)
		filesToUpdate=glob(f"{self.directory}/_toUpdate_*")
		print(filesToUpdate)
		filesToReplace=[f"{self.directory}\\{fn.split('_toUpdate_')[1]}" for fn in filesToUpdate]
		print(filesToReplace)
		print(f'Replacing {filesToReplace} with {filesToUpdate}')
		for fn in filesToReplace:
			if os.path.exists(fn+currentVersion):#If previous update left files of same version, remove it 1st to avoid rename error
				try:
					shutil.rmtree(fn+currentVersion)
				except NotADirectoryError: #is a file
					os.remove(fn+currentVersion)
			try:
				os.rename(fn,fn+currentVersion)
			except FileNotFoundError:
				pass
		for fn in filesToUpdate:
			os.rename(fn,f"{self.directory}\\{fn.split('_toUpdate_')[1]}")

if __name__ == "__main__":
	aivcMonitor=AIVC_Monitor()