import plcLib
from collections import deque
import time
from pymodbus.client.sync import ModbusTcpClient
import datetime
from multiprocessing import Process, Queue, Value, freeze_support
import os
class PLC_Process(Process):
	def __init__(self,register):
		super().__init__()
		self.register=register
		self.quit=Value('i',0)
		self.daemon=True
		self.start()
	def run(self):
		print("run")
		self.prevTime=time.time()
		self.plc=plcLib.PLC("10.32.11.2")
		i=0
		while self.quit.value==0:
			t=time.time()
			value=self.plc.readRegister(self.register)
			totalTime=time.time()-self.prevTime
			if totalTime>0.1:
				debug(f"{self.register} | {value} | used:{time.time()-t} | total:{totalTime}")
			self.prevTime=time.time()
			self.plc.writeRegister(self.register,i)
			time.sleep(0.0003)
			i+=1
			if i >1000:
				i=0
				print(self.register)
		print(f"{self.register} Process Ended")


def debug(string):
	timenow = datetime.datetime.now().strftime("%a %m/%d/%Y, %H:%M:%S")
	if not os.path.exists('logs/'):
		os.mkdir('logs/')
	with open('logs/debug.txt', mode='a') as out_file:
		out_file.write(timenow + '\t | ' + string + '\n')
	print(f"Logged: {string}")

if __name__=="__main__":
	debug("Started")
	processes=[PLC_Process(i+900) for i in range(10)]
	time.sleep(28800)
	debug("Closing processes")
	for p in processes:
		p.quit.value=1
	time.sleep(2)
	debug("Closed program")
	