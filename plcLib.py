from pymodbus.client.sync import ModbusTcpClient
from pymodbus.exceptions import ConnectionException
import time

import logging
logger=logging.getLogger("Logger")

X0_ADDR=1024				#X0
COIL_START_ADDR=2048		#M0
GLOVE_PRESENT_ADDR=2048		#M0
PLC_RESET_ADDR=2147			#M99
RASM_ANCHOR_ADDR=2052  		#M4
CHAIN_ANCHOR_ADDR=2118  	#M70
PURGER_ADDR=2058			#M10
BYPASSING_ADDR=2438			#M390
REGISTER_START_ADDR=4096	#D0
PURGING_DURATION_ADDR=4096 	#D0
PURGE_INTERVAL_ADDR=4106	#D10
PURGE_DELAY_ADDR=4116		#D20
AIR_PRESSURE_ADDR=4296		#D200
DUAL_BIN_FLAP_ON=2548		#M500
DUAL_BIN_FLAP_OFF=2598		#M550
FLIP_DURATION_ADDR=4146		#D50
FLIP_DELAY_ADDR=4151		#D55
FURS_ADDR=2748				#M700
FURS_ON_TIME=4166			#D70
PERI_ADDR=2948				#M900
ASM_ADDR=2648				#M600
ASM_SHIFT_ADDR=2698			#M650
REJECT_COUNT_ADDR=4796		#D700
TIMER_10MS_ADDR=3076		#M1028
ENCODER_ADDR=3829			#C245 (3784+45) X4 Encoder
ENCODER_LATCH_ADDR=4386		#D290
HIGH_DEFECT_FORMER_ADDR=2998	#M950
FORMER_COUNTING=6096			#D2000

class HalfmoonPLC():
	def __init__(self, ip):
		#ip should be 10.39.0.39
		self.client = ModbusTcpClient(ip)
		self.connected = self.client.connect()
		self.ip=ip

	def connectIP(self, ip):
		if self.connected:
			self.client.close()
			print(f"Modbus TCP connection to Half-moon PLC {self.ip} closed")
		self.ip=ip
		self.client = ModbusTcpClient(ip)
		self.connected = self.client.connect()
		if self.connected:
			print(f"Establised Modbus TCP connection to Half-moon PLC {self.ip}")
		else:
			print("Failed To Connect Half-moon PLC")
		return self.connected
		
	def activateHM(self,side):
		if not self.connected:
			logger.info(f"None Establised Half-moon PLC Connection. Attempt To Reconnect {self.ip}")
			if not self.connectIP(self.ip):
				return -1
		#Connected
		try:
			self.client.write_coil(side, True)
		except Exception as e:
			print(f"Lost PLC Connection. Failed to activate Half-moon. {e}")
			self.connected=False
			return-1

class PLC():
	timeSpan=0
	connected=False
	prev_res=0

	def __init__(self, ip,sensorAddr=0,periSensorAddr=50,periSignalAddr=900,aivcMode=0):
		#ip should be 10.39.0.2
		self.client = ModbusTcpClient(ip)
		self.connected = self.client.connect()
		self.ip=ip
		self.sensorAddr=sensorAddr
		self.periSensorAddr=periSensorAddr
		self.periSignalAddr=periSignalAddr
		self.aivcMode=aivcMode
		self.clearFlags()

	def connectIP(self, ip):
		if self.connected:
			self.client.close()
			print(f"Modbus TCP connection to PLC {self.ip} closed")
		self.ip=ip
		self.client = ModbusTcpClient(ip)
		self.connected = self.client.connect()
		if self.connected:
			print(f"Establised Modbus TCP connection to PLC {self.ip}")
			self.clearFlags()
		else:
			print("Failed To Connect PLC")

		return self.connected

	def clearFlags(self):
		if self.connected:
			self.client.write_coils(COIL_START_ADDR+self.sensorAddr, (0,0,0,0,0,0,0,0,0)) #Clear all flags
			self.client.write_coils(COIL_START_ADDR+self.periSensorAddr, (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)) #Clear all flags
			self.client.write_register(FURS_ON_TIME,5)#half second

	def waitNextGlove(self):
		if self.connected:
			for i in range(500):
				if not self.connected:
					break
				try:
					result = self.client.read_discrete_inputs(GLOVE_PRESENT_ADDR,1)
					if result.bits[0]:
						self.client.write_coil(GLOVE_PRESENT_ADDR, False)
						time.sleep(0.03) ##Displacement delay
						return 1
					time.sleep(0.002)
				except:
					print("Changing PLC IP Address")
			print("Production Line Stopped")
			return 0
		time.sleep(1)
		print("No PLC Connection")
		#Do not wait next glove if no connection, return 0
		return -1
	def readSensors(self,addr=0):
		if not self.connected:
			logger.info(f"None Establised PLC Connection. Attempt To Reconnect {self.ip}")
			if not self.connectIP(self.ip):
				return -1
		#Connected
		try:
			result = self.client.read_discrete_inputs(GLOVE_PRESENT_ADDR+addr,4)
			for side, bit in enumerate(result.bits):
				if bit:
					self.client.write_coil(GLOVE_PRESENT_ADDR+addr+side, False)
			return result.bits
		except Exception as e:
			print(f"Lost PLC Connection. Failed to read sensor. {e}")
			self.connected=False
			return-1
	def readActuatorSensors(self,addr=50):
		if not self.connected:
			return -1
		#Connected
		try:
			result = self.client.read_discrete_inputs(COIL_START_ADDR+addr,16)
			for idx, bit in enumerate(result.bits):
				if bit:
					self.client.write_coil(COIL_START_ADDR+addr+idx, False)
			return result.bits
		except Exception as e:
			print(f"Lost PLC Connection. Failed to read actuator sensor. {e}")
			self.connected=False
			return-1
	def directReadX(self):
		if not self.connected:
			return -1
		#Connected
		try:
			result = self.client.read_discrete_inputs(X0_ADDR+addr,4)
			return result.bits
		except Exception as e:
			print(f"Lost PLC Connection. Failed to read sensor X. {e}")
			self.connected=False
			return-1

	def purgeGlove32(self, line):
		if self.connected:
			#activate purger by setting M1, will be cleared by PLC
			self.client.write_register(PURGER_ADDR+line, 1)
			time.sleep(0.5)
			self.client.write_register(PURGER_ADDR+line, 0)

	def purgeGlove(self, line):
		if self.connected:
			#activate purger by setting M1, will be cleared by PLC
			self.client.write_coil(PURGER_ADDR+line, True)

	def setPurgeDelay_100ms(self,line,val):
		if self.connected:
			self.client.write_register(PURGE_DELAY_ADDR+line,val)

	def setPurgeDuration_100ms(self,line,val):
		if self.connected:
			self.client.write_register(PURGING_DURATION_ADDR+line,val)

	def setPurgeInterval_100ms(self,line,val):
		if self.connected:
			self.client.write_register(PURGE_INTERVAL_ADDR+line,val)

	def setDefaultPurgingTime(self):
		if self.connected:
			for i in range(4):
				self.setPurgeDuration_100ms(i,8)
				self.setPurgeInterval_100ms(i,3)

	def readChainAnchor(self,mode):
		return self.readNClearFlag(CHAIN_ANCHOR_ADDR+mode) #Former Anchor Flag M8

	def readRasmAnchor(self,side):
		return self.readNClearFlag(RASM_ANCHOR_ADDR+side) #RASM Anchor Flag M4~M7

	def readNClearFlag(self, addr):
		if self.connected:
			try:
				result = self.client.read_discrete_inputs(addr,1)
				if result.bits[0]:
					self.client.write_coil(addr, False)
					return 1	#read and cleared
				else:
					return 0	#no flag
			except AttributeError:
				print("Anchor Checking no reading because lost PLC connection")
				return -1
			except ConnectionException:
				self.connected=False
				print(f'Lost PLC connection to {self.ip}')
				return -1
		else:
			return -1	#no connection

	def formerCounting(self,formerID,camSeq):
		if self.connected:
			for ele, data in enumerate(formerID):
				if camSeq == 8:
					#print(f'This is PLC address: {FORMER_COUNTING+ele} | Data write: {data} | Camera Sequence: {camSeq}')
					self.client.write_register(FORMER_COUNTING+ele,data)

				elif camSeq == 9:
					#print(f'This is PLC address: {FORMER_COUNTING+ele+4} | Data write: {data} | Camera Sequence: {camSeq}')
					self.client.write_register(FORMER_COUNTING+ele+4,data)
				
				elif camSeq == 10:
					#print(f'This is PLC address: {FORMER_COUNTING+ele+4} | Data write: {data} | Camera Sequence: {camSeq}')
					self.client.write_register(FORMER_COUNTING+ele+8,data)

				elif camSeq == 11:
					#print(f'This is PLC address: {FORMER_COUNTING+ele+4} | Data write: {data} | Camera Sequence: {camSeq}')
					self.client.write_register(FORMER_COUNTING+ele+12,data)


	def setDualBinFlap(self,side,val):
		if self.connected:
			if val:
				self.client.write_coil(DUAL_BIN_FLAP_ON+side, True)
			else:
				self.client.write_coil(DUAL_BIN_FLAP_OFF+side, True)

	def setFlipDuration_100ms(self,val):
		if self.connected:
			self.client.write_register(FLIP_DURATION_ADDR,val)
	def setFlipDelay_100ms(self,val):
		if self.connected:
			self.client.write_register(FLIP_DELAY_ADDR,val)

	def activateCoilBySide(self,addr,side):
		if self.connected:
			self.client.write_coil(COIL_START_ADDR+addr+side, True)
			
	def setBypass(self,side,bypass):
		if self.connected:
			self.client.write_coil(BYPASSING_ADDR+side, bypass)

	def activatePeri(self,side,peri,periAddr):
		if self.connected:
			self.client.write_coil(COIL_START_ADDR+periAddr+side+peri*10, True)

	def sendFormerMarkingSignal(self,side):
		if self.connected:
			self.client.write_coil(HIGH_DEFECT_FORMER_ADDR+self.aivcMode*10+side, True)
			#self.client.write_coil(HIGH_DEFECT_FORMER_ADDR+self.aivcMode*10+side, False)

	def rejectAsm(self,side,num):#LI:M600~605, RI:M610~615, LO:M620~625, RO:M630~635
		if self.connected:
			self.client.write_coil(ASM_ADDR+side*10+num, True)
			
	def readAirPressures(self):
		if not self.connected:
			return -1
		try:
			result = self.client.read_holding_registers(AIR_PRESSURE_ADDR,4)
			return result.registers
		except Exception as e:
			print(f"Lost PLC Connection. Failed to read air pressure. {e}")
			self.connected=False
			return-1

	def readRejectCount(self):
		if not self.connected:
			return -1
		try:
			result = self.client.read_holding_registers(REJECT_COUNT_ADDR,8)
			return result.registers
		except Exception as e:
			print(f"Lost PLC Connection. Failed to read rejection counting. {e}")
			self.connected=False
			return-1

	def checkPlcReset(self,aiMode):
		if not self.readCoil(97+aiMode): #Reset Coil was LOW / lost PLC connection
			self.writeCoil(97+aiMode,True)
			return True
		else:
			return False
	def resetRejectCount(self,side):
		if self.connected:
			self.client.writeRegisters(REJECT_COUNT_ADDR+side*2,0,2)

	def readEncoder(self,sensor):
		if self.connected:
			try:
				ret=self.client.read_holding_registers(ENCODER_LATCH_ADDR+sensor*2,1)
				if hasattr(ret,'registers'):
					return ret.registers[0]
				else:
					print(f"No Result In Read Register {ret}")
					return -1
			except Exception as e:
				print(f"Lost PLC Connection. Failed to read register {ENCODER_LATCH_ADDR+sensor*2}. {e}")
				self.connected=False
				return-1
		else:
			return -1
	def writeRegister(self,addr,val):
		if self.connected:
			self.client.write_register(REGISTER_START_ADDR+addr,val)
			return True
		else:
			return False
	def writeCoil(self,addr,val):
		if self.connected:
			self.client.write_coil(COIL_START_ADDR+addr,val)
			return True
		else:
			return False
	def readRegister(self,addr,count=1):
		if self.connected:
			try:
				ret=self.client.read_holding_registers(REGISTER_START_ADDR+addr,count)
				if hasattr(ret,'registers'):
					return ret.registers
				else:
					print(f"No Result In Read Register {ret}")
					return -1
			except Exception as e:
				print(f"Lost PLC Connection. Failed to read register {addr}. {e}")
				self.connected=False
				return -1
		else:
			return -1
	def readCoil(self,addr):
		if self.connected:
			try:
				ret = self.client.read_discrete_inputs(COIL_START_ADDR+addr,1)
				return ret.bits[0]
			except Exception as e:
				print(f"Lost PLC Connection. Failed to read coil {addr}. {e}")
				self.connected=False
				return -1
		else:
			return -1

	def close(self):
		self.connected=False
		self.client.close()
		print("Modbus TCP connection closed")