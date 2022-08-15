import pyodbc 
import json
import datetime
import os
from utils.log import log
import logging
recorder=logging.getLogger("Record")
logger=logging.getLogger("Logger")


SQL_MAIN_IP='172.16.10.84'
SQL_BACKUP_IP='10.39.0.179'

SIDE_SHORT=["LI","RI","LO","RO"]

class SQLConnect():
	def __init__(self,dataNames):
		self.dataNames=dataNames
		self.connection=False
		self.usingBackup=False
		self.secondTry=False
		self.connectServer()

	def push(self, factory, line, side, startDate, startTime, endDate, endTime, status, data):
		if self.connection==False:
			print(f"None Established SQL Connection, Trying To Reconnect Main SQL Server {SQL_MAIN_IP}")
			if self.connectServer() == False:
				print("Failed To Connect Both Main And Backup SQL Server. Abort Pushing Data")
				return -1
		elif self.usingBackup:
			print(f'Try Reconnect Main SQL Server {SQL_MAIN_IP}')
			if self.connectServer() == False:
				print("Failed To Connect Both Main And Backup SQL Server. Abort Pushing Data")
				return -1

		jsonData="{"
		for idx, val in enumerate(data):
			jsonData+=f"\"{self.dataNames[idx]}\":\"{val}\", "
		jsonData=jsonData[:-2]
		jsonData+="}"
		# factoryNum=int(factory[1:])
		# factory=f'F{factoryNum:02d}'#SQL Server Only Accept Two Digit Factory Name
		query=f"EXECUTE [dbo].[SPFactAIVCv2Insert_JSON] @StartDate=\'{startDate}\', @StartTime=\'{startTime}\', @EndDate=\'{endDate}\', @EndTime=\'{endTime}\', @Plant=\'{factory}\', @ProductionLine=\'{line}\', @ProductionLineStatus=\'{status}\', @ProductionLineRow=\'{SIDE_SHORT[side]}\', @Class_Value_JSON=\'{jsonData}\'"
		#p@query=f"EXECUTE [dbo].[SPFactAIVCv2Insert_JSON] @Plant=\'{factory}\', @ProductionLine=\'{line}\', @ProductionLineRow=\'{SIDE_SHORT[side]}\', @FullDate=\'{date}\', @Time=\'{time}\', @Class_Value_JSON=\'{jsonData}\'"
		recorder.info(query)
		try:
			self.cursor.execute(query)
			self.cnxn.commit()
			recorder.info("Sucessfully uploaded data to SQL Database")
		except Exception as e :
			self.connection=False
			if self.secondTry: #Second try already, not connection issue (most likely factory name issue). Abort pushing.
				self.secondTry=False
				return -1
			self.secondTry=True
			recorder.warning(f"Failed Pushing Data To SQL Server {SQL_BACKUP_IP if self.usingBackup else SQL_MAIN_IP}: {e}")
			if self.push(factory, line, side, startDate, startTime, endDate, endTime, status, data) == -1:
				return -1
		return 0

	def connectServer(self):
		try:
			print("Connecting SQL Server")
			SQL_ATTR_CONNECTION_TIMEOUT = 113
			self.cnxn = pyodbc.connect(f"DRIVER={{ODBC Driver 17 for SQL Server}}; SERVER={{{SQL_MAIN_IP}}}; DATABASE=TopGloveAIVC_DB; Persist Security Info=True; UID=TGAIVC_R; PWD=100%Intelligent",timeout=3,attrs_before={SQL_ATTR_CONNECTION_TIMEOUT : 3})
			#n@self.cnxn = pyodbc.connect(f"Data Source={SQL_MAIN_IP};Initial Catalog=TopGloveAIVC_DB;Persist Security Info=True;User ID=TGAIVC_R;Password=100%Intelligent",timeout=3,attrs_before={SQL_ATTR_CONNECTION_TIMEOUT : 3})
			self.cnxn.timeout=3
			self.cursor = self.cnxn.cursor()
			self.usingBackup=False
		except (pyodbc.OperationalError, pyodbc.InterfaceError)as e:
			logger.warning(f"Failed To Connect Main SQL Server {SQL_MAIN_IP}: {e}\nTry Connecting Backup Server {SQL_BACKUP_IP}")
			try:
				self.cnxn = pyodbc.connect(f"DRIVER={{ODBC Driver 17 for SQL Server}}; SERVER={{{SQL_BACKUP_IP}}}; DATABASE=TopGloveAIVC_DB; Persist Security Info=True; UID=TGAIVC_R; PWD=100%Intelligent",timeout=3,attrs_before={SQL_ATTR_CONNECTION_TIMEOUT : 3})
				#n@self.cnxn = pyodbc.connect(f"Data Source={SQL_BACKUP_IP};Initial Catalog=TopGloveAIVC_DB;Persist Security Info=True;User ID=TGAIVC_R;Password=100%Intelligent",timeout=3,attrs_before={SQL_ATTR_CONNECTION_TIMEOUT : 3})
				self.cnxn.timeout=3
				self.cursor = self.cnxn.cursor()
				self.usingBackup=True
			#except pyodbc.OperationalError as e:
			except Exception as e:
				logger.warning(f"Failed To Connect BACKUP SQL Server {SQL_BACKUP_IP}: {e}")
				self.connection=False
				return False
		self.connection=True
		print(f"Established {'Backup' if self.usingBackup else 'Main'} SQL Server Connection")
		return True

	# def pull(self):
	# 	query="SELECT TOP (1000) [PlantKey],[ProductionLineKey],[ProductionLineRowKey],[ClassKey],[DateKey],[TimeKey],[Value] FROM [TopGloveAIVC_DB].[dbo].[FactAIVC]"
	# 	print(query)
	# 	self.cursor.execute(query)
	# 	row = self.cursor.fetchone() 
	# 	while row: 
	# 	    print([a for a in row])
	# 	    row = self.cursor.fetchone()

#sqlConnect=SQLConnect()
#sqlConnect.pull()
#sqlConnect.push("F40","L11D","LO","2020-09-30","20:59:21",data)
#sqlConnect.insert()