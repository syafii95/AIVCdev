import time
import logging
logger=logging.getLogger("Logger")

class Indexer():
	def __init__(self,offset=0,length=30):
		self.dataDict={}
		self.tempDataDict={}
		self.currentIdx=-1
		self.state=0
		self.totalLen=None
		self.offset=offset
		self.length=length

	def feed(self, data):
		if self.state==0:
			self.currentIdx+=1
			self.tempDataDict[self.currentIdx]=data
		elif self.state==1:
			self.currentIdx+=1
			self.dataDict[self.currentIdx]=data
		else:
			self.currentIdx+=1
			if self.currentIdx>=self.totalLen:#Handle out of bound
				print("Warning: Missed Anchor Reset, currentIdx Out Of Bound, Record Is Skipped Until Next Anchor Reset")
				self.currentIdx=self.totalLen-1
				return
			self.dataDict[self.currentIdx]+=data #Addition for np array 
			#self.dataDict[self.currentIdx][data]+=1 #Customized for defection grid
			#self.dataDict[self.currentIdx]=[self.dataDict[self.currentIdx][i] + data[i] for i in range(len(data))]#Addition for list

	def anchorReached(self):
		if self.state==0:#first trigger
			self.state+=1
			self.numTemp=self.currentIdx+1
		elif self.state==1:#second trigger
			self.state+=1
			self.totalLen=self.currentIdx+1
			for item in self.tempDataDict.items():
				try:
					self.dataDict[self.totalLen+item[0]-self.numTemp]+=item[1]
				except KeyError:
					print('Warning: Extra data before first trigger')
			self.tempDataDict.clear()
		else:
			#Check to make sure the len is consistence
			if self.currentIdx+1 < self.totalLen:
				print('Warning: Trigger number less than total length')
			if self.currentIdx+1 > self.totalLen:
				print('Warning: Trigger number more than total length')
			else:
				print('Completed Loop')
		self.currentIdx=-1

	def get(self):
		if self.state==0:
			return self.tempDataDict[self.currentIdx]
		else:
			return self.dataDict[self.currentIdx]

	def getActualIndex(self):
		if self.state==2:
			return (self.currentIdx+self.offset)%self.totalLen
		else:
			return self.currentIdx

class FixLenIndexer():
	def __init__(self,name,offset=0,totalLen=30):
		self.name=name
		self.dataDict={}
		self.tempDataDict={}
		self.currentIdx=-1
		self.state=0
		self.offset=offset
		self.totalLen=totalLen

	def feed(self, data,index=False):
		if index:
			self.currentIdx=index
		else:
			self.currentIdx+=1
		if self.state==0:
			if self.currentIdx>=self.totalLen:#Handle out of bound
				print(f"Warning: {self.name} Max Len Reached,  No Anchor Detected, Index {self.currentIdx} Reset To 0")
				self.currentIdx=0
			try:
				self.tempDataDict[self.currentIdx]+=data #Increment data
			except KeyError:
				self.tempDataDict[self.currentIdx]=data #Create data if not existed
		else:
			if self.currentIdx>=self.totalLen:#Handle out of bound
				print(f"Warning: {self.name} Max Len Reached,  No Anchor Detected, Index {self.currentIdx} Reset To 0")
				self.currentIdx=0
			try:
				self.dataDict[self.currentIdx]+=data #Increment data
			except KeyError: 
				self.dataDict[self.currentIdx]=data #Create data if not existed

	def anchorReached(self):
		if self.state==0:#first trigger
			t=time.time()
			self.state+=1
			numTemp=self.currentIdx+1
			for item in self.tempDataDict.items():
				self.dataDict[(item[0]-numTemp)%self.totalLen]=item[1]
			self.tempDataDict.clear()
			print(f"{self.name} First Anchor Reached Alignment Took {time.time()-t}s")
		else:
			#Check to make sure the len is consistence
			miscount= self.totalLen - (self.currentIdx+1)
			if miscount==0:
				print(f'{self.name} Completed Loop')
			else:
				logger.warning(f'Warning: {self.name} trigger number less than total length by {miscount}')
		self.currentIdx=-1

	def get(self,index=False):
		if index is False:
			if self.state==0:
				return self.tempDataDict[self.currentIdx]
			else:
				return self.dataDict[self.currentIdx]
		else:
			try:
				if self.state==0:
					return self.tempDataDict[index]
				else:
					return self.dataDict[index]
			except KeyError:
				return False

	def getActualIndex(self):
		if self.state==1:
			return (self.currentIdx+self.offset)%self.totalLen
		else:
			return self.currentIdx

	def getAllData(self):
		if self.state==0:
			return self.tempDataDict
		else:
			return self.dataDict

	def changeLength(self, length):
		self.totalLen=length
		self.tempDataDict.clear()
		self.dataDict.clear()
		self.currentIdx=-1
