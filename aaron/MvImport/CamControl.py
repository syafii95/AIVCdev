import sys
import msvcrt
import numpy as np
import matplotlib.pyplot as plt
import time
import ipaddress

from ctypes import *
sys.path.insert(0, 'MvImport')

from MvImport.MvCameraControl_class import *

class CamControl():

	def __init__(self):
		self.deviceList = MV_CC_DEVICE_INFO_LIST()
		self.tlayerType = MV_GIGE_DEVICE
		self.connected_cams_num=0
		self.camNumsSortedByIp=[]
		self.camNumsSelected=[]
		self.connectedCams=[]
		self.camsToConnect=[]
		self.cams = []
		self.ipMin=0
		self.ipMax=255

	def init(self, device='all'):
		ret = MvCamera.MV_CC_EnumDevices(self.tlayerType, self.deviceList)
		if ret != 0:
			print ("enum devices fail! ret[0x%x]" % ret)
			return -1

		if device != "all":
			self.ipMin, self.ipMax=device

		self.sortCamsByIP()
		for camNum in self.camNumsSortedByIp:
			if camNum in self.camsToConnect:
				self.camNumsSelected.append(camNum)

		# elif isinstance(device, int) and device < self.deviceList.nDeviceNum:
		# 	self.camNumsSelected = self.camNumsSortedByIp[:device]
		# elif isinstance(device, list):
		# 	self.camNumsSelected = [i for i in device if i < self.deviceList.nDeviceNum]
		print ("opening device(s) for: %s" % self.camNumsSelected)
		#for cam in self.cams:
		
		camDetails=[]
		for idx,camSeq in enumerate(self.camNumsSelected):
			cam=Camera(idx)
			self.cams.append(cam)
			cam.seq=idx
			cam.deviceInfo = cast(self.deviceList.pDeviceInfo[camSeq], POINTER(MV_CC_DEVICE_INFO)).contents
			cam.ip=cam.deviceInfo.SpecialInfo.stGigEInfo.nCurrentIp & 0x000000ff
			info=cam.deviceInfo.SpecialInfo.stGigEInfo
			cam.ipString=str(ipaddress.IPv4Address(cam.deviceInfo.SpecialInfo.stGigEInfo.nCurrentIp))
			camDetails.append(f"{cam.ipString}\n{bytes(info.chUserDefinedName).decode('ascii')}\n{bytes(info.chModelName).decode('ascii')}")#Get more details
			print(f'Cam IP: {cam.ipString}')
			ret = cam.open()
			if ret != 0:
				print(f'Failed to access cam. {ret:x}')
				continue
			self.connected_cams_num+=1
			self.connectedCams.append(idx)
			
		return [self.connectedCams,camDetails]


	def __del__(self):
		print("Camcontrol Destroyed")
		for cam in self.cams:
			cam.ret = cam.mvCam.MV_CC_StopGrabbing()

			if cam.ret != 0:
				print(f"Cam{cam.seq} stop grabbing fail! {cam.ret:x}")
			else:
				cam.startGrabbing=False
			
			# ch:关闭设备 | Close device
			cam.ret = cam.mvCam.MV_CC_CloseDevice()
			if cam.ret != 0:
				print(f"Cam{cam.seq} close device fail! {cam.ret:x}")
			else:
				print ("device %s closed" % cam.seq)
				cam.isOpen=False

			# ch:销毁句柄 | Destroy handle
			cam.ret = cam.mvCam.MV_CC_DestroyHandle()
			if cam.ret != 0:
				print(f"Cam{cam.seq} destroy handle fail! {cam.ret:x}")
			else:
				cam.hasHandle=False

	def capture(self,camNum):
		t = time.time()
		if camNum in self.connectedCams:
			cam=self.cams[camNum]
			if not cam.alive:
				print('Try to reconnect')
				ret=cam.open()
				if ret == 0:
					print(f'Successfully reconnected cam {cam.seq}')
				else:
					print(f'Failed to reconnected cam {cam.seq}')
					return ret, None, cam.ipString

			ret = cam.mvCam.MV_CC_SetCommandValue("TriggerSoftware")
			if ret!=0:
				print("Camera software trigger fail!")
				cam.alive=False
				return ret, None, cam.ipString
			ret = cam.mvCam.MV_CC_GetOneFrameTimeout(byref(cam.data_buf), cam.nPayloadSize, cam.frameInfo, 1000)
			if ret != 0:
				print ("no data[0x%x]" % ret)
				cam.closeCam()
				cam.alive=False
				return ret, None, cam.ipString
			ret = cam.mvCam.MV_CC_ConvertPixelType(cam.stConvertParam)
			if ret != 0:
				print("convert pixel fail! ret[0x%x]" % ret)
				cam.closeCam()
				cam.alive=False
				return ret, None, cam.ipString
			cdll.msvcrt.memcpy(byref(cam.img_buff), cam.stConvertParam.pDstBuffer, cam.nConvertSize)

			numArray = self.colorNumpy(cam.img_buff,cam.frameInfo.nWidth,cam.frameInfo.nHeight)
			if numArray.shape[0]==0:
				print('empty frame')
				cam.alive=False
			duration=time.time()-t
			if duration > 0.1:
				print(f'Warning: Camera Slow Response: {duration}s. Please Check LAN Cable Connection And Resulting Frame Rate')#log this instead
			return ret, numArray, cam.ipString
		else:
			print(f"Invalid Cam Num {camNum}")
			return -1, None, cam.ipString

	def colorNumpy(self,data,nWidth,nHeight):
		t=time.time()
		data_ = np.frombuffer(data, count=int(nWidth*nHeight*3), dtype=np.uint8, offset=0)
		data_r = data_[0:nWidth*nHeight*3:3]
		data_g = data_[1:nWidth*nHeight*3:3]
		data_b = data_[2:nWidth*nHeight*3:3]

		data_r_arr = data_r.reshape(nHeight, nWidth)
		data_g_arr = data_g.reshape(nHeight, nWidth)
		data_b_arr = data_b.reshape(nHeight, nWidth)
		numArray = np.zeros([nHeight, nWidth, 3],"uint8")

		numArray[:, :, 0] = data_r_arr
		numArray[:, :, 1] = data_g_arr
		numArray[:, :, 2] = data_b_arr
		#print(f"colorNumpy {time.time()-t}")
		return numArray

	def getCamsNum(self):
		return self.connected_cams_num

	def enum_device(self):
		for i in range(self.deviceList.nDeviceNum):
			print(i)
			mvcc_dev_info = cast(self.deviceList.pDeviceInfo[i], POINTER(MV_CC_DEVICE_INFO)).contents

			print ("\ngige device: [%d]" % i)
			strModeName = ""
			for per in mvcc_dev_info.SpecialInfo.stGigEInfo.chModelName:
				strModeName = strModeName + chr(per)
			print ("device model name: %s" % strModeName)

			nip1 = ((mvcc_dev_info.SpecialInfo.stGigEInfo.nCurrentIp & 0xff000000) >> 24)
			nip2 = ((mvcc_dev_info.SpecialInfo.stGigEInfo.nCurrentIp & 0x00ff0000) >> 16)
			nip3 = ((mvcc_dev_info.SpecialInfo.stGigEInfo.nCurrentIp & 0x0000ff00) >> 8)
			nip4 = (mvcc_dev_info.SpecialInfo.stGigEInfo.nCurrentIp & 0x000000ff)
			print ("current ip: %d.%d.%d.%d\n" % (nip1, nip2, nip3, nip4))

	def sortCamsByIP(self):
		ipList=[]
		for i in range(self.deviceList.nDeviceNum):
			mvcc_dev_info = cast(self.deviceList.pDeviceInfo[i], POINTER(MV_CC_DEVICE_INFO)).contents
			ip=mvcc_dev_info.SpecialInfo.stGigEInfo.nCurrentIp & 0x000000ff
			ipList.append(ip)
			if(ip>=self.ipMin and ip<=self.ipMax):
				print('Added Cam IP '+str(ip))
				self.camsToConnect.append(i)
			else:
				print('Ignored Cam IP '+str(ip))
		print(ipList)
		self.camNumsSortedByIp=sorted(range(len(ipList)), key=lambda k: ipList[k])
		print(self.camNumsSortedByIp)

class Camera():
	def __init__(self,seq):
		self.mvCam=MvCamera()
		self.seq=seq
		self.ip=None
		self.ipString=''
		self.isOpen=False
		self.hasHandle=False
		self.successSetPacketSize=False
		self.successGetPacketSize=False
		self.successGetPayLoadSize=False
		self.startGrabbing=False

		self.data_buf=None
		self.nPayloadSize=None
		self.deviceInfo=None
		self.frameInfo=None
		self.ret=None
		self.nPacketSize=None
		self.stParam=None

		self.stConvertParam=None
		self.img_buff=None
		self.nConvertSize=None

		self.alive=False

	def open(self):
		self.ret = self.mvCam.MV_CC_CreateHandle(self.deviceInfo)
		if self.ret != 0:
			self.mvCam.MV_CC_DestroyHandle()
			print ("create handle fail! ret[0x%x]" % self.ret)
			return self.ret
		else:
			self.hasHandle=True

		self.ret = self.mvCam.MV_CC_OpenDevice(MV_ACCESS_ExclusiveWithSwitch, 0)
		if self.ret != 0:
			print(f"open camera {self.seq} fail! ret[0x{self.ret:x}]")
			return self.ret
		else:
			self.isOpen=True
			print ("open camera %s successfully!" % self.seq)

		# ch:探测网络最佳包大小(只对GigE相机有效) | en:Detection network optimal package size(It only works for the GigE camera)
		if self.deviceInfo.nTLayerType == MV_GIGE_DEVICE:
			self.nPacketSize =self.mvCam.MV_CC_GetOptimalPacketSize()
			if int(self.nPacketSize) > 0:
				self.successGetPacketSize=True
				self.ret = self.mvCam.MV_CC_SetIntValue("GevSCPSPacketSize",self.nPacketSize)
				if self.ret != 0:
					print ("Warning: Set Packet Size fail! ret[0x%x]" % self.ret)
				else:
					self.successSetPacketSize=True
			else:
				print ("Warning: Get Packet Size fail! ret[0x%x]" % self.nPacketSize)


			self.mvCam.MV_GIGE_SetResend(1,nMaxResendPercent=100,nResendTimeout=20)
			if MV_OK != self.ret:
				print ("set Resend fail! ret [0x%x]" % self.ret)

		#ch:获取数据包大小 | en:Get payload size
		self.stParam = MVCC_INTVALUE()
		memset(byref(self.stParam), 0, sizeof(MVCC_INTVALUE))

		self.ret = self.mvCam.MV_CC_GetIntValue("PayloadSize", self.stParam)
		if self.ret != 0:
			print ("get payload size fail! ret[0x%x]" % self.ret)
		else:
			self.successGetPayLoadSize=True
		#@#@#
		self.ret = self.mvCam.MV_CC_SetEnumValue("TriggerMode", MV_TRIGGER_MODE_ON)
		if self.ret != 0:
			print ("set trigger mode fail! ret[0x%x]" % self.ret)
		self.ret = self.mvCam.MV_CC_SetEnumValue("AcquisitionMode", MV_ACQ_MODE_CONTINUOUS) ##TheImagingSource dont hv continuous mode
		if self.ret != 0:
			print("set continuous acquisition fail! (TheImagingSource doesn't hv continous mode)")
		self.ret = self.mvCam.MV_CC_SetEnumValue("TriggerSource", MV_TRIGGER_SOURCE_SOFTWARE)
		if self.ret != 0:
			print("set software trigger source fail!")
		self.nPayloadSize = self.stParam.nCurValue
		self.ret = self.mvCam.MV_CC_StartGrabbing()

		self.ret = self.mvCam.MV_CC_SetCommandValue("TriggerSoftware")
		if self.ret!=0:
			print("Camera software trigger fail!")
		if self.ret != 0:
			print ("start grabbing fail! ret[0x%x]" % self.ret)
		else:
			self.startGrabbing=True

		self.frameInfo = MV_FRAME_OUT_INFO_EX()
		memset(byref(self.frameInfo), 0, sizeof(self.frameInfo))
		self.data_buf = (c_ubyte * self.nPayloadSize)()

		self.ret=self.mvCam.MV_CC_GetOneFrameTimeout(byref(self.data_buf), self.nPayloadSize, self.frameInfo, 1000)##Take a frame to get frame info
		if self.ret !=0:
			print(f"Failed to get 1st frame {self.seq} {self.ret:x}")
		n_save_image_size = self.frameInfo.nWidth * self.frameInfo.nHeight * 10 + 2048
		self.img_buff = (c_ubyte * n_save_image_size)()
		stConvertParam = MV_CC_PIXEL_CONVERT_PARAM()
		memset(byref(stConvertParam), 0, sizeof(stConvertParam))
		stConvertParam.nWidth = self.frameInfo.nWidth
		stConvertParam.nHeight = self.frameInfo.nHeight
		stConvertParam.pSrcData = self.data_buf
		stConvertParam.nSrcDataLen = self.frameInfo.nFrameLen
		stConvertParam.enSrcPixelType = self.frameInfo.enPixelType
		self.nConvertSize = self.frameInfo.nWidth * self.frameInfo.nHeight * 10
		stConvertParam.enDstPixelType = PixelType_Gvsp_RGB8_Packed
		stConvertParam.pDstBuffer = (c_ubyte * self.nConvertSize)()
		stConvertParam.nDstBufferSize = self.nConvertSize
		self.stConvertParam=stConvertParam
		self.alive=True
		return self.ret


	def closeCam(self):
		self.ret = self.mvCam.MV_CC_StopGrabbing()
		if self.ret != 0:
			print("stop grabbing fail! ret[0x%x]" % self.ret)
			#raise Exception("stop grabbing fail! ret[0x%x]" % self.rets[idx])
		
		# ch:关闭设备 | Close device
		self.ret = self.mvCam.MV_CC_CloseDevice()
		print ("device %s closed" % self.seq)
		if self.ret != 0:
			print("close device fail! ret[0x%x]" % self.ret)
			#raise Exception("close device fail! ret[0x%x]" % self.rets[idx])

		# ch:销毁句柄 | Destroy handle
		self.ret= self.mvCam.MV_CC_DestroyHandle()
		if self.ret!= 0:
			print("destroy handle fail! ret[0x%x]" % self.ret)
			#raise Exception("destroy handle fail! ret[0x%x]" % self.rets[idx])
		self.alive=False