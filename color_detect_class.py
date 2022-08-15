import cv2
import numpy as np

class ColorDetect():
	def __init__(self):
		with open('color_mask_threshold.txt','r') as f:
			lines = f.readlines()
		thres = []
		for line in lines:
			thres.append([int(i) for i in line[1:-2].split()])

		self.lower = np.array(thres[0])
		self.upper = np.array(thres[1])


	def detect(self, img):
		try:
			imgHsv = cv2.cvtColor(img,cv2.COLOR_RGB2HSV)
			mask = cv2.inRange(imgHsv,self.lower,self.upper)
			detected = False
			contours,hierarchy = cv2.findContours(mask,cv2.RETR_EXTERNAL,cv2.CHAIN_APPROX_NONE)
			for cnt in contours:
				area = cv2.contourArea(cnt)
				if area>500:
					detected = True
			return detected
		except:
			print("Color Detect No Img")
			return False
		