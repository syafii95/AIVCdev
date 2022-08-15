import os
import random
w=1280
h=960
train_files = []
test_files = []
os.chdir(os.path.join("dataset","F20nF40Relabel"))
for filename in os.listdir(os.getcwd()):
	if filename.endswith(".jpg") or filename.endswith(".png"):
		imgPath=os.getcwd() +'\\'+ filename
		boundingBoxStr=imgPath
		txtPath=imgPath[:-4]+".txt"
		with open(txtPath,'r') as f:
			for line in f.read().split('\n'):
				if line:
					data = list(map(float, line.split())) 
					c, xc, yc, width, height = data
					xd=width/2
					x0=int((xc-xd)*w+0.5)
					x1=int((xc+xd)*w+0.5)
					yd=height/2
					y0=int((yc-yd)*h+0.5)
					y1=int((yc+yd)*h+0.5)
					c=int(c)
					boundingBoxStr+=f" {x0},{y0},{x1},{y1},{c}"
		boundingBoxStr+='\n'
		if random.random()>0.1:
			train_files.append(boundingBoxStr)
		else:
			test_files.append(boundingBoxStr)

os.chdir("..")
with open("train.txt", "w") as outfile:
    for boundingBoxStr in train_files:
        outfile.write(boundingBoxStr)
    outfile.close()
with open("test.txt", "w") as outfile:
    for boundingBoxStr in test_files:
        outfile.write(boundingBoxStr)
    outfile.close()
os.chdir("..")

#1280*960


                        # xc=(x0+x1)*0.5/w
                        # yc=(y0+y1)*0.5/h
                        # width=(x1-x0)/w
                        # height=(y1-y0)/h