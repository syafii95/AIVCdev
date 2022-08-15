from plcLib import PLC
import time

def log(string):
    timenow = datetime.datetime.now().strftime("%a %m/%d/%Y, %H:%M:%S")
    with open('sensorReading.txt', mode='a') as out_file:
        out_file.write(timenow + '\t | ' + string + '\n')
    print(f"Logged: {string}")

p=PLC('10.40.0.2')
mt=[time.time() for _ in range(4)]
xt=[time.time() for _ in range(4)]
while(1):
	ms=p.readSensors()
	for i,s in enumerate(ms):
		if(s):
			log(f'M{i} {time.time()-mt[i]}')
			mt[i]=time.time()
	xs=p.directReadX()
	for i,s in enumerate(xs):
		if(s):
			if(time.time()-xt[i]>0.25):
				log(f'X{i} {time.time()-mt[i]}')
				mt[i]=time.time()

			