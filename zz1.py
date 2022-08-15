import plcLib
from utils.log import log
from collections import deque
import time
if __name__ == "__main__":
	log("Counting Start")
	plc=plcLib.PLC("10.32.11.2")
	prevRotaryCodes=[-1,-1,-1]
	averageRotationDeque=deque(maxlen=50)
	countings=[0,0,0]
	averageRotation=170#predefined with 1024 pulse/rotation rotary encoder
	while True:
		gloveSensors=plc.readSensors(235)
		if gloveSensors is not -1:
			for s in range(3):
				if gloveSensors[s]:
					rotaryCode=plc.readEncoder()[1]
					rotation=rotaryCode-prevRotaryCodes[s]
					if rotation<0:
						rotation=rotation+10000
					if rotation>400: #lost connection check
						rotation=-1
					if len(averageRotationDeque)>30:
						averageRotation=sum(averageRotationDeque)/len(averageRotationDeque)
					if rotation < 0.6*averageRotation:#Extra count
						log(f"{rotaryCode,averageRotation,s,rotation,countings}")
					else:#valid or missed count
						if rotation > 1.4*averageRotation: 
							countings[s]+=1#missed counted, add back
							log(f"{rotaryCode,averageRotation,s,rotation,countings}")
						countings[s]+=1
						averageRotationDeque.append(rotation)
					prevRotaryCodes[s]=rotaryCode
					print(rotaryCode,averageRotation,s,rotation,countings)
		time.sleep(0.01)