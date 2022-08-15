import fileinput
import glob

with fileinput.input(files=glob.glob('*.txt'), inplace=True) as files:
    for line in files:
    	line = '2'+ line[1:-1]
    	print(line)