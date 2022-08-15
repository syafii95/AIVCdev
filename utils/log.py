import os
import datetime

def log(string):
    timenow = datetime.datetime.now().strftime("%a %m/%d/%Y, %H:%M:%S")
    if not os.path.exists('logs/'):
        os.mkdir('logs/')
    with open('logs/log.txt', mode='a') as out_file:
        out_file.write(timenow + '\t | ' + string + '\n')
    print(f"Logged: {string}")