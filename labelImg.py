#!/usr/bin/env python
# -*- coding: utf-8 -*-
import fileinput
import glob
import qdarkstyle
import codecs
import distutils.spawn
import os.path
import platform
import re
import sys
import subprocess
import numpy as np
import time
import random
import datetime
import ast
#from train import AITrainer

from functools import partial
from collections import defaultdict

try:
    from PyQt5.QtGui import *
    from PyQt5.QtCore import *
    from PyQt5.QtWidgets import *
except ImportError:
    # needed for py3+qt4
    # Ref:
    # http://pyqt.sourceforge.net/Docs/PyQt4/incompatible_apis.html
    # http://stackoverflow.com/questions/21217399/pyqt4-qtcore-qvariant-object-instead-of-a-string
    if sys.version_info.major >= 3:
        import sip
        sip.setapi('QVariant', 2)
    from PyQt4.QtGui import *
    from PyQt4.QtCore import *

from libs.resources import *
from libs.constants import *
from libs.utils import *
from libs.settings import Settings
from libs.shape import Shape, DEFAULT_LINE_COLOR, DEFAULT_FILL_COLOR
from libs.stringBundle import StringBundle
from libs.canvas import Canvas
from libs.zoomWidget import ZoomWidget
from libs.labelDialog import LabelDialog
from libs.colorDialog import ColorDialog
from libs.labelFile import LabelFile, LabelFileError
from libs.toolBar import ToolBar
from libs.yolo_io import YoloReader
from libs.yolo_io import TXT_EXT
from libs.ustr import ustr
from libs.hashableQListWidgetItem import HashableQListWidgetItem

from shutil import copyfile, SameFileError

from libs.yoloCfgGenerator import generateYoloCfg
from utils.AIVCcomponents import LineEditLimInt
from userDialog import UserDialog
from mongoHandler import MLabel, connectMongo, MReview, MUser
import pymongo
import mongoengine
from smbclient import register_session, open_file
__VERSION__="2.3.61.5"
THIS_DIR = os.path.dirname(os.path.realpath(__file__))
THIS_DIR = THIS_DIR.replace(os.sep, '/')
__appname__ = 'labelImg'
DEFAULT_DARKNET_DIR='C:/darknet'
MONGO_ADDR="10.39.0.11:1457"
NAS_IP='10.39.0.55'
CLOUD_ADDR=f'http://{NAS_IP}:8282'
CLOUD_DIR=f"AIVC_Cloud/"
TIME_FORMAT="%Y-%m-%d_%H_%M_%S"
SIDE_SHORT=["LI", "RI", "LO", "RO", "Total"]

class Train_Thread(QThread):
    emitError=pyqtSignal(str,str)
    def __init__(self, parent, classNum):
        super().__init__(parent)
        self.parent=parent
        self.classNum=classNum
    def run(self):
        cfgFileName=generateYoloCfg(self.classNum)
        modelName = QFileDialog.getOpenFileName(caption='Select Base Model', directory=f'{THIS_DIR}/data/darknet53.conv.74')
        if(modelName[0]):
            #command=f'"{DEFAULT_DARKNET_DIR}/darknet.exe detector train {THIS_DIR}/data/obj.data {THIS_DIR}/data/yolov3_glove.cfg {THIS_DIR}/data/darknet53.conv.74"'
            command=f'"{DEFAULT_DARKNET_DIR}/darknet.exe detector train "{THIS_DIR}/data/obj.data" "{THIS_DIR}/{cfgFileName}" "{modelName[0]}" -map"'
            print(command)
            os.system('cmd /k '+command)
        else:
            print('No base model selected, abort model training')
            self.emitError.emit('No base model selected','Abort model training')
            time.sleep(0.5)
class ProfileWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.vLayout=QVBoxLayout()
        self.setLayout(self.vLayout)
        self.userForm=QFormLayout()
        self.form_email=QLabel()
        self.form_authLvl=QLabel()
        self.form_expAt=QLabel()
        self.form_labNum=QLabel()
        self.form_revNum=QLabel()
        self.form_falseNum=QLabel()
        self.form_relabNum=QLabel()
        self.btn_logout=QPushButton("Logout")
        self.userWidget=QWidget()
        self.vLayout.addWidget(self.userWidget)
        self.userWidget.hide()
        self.userWidget.setLayout(self.userForm)
        self.userForm.setWidget(0,QFormLayout.LabelRole, QLabel("Email"))
        self.userForm.setWidget(0,QFormLayout.FieldRole, self.form_email)
        self.userForm.setWidget(1,QFormLayout.LabelRole, QLabel("AuthorityLvl"))
        self.userForm.setWidget(1,QFormLayout.FieldRole, self.form_authLvl)
        self.userForm.setWidget(2,QFormLayout.LabelRole, QLabel("ExpireAt"))
        self.userForm.setWidget(2,QFormLayout.FieldRole, self.form_expAt)
        self.userForm.setWidget(3,QFormLayout.LabelRole, QLabel("LabelledNum"))
        self.userForm.setWidget(3,QFormLayout.FieldRole, self.form_labNum)
        self.userForm.setWidget(4,QFormLayout.LabelRole, QLabel("ReviewedNum"))
        self.userForm.setWidget(4,QFormLayout.FieldRole, self.form_revNum)
        self.userForm.setWidget(5,QFormLayout.LabelRole, QLabel("FalseLabelNum"))
        self.userForm.setWidget(5,QFormLayout.FieldRole, self.form_falseNum)
        self.userForm.setWidget(6,QFormLayout.LabelRole, QLabel("RelabelNum"))
        self.userForm.setWidget(6,QFormLayout.FieldRole, self.form_relabNum)
        #self.userForm.setWidget(3,QFormLayout.SpanningRole , self.btn_logout)
        self.userForm.setWidget(7,QFormLayout.LabelRole , self.btn_logout)
        self.btn_login=QPushButton("Login")
        self.btn_login.setMaximumWidth(50)
        self.vLayout.addWidget(self.btn_login)
    def logoutProfile(self):
        self.vLayout.removeItem(self.userForm)
        self.userWidget.hide()
        self.btn_login.show()

class ExtractDatasetDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent, flags=Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
        self.setWindowTitle("Extract Cloud Dataset")
        
        vLayout=QVBoxLayout()
        self.setLayout(vLayout)
        self.formLayout=QFormLayout()
        vLayout.addLayout(self.formLayout)
        self.form_query=QLineEdit()
        self.form_query.setFixedWidth(350)
        self.form_query.setPlaceholderText("Query to filter the dataset")
        self.form_query.setText("reviews__1__exists=True")
        self.formLayout.setWidget(0,QFormLayout.LabelRole, self.form_query)
        self.queryBtn=QPushButton("Query")
        self.queryBtn.clicked.connect(self.showQuery)
        self.formLayout.setWidget(0,QFormLayout.FieldRole, self.queryBtn)
        sampleStr=QLabel('E.G. reviews__1__exists=True, color="white", acquireFrom__icontains="F39", AIClass=0')
        sampleStr.setWordWrap(True)
        vLayout.addWidget(sampleStr)
        hLayout=QHBoxLayout()
        vLayout.addLayout(hLayout)

        hLayout.addWidget(QLabel("Start Date:"))
        self.queryDateSelect=QDateEdit()
        self.queryDateSelect.setFixedWidth(200)
        self.queryDateSelect.setCalendarPopup(True)
        hLayout.addWidget(self.queryDateSelect)
        hLayout.addWidget(QLabel("End Date:"))
        self.queryEndDateSelect=QDateEdit()
        self.queryEndDateSelect.setFixedWidth(200)
        self.queryEndDateSelect.setCalendarPopup(True)
        self.queryEndDateSelect.setDate(QDate.currentDate())
        hLayout.addWidget(self.queryEndDateSelect)
        hLayout.addItem(QSpacerItem(0,0,hPolicy = QSizePolicy.MinimumExpanding))


        self.queryResult=QLabel()
        self.queryResult.setWordWrap(True)
        vLayout.addWidget(self.queryResult)
        self.loadingProgressTxt=QLabel()
        vLayout.addWidget(self.loadingProgressTxt)
        vLayout.addItem(QSpacerItem(5,5,vPolicy = QSizePolicy.MinimumExpanding))
        self.returnedLabels=None
        self.setFixedSize(QSize(500, 400))
        self.hide()

    def showQuery(self):
        self.parent().checkMongoConnection()
        if not self.parent().connectedMongo:
            return
        kwargs={'error':0,'createdAt__gte':self.queryDateSelect.date().toPyDate(),\
            'createdAt__lt':self.queryEndDateSelect.date().toPyDate(),}
        queries=""
        try:
            if self.form_query.text():
                queries=self.form_query.text().split(',')
                for query in queries:
                    keyword, sep, value = query.partition('=')
                    kwargs[keyword]=ast.literal_eval(value)
            print(kwargs)
            self.returnedLabels=MLabel.objects(**kwargs)
            totalLabel=self.returnedLabels.count()
            qResultStr=f"Query: {kwargs}"
            qResultStr+=f"\nTotal Labels: {totalLabel}"
            for i in range(10):
                qResultStr+=f"\nClass {i}: {self.returnedLabels.filter(AIClass=i).count()}"
            self.queryResult.setText(qResultStr)
        except Exception as e:
            self.queryResult.setText(f"Failed To Query: {e}")
            self.returnedLabels=None
            return
        
        dialogStr="Do you want to extract dataset?\n"
        dialogStr+=qResultStr
        yes, no = QMessageBox.Yes, QMessageBox.No
        a = QMessageBox.question(self, 'Train Yolov3', dialogStr, yes | no)
        if no==a:
            return
        else:
            allLabels=MLabel.objects(createdAt__gte=datetime.datetime.now()-datetime.timedelta(hours = 5))
            timeStr=datetime.datetime.now().strftime(TIME_FORMAT)
            directory=os.getcwd()+"\\dataset"+timeStr
            print(directory)
            n=1
            while os.path.exists(directory):
                directory+=f"({n})"
                n+=1
            os.makedirs(directory)
            
            with open(f"{directory}\\query.txt", 'w') as f:
                lab=f.write(qResultStr)
            for i, l in enumerate(self.returnedLabels):
                print(l.source)
                loadName=f"\\\\{NAS_IP}\\AIVC_Cloud\\{l.color}\\{l.id}"
                saveName=f"{directory}\\{l.id}"
                try:
                    with open_file(loadName+".jpg", mode='rb', username="AImodel", password="aimodel123") as fd:
                        img=fd.read()
                    with open(saveName+".jpg", 'wb') as f:
                        f.write(img) 
                    with open_file(loadName+".txt", mode='rb', username="AImodel", password="aimodel123") as fd:
                        lab=fd.read()
                    with open(saveName+'.txt', 'wb') as f:
                        f.write(lab)
                    self.loadingProgressTxt.setText(f"Extracting Labels: {i+1}/{totalLabel}")
                except Exception as e:
                    print(e)
                    l.exception=str(e)
                    l.error=2
                    l.save()
            
class UploadDialog(QDialog):
    def __init__(self, canvas, classList, parent=None):
        super().__init__(parent, flags=Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
        self.canvas=canvas
        self.classList=classList
        self.setWindowTitle("Upload Label")
        vLayout=QVBoxLayout()
        self.setLayout(vLayout)
        self.connectionLabel=QLabel("Not Connected")
        vLayout.addWidget(self.connectionLabel)
        self.dataForm=QFormLayout()
        vLayout.addLayout(self.dataForm)
        self.form_factory=QLineEdit()
        self.form_factory.setPlaceholderText("e.g. F05 (must be two digit)")
        self.form_line=LineEditLimInt(max=50, hint="line number")
        self.form_side=QComboBox()
        self.form_side.addItems(['LI','RI','LO','RO'])
        self.form_color=QComboBox()
        self.form_color.addItems(['black','blue','green','orange','pink','white'])
        self.form_image=QLabel()
        self.form_user=QLabel()
        self.dataForm.setWidget(0,QFormLayout.LabelRole, QLabel("Factory"))
        self.dataForm.setWidget(0,QFormLayout.FieldRole, self.form_factory)
        self.dataForm.setWidget(1,QFormLayout.LabelRole, QLabel("Line"))
        self.dataForm.setWidget(1,QFormLayout.FieldRole, self.form_line)
        self.dataForm.setWidget(2,QFormLayout.LabelRole, QLabel("Side"))
        self.dataForm.setWidget(2,QFormLayout.FieldRole, self.form_side)
        self.dataForm.setWidget(3,QFormLayout.LabelRole, QLabel("Color"))
        self.dataForm.setWidget(3,QFormLayout.FieldRole, self.form_color)
        self.dataForm.setWidget(4,QFormLayout.LabelRole, QLabel("Image"))
        self.dataForm.setWidget(4,QFormLayout.FieldRole, self.form_image)
        self.dataForm.setWidget(5,QFormLayout.LabelRole, QLabel("User"))
        self.dataForm.setWidget(5,QFormLayout.FieldRole, self.form_user)
        self.errorLabel=QLabel("")
        vLayout.addWidget(self.errorLabel)
        self.uploadBtn=QPushButton("Upload")
        self.uploadBtn.clicked.connect(self.uploadLabel)
        self.uploadBtn.setEnabled(False)
        self.uploadBtn.setDefault(True)
        vLayout.addWidget(self.uploadBtn)
        self.setFixedSize(QSize(500, 240))
        self.hide()
        #currentText() 
    def uploadLabel(self):
        if not self.canvas.shapes:
            print("No Label!!")
            return
        factoryName=self.form_factory.text()
        lineNum=self.form_line.val
        side=self.form_side.currentText()
        color=self.form_color.currentText()
        acquireFrom=f"{factoryName}L{lineNum}{side}"
        cls=self.classList.index(self.canvas.shapes[0].label)
        user=self.form_user.text()
        source=self.parent().filePath
        if ((not factoryName) or (not lineNum)):
            self.errorLabel.setText("Please fill in all form")
        else:
            self.errorLabel.setText(f"Uploaded {source} as {self.form_image.text()}")
            storedCount=MLabel.objects(acquireFrom=acquireFrom,color=color,AIClass=cls).count()
            #F40L1LIwhite0_50.jpg

            imgName=f"{acquireFrom}{color}{cls}"
            try:
                mLabel=MLabel(source=source, color=color,acquireFrom=acquireFrom, AIClass=cls, labelUser=user).save()
                self.parent().mUser.labeledImgNum+=1
                self.parent().mUser.save()
                self.parent().loadUserMetadata()
            except pymongo.errors.DuplicateKeyError as e:
                print(e)
                return
            except mongoengine.errors.NotUniqueError:
                self.errorLabel.setText(f"{source} Already Exist")
                return

            if self.parent().dirty:
                self.parent().saveFile()
            saveName=f"\\\\{NAS_IP}\\AIVC_Cloud\\{color}\\{mLabel.id}"
            try:
                with open(source, 'rb') as f:
                    img=f.read() 
                with open_file(saveName+".jpg", mode='wb', username="AImodel", password="aimodel123") as fd:
                    fd.write(img)
                with open(source[:-3]+'txt', 'rb') as f:
                    lab=f.read()
                with open_file(saveName+".txt", mode='wb', username="AImodel", password="aimodel123") as fd:
                    fd.write(lab)
            except Exception as e:
                print(e)
                mLabel.exception=str(e)
                mLabel.error=1
                mLabel.save()
            #self.parent().cloudClient.put_file(CLOUD_DIR+f"{color}/{imgName}.txt", source[:-3]+'txt')
            self.parent().statusBar().showMessage(f'Uploaded {source}   as   {color}/{mLabel.id}')
            self.parent().statusBar().show()
            self.hide()
            
class ComboBox(QWidget):
    def __init__(self, parent=None, items=[]):
        super(ComboBox, self).__init__(parent)
        layout = QHBoxLayout()
        self.cb = QComboBox()
        self.items = items
        self.cb.addItems(self.items)
        self.cb.currentIndexChanged.connect(parent.comboSelectionChanged)
        layout.addWidget(self.cb)
        self.setLayout(layout)

    def update_items(self, items):
        self.items = items
        self.cb.clear()
        self.cb.addItems(self.items)
            
class LoadingDialog(QDialog):
    def __init__(self, parent=None,title='Loading'):
        super().__init__(parent, flags=Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
        self.setWindowTitle(title)
        vLayout=QVBoxLayout()
        self.setLayout(vLayout)
        self.label=QLabel()
        vLayout.addWidget(self.label)
        self.setFixedSize(QSize(250, 50))
        self.done=True

        QTimer.singleShot(3000, self.doneClose)
        self.show()

    def update(self,string):
        self.done=False
        self.label.setText(string)
        self.show()
    
    def doneClose(self):
        if self.done:
            self.close()
        else:
            self.done=True
            QTimer.singleShot(2000, self.doneClose)


class ClassSelectChangeThread(QThread):
    updateLoading=pyqtSignal(str)
    doneLoading=pyqtSignal(list)
    def __init__(self,classIndex,className,directory,parent=None):
        super().__init__(parent=parent)
        self.classIndex=classIndex
        self.className=className
        self.directory=directory

    def run(self):
        print('loading')
        images = []
        print('glob')
        files=glob.glob(self.directory+'/*.png')
        files+=glob.glob(self.directory+'/*.jpg')
        totalImages=len(files)
        if files == []:
            self.updateLoading.emit(f'No Labels In {self.directory}')
            self.doneLoading.emit(images)
            return
        count=0
        for img in files:
            count+=1
            if count%100==0:
                msg=f'Loading {count}/{totalImages} Images'
                if ON_AIVC:
                    msg+="\nLoad only first 2000 images to avoid hanging AIVC. For all images display please use seperate TGAITrainer"
                self.updateLoading.emit(msg)
            if ON_AIVC:
                if count >= 2000:
                    print("Too many images, load only first 2000 to avoid hanging AIVC. For all images display please use seperate TGAITrainer")
                    break
            lab=img[:-4]+'.txt'
            try:
                with open(lab,'r') as f:
                    for line in f.read().split('\n'):
                        if line == '':
                            continue
                        try:
                            if(int(line.split(' ')[0])==self.classIndex):
                                img = img.replace('/', '\\')
                                if img in images:
                                    continue
                                images.append(img)
                        except ValueError:
                            print(lab+' invalid format')
            except FileNotFoundError:
                print(lab+' not found')
        print(f'Done filtering {count} images')
        msg=f'Loading {count}/{totalImages} Images'
        if ON_AIVC:
            msg+="\nLoad only first 2000 images to avoid hanging AIVC. For all images display please use seperate TGAITrainer"
        self.updateLoading.emit(msg)
        self.doneLoading.emit(images)

class LoadLabelNumThread(QThread):
    updateLoading=pyqtSignal(str)
    doneLoading=pyqtSignal(np.ndarray,dict)
    def __init__(self,classesNumber,directory,parent=None):
        super().__init__(parent=parent)
        self.classesNumber=classesNumber
        self.directory=directory

    def run(self):
        classCount=np.zeros(self.classesNumber,dtype=int)
        classRecord={}
        #files=glob.glob(directory+'/img*.txt')
        files=glob.glob(self.directory+'/*.png')
        files+=glob.glob(self.directory+'/*.jpg')
        totalImages=len(files)
        if files == []:      
            self.doneLoading.emit(classCount,classRecord)
            self.updateLoading.emit(f'No Labels In {self.directory}')
            return
        count=0
        for img in files:
            count += 1
            # self.statusBar().showMessage(f'Loading Images {count}/{len(files)}')
            # self.statusBar().show()
            if count % 100 == 0:
                msg=f'Loading {count}/{totalImages} Images'
                if ON_AIVC:
                    msg+="\nLoad only first 2000 images to avoid hanging AIVC. For all images display please use seperate TGAITrainer"
                self.updateLoading.emit(msg)
            if ON_AIVC:
                if count >= 2000:
                    print('Too many images, load only first 2000 to avoid crash')
                    break
            lab=img[:-4]+'.txt'
            try:
                with open(lab,'r') as f:
                    imgName=img.split('\\')[-1][:-4]
                    cList=[]
                    for line in f.read().split('\n'):
                        if line == '':
                            continue
                        try:
                            aiclass=int(line.split(' ')[0])
                            classCount[aiclass]+=1
                            cList.append(aiclass)
                        except: 
                            print("Wrong label file "+lab)
                            #@#TODO:move to other directory
                    classRecord[imgName]=cList
            except FileNotFoundError:
                print(lab+' not found')
        print(f'Done Reading {count} Labels')    
        msg=f'Loading {count}/{totalImages} Images'
        if ON_AIVC:
            msg+="\nLoad only first 2000 images to avoid hanging AIVC. For all images display please use seperate TGAITrainer"
        self.updateLoading.emit(msg)       
        self.doneLoading.emit(classCount,classRecord)

class WindowMixin(object):

    def menu(self, title, actions=None):
        menu = self.menuBar().addMenu(title)
        if actions:
            addActions(menu, actions)
        return menu

    def toolbar(self, title, actions=None):
        toolbar = ToolBar(title)
        toolbar.setObjectName(u'%sToolBar' % title)
        # toolbar.setOrientation(Qt.Vertical)
        toolbar.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        if actions:
            addActions(toolbar, actions)
        self.addToolBar(Qt.LeftToolBarArea, toolbar)
        return toolbar


class MainWindow(QMainWindow, WindowMixin):
    FIT_WINDOW, FIT_WIDTH, MANUAL_ZOOM = list(range(3))
    def loadLabelNum(self,classCount,classRecord):
        self.classCount=classCount
        self.classRecord=classRecord
        self.setLabelNum()
        # if self.loadingDialogLN:
        #     self.loadingDialogLN.close()

    def readLabelNum(self, directory):
        self.loadingDialogLN=LoadingDialog(parent=self,title='Loading Number Of Labels')
        loadlabelNumThread=LoadLabelNumThread(len(self.labelHist),directory,self)
        loadlabelNumThread.doneLoading.connect(self.loadLabelNum)
        loadlabelNumThread.updateLoading.connect(self.loadingDialogLN.update)
        loadlabelNumThread.start(3)

    def updateLabelNum(self, imgName):
        #If the image is in dataset already, deduct the class count by the record
        if imgName in self.classRecord:
            record=self.classRecord[imgName]
            for r in record:
                self.classCount[r]-=1
        #Increment classCount and update classRecord
        cList=[]
        for shape in self.canvas.shapes:
            c=self.labelHist.index(shape.label)
            self.classCount[c]+=1
            cList.append(self.labelHist.index(shape.label))
        self.classRecord[imgName]=cList
        self.setLabelNum()

    def deleteLabelNum(self, imgName):
        #If the image is in dataset already, deduct the class count by the record
        if imgName in self.classRecord:
            record=self.classRecord[imgName]
            for r in record:
                self.classCount[r]-=1
            self.classRecord.pop(imgName)
        self.setLabelNum()
        
    def setLabelNum(self):
        labelNumStr=f"Labelled Object In Dataset:\n({self.datasetDir})\n"
        for i,label in enumerate(self.classCount):
            labelNumStr+=f'{self.labelHist[i]:<15}: {str(label)}\n'
        self.infoLabel.setText(labelNumStr)
                            
    def logoutUser(self):
        self.profile.logoutProfile()
        self.mUser=None
        self.closeReviewMode()

    def checkMongoConnection(self):
        if not self.connectedMongo:
            self.connectedMongo=connectMongo()
            if not self.connectedMongo:
                self.errorMessage("Failed to connect database","Please check your intranet connection")
                self.uploadDialog.connectionLabel.setText(f"Unable to connect {MONGO_ADDR}")
                self.uploadDialog.uploadBtn.setEnabled(False)
            else:
                self.uploadDialog.connectionLabel.setText(f"Connected {MONGO_ADDR}")
                self.uploadDialog.uploadBtn.setEnabled(True)
    
    def loginUpdateProfile(self):
        #{'email': 'tan_ser_yee', 'authorityLvl': 8, 'expireAt': '2021-08-18 11:26:07'}
        user=self.userDialog.user
        self.profile.form_email.setText(user['email']+"@topglove.com.my")
        self.profile.form_authLvl.setText(str(user['authorityLvl']))
        self.profile.form_expAt.setText(user['expireAt'])
        self.checkMongoConnection()
        #Get user details on mongodb
        if self.connectedMongo:
            self.mUser=MUser.objects(email=user['email']).first()
            print(self.mUser)
            if not self.mUser:
                self.mUser=MUser(email=user['email']).save()
            self.loadUserMetadata()
        self.profile.userWidget.show()
        self.profile.btn_login.hide()

    def __init__(self, defaultImg=None,defaultFilename=None, parent=None,onAIVC=False,factory=None,line=None,userDL=None):
        super(MainWindow, self).__init__(parent)
        global ON_AIVC
        ON_AIVC=onAIVC
        self.factory=factory
        self.line=line
        #Load classes.names
        self.labelHist=[]
        try:
            with open('classes.names','r') as names:
                for name in names:
                    self.labelHist.append(name.strip('\n'))
        except FileNotFoundError as e:
            print(e)
            #classes.names not found, use default name instead
            self.labelHist=["Good Glove","Tearing","Single Arm","Double Dip", "Unstripped","No Glove","Stained", "Lump", "Broken Former", "Other"]

        self.connectedMongo=False
        #self.connectedCloud=False
        self.reviewModeOn=False
        self.reviewImg=''
        self.mUser=None
        #self.cloudClient = nextcloud_client.Client(CLOUD_ADDR)
        self.classRecord={}
        self.datasetDir= f'{os.getcwd()}/tempDataSetDir'.replace('\\', '/')
        #self.datasetDir= f'{os.path.dirname(os.path.realpath(__file__))}\\tempDataSetDir'.replace('\\', '/')
        self.setWindowTitle(__appname__)
        self.statusBar().setFixedHeight(40)
        self.statusBar().setFont(QFont('Times', 15))
        self.showMaximized()
        if userDL:
            self.userDialog=userDL
        else:
            self.userDialog=UserDialog(self)
        self.profile = ProfileWidget(self)
        self.profile.btn_logout.clicked.connect(self.userDialog.logout)
        self.profile.btn_login.clicked.connect(self.openLoginDialog)
        self.userDialog.userLoggedIn.connect(self.loginUpdateProfile)
        self.userDialog.userLoggedOut.connect(self.logoutUser)

        # Load setting in the main thread
        self.settings = Settings()
        self.settings.load()
        settings = self.settings

        # Load string bundle for i18n
        self.stringBundle = StringBundle.getBundle()
        getStr = lambda strId: self.stringBundle.getString(strId)

        self.defaultSaveDir = defaultFilename
        self.usingYoloFormat = True

        # For loading all image under a directory
        self.mImgList = []
        self.dirname = None
        self.lastOpenDir = "."

        # Whether we need to save or not.
        self.dirty = False

        self._noSelectionSlot = False
        self._beginner = True
        self.screencastViewer = self.getAvailableScreencastViewer()
        self.screencast = "https://youtu.be/p0nR2YsCY_U"


        # Main widgets and related state.
        self.labelDialog = LabelDialog(parent=self, listItem=self.labelHist)

        self.itemsToShapes = {}
        self.shapesToItems = {}
        self.prevLabelText = ''

        self.dockVLayout = QVBoxLayout()
        self.dockVLayout.setContentsMargins(0, 0, 0, 0)
        self.dockVLayout.addWidget(self.profile)
        # Create and add combobox for showing unique labels in group 
        self.comboBox = ComboBox(self)
        self.dockVLayout.addWidget(self.comboBox)

        # Create and add a widget for showing current label items
        self.labelList = QListWidget()
        labelListContainer = QWidget()
        labelListContainer.setLayout(self.dockVLayout)
        labelListContainer.setFixedWidth(450)
        self.labelList.itemActivated.connect(self.labelSelectionChanged)
        self.labelList.itemSelectionChanged.connect(self.labelSelectionChanged)
        self.labelList.itemDoubleClicked.connect(self.editLabel)
        # Connect to itemChanged to detect checkbox changes.
        self.labelList.itemChanged.connect(self.labelItemChanged)
        self.dockVLayout.addWidget(self.labelList)

        myFont=QFont("Courier New", 14, QFont.Bold)
        self.infoLabel=QLabel()
        self.readLabelNum(self.datasetDir)
        #self.infoLabel.setText("Labelled Object In Dataset:\n0\t: 0 \n1\t: 0\n")
        self.infoLabel.setFont(myFont)
        self.dockVLayout.addWidget(self.infoLabel)
        self.commentField=QLineEdit()
        self.commentField.setPlaceholderText("Review Comment. *Disaprove by default")
        self.commentField.returnPressed.connect(lambda: self.approveReview(False))
        self.dockVLayout.addWidget(self.commentField)
        self.commentField.hide()

        self.dock = QDockWidget('Profile', self)
        self.dock.setObjectName(getStr('labels'))
        self.dock.setWidget(labelListContainer)

        self.classSelect=QComboBox()
        self.classSelect.addItem('All')
        for l in self.labelHist:
            self.classSelect.addItem(l)
        self.classSelect.currentIndexChanged.connect(self.classSelectChange)

        self.fileListWidget = QListWidget()
        self.fileListWidget.itemDoubleClicked.connect(self.fileitemDoubleClicked)
        filelistLayout = QVBoxLayout()
        filelistLayout.setContentsMargins(0, 0, 0, 0)
        filelistLayout.addWidget(self.classSelect)
        filelistLayout.addWidget(self.fileListWidget)
        fileListContainer = QWidget()
        fileListContainer.setLayout(filelistLayout)
        self.filedock = QDockWidget(getStr('fileList'), self)
        self.filedock.setObjectName(getStr('files'))
        self.filedock.setWidget(fileListContainer)

        self.zoomWidget = ZoomWidget()
        self.colorDialog = ColorDialog(parent=self)

        self.canvas = Canvas(parent=self)
        self.canvas.zoomRequest.connect(self.zoomRequest)
        self.canvas.setDrawingShapeToSquare(settings.get(SETTING_DRAW_SQUARE, False))

        scroll = QScrollArea()
        scroll.setWidget(self.canvas)
        scroll.setWidgetResizable(True)
        self.scrollBars = {
            Qt.Vertical: scroll.verticalScrollBar(),
            Qt.Horizontal: scroll.horizontalScrollBar()
        }
        self.scrollArea = scroll
        self.canvas.scrollRequest.connect(self.scrollRequest)

        self.canvas.newShape.connect(self.newShape)
        self.canvas.shapeMoved.connect(self.setDirty)
        self.canvas.selectionChanged.connect(self.shapeSelectionChanged)
        self.canvas.drawingPolygon.connect(self.toggleDrawingSensitive)

        self.setCentralWidget(scroll)
        self.addDockWidget(Qt.RightDockWidgetArea, self.dock)
        self.addDockWidget(Qt.RightDockWidgetArea, self.filedock)
        self.filedock.setFeatures(QDockWidget.DockWidgetFloatable)

        self.dockFeatures = QDockWidget.DockWidgetClosable | QDockWidget.DockWidgetFloatable
        self.dock.setFeatures(self.dock.features() ^ self.dockFeatures)

        self.extractDatasetDialog=ExtractDatasetDialog(self)
        self.uploadDialog=UploadDialog(self.canvas,self.labelHist,self)#
        self.uploadDialog.form_factory.setText(self.factory)
        if self.line:
            self.uploadDialog.form_line.setText(str(self.line))
            
        if self.userDialog.authenticated:
            self.loginUpdateProfile()

        # Actions
        action = partial(newAction, self)
        quit = action(getStr('quit'), self.close,
                      'Ctrl+Q', 'quit', getStr('quitApp'))

        #open = action(getStr('openFile'), self.openFile,
        #              'Ctrl+O', 'open', getStr('openFileDetail'))

        opendir = action(getStr('openDir'), self.openDirDialog,
                         'Ctrl+u', 'open', getStr('openDir'))

        #changeSavedir = action(getStr('changeSaveDir'), self.changeSavedirDialog,
        #                       'Ctrl+r', 'open', getStr('changeSavedAnnotationDir'))

        changeDatasetDir = action('Change Training\nDataset Dir', self.changeDatasetDirDialog,
                               'T', 'open', 'Select training dataset directory')

        trainAI= action('Train AI', self.trainAIDialog,
                               'Ctrl+T', 'aiTraining', 'Start training Yolov3 neural network')

        extractDataset= action('Extract Dataset', self.openExtractDatasetDialog,
                               'Ctrl+E', 'extractDataset', 'Extract Centrailized Dataset')

        openAnnotation = action(getStr('openAnnotation'), self.openAnnotationDialog,
                                'Ctrl+Shift+O', 'open', getStr('openAnnotationDetail'))

        openNextImg = action(getStr('nextImg'), self.openNextImg,
                             'd', 'next', getStr('nextImgDetail'))

        openPrevImg = action(getStr('prevImg'), self.openPrevImg,
                             'a', 'prev', getStr('prevImgDetail'))

        verify = action('Save Into Dataset', self.verifyImg,
                        'space', 'verify', getStr('verifyImgDetail'))
        uploadLabel = action('Upload Label', self.openUploadDialog,
                        'u', 'uploadLabel', getStr('verifyImgDetail'))
        save = action(getStr('save'), self.saveFile,
                      'Ctrl+S', 'save', getStr('saveDetail'), enabled=False)

        saveAs = action(getStr('saveAs'), self.saveFileAs,
                        'Ctrl+Shift+S', 'save-as', getStr('saveAsDetail'), enabled=False)

        close = action(getStr('closeCur'), self.closeFile, 'Ctrl+W', 'close', getStr('closeCurDetail'))

        resetAll = action(getStr('resetAll'), self.resetAll, None, 'resetall', getStr('resetAllDetail'))

        color1 = action(getStr('boxLineColor'), self.chooseColor1,
                        'Ctrl+L', 'color_line', getStr('boxLineColorDetail'))

        createMode = action(getStr('crtBox'), self.setCreateMode,
                            'w', 'new', getStr('crtBoxDetail'), enabled=False)
        editMode = action('&Edit\nRectBox', self.setEditMode,
                          'Ctrl+J', 'edit', u'Move and edit Boxs', enabled=False)

        create = action(getStr('crtBox'), self.createShape,
                        'w', 'new', getStr('crtBoxDetail'), enabled=False)
        delete = action(getStr('delBox'), self.deleteSelectedShape,
                        'Delete', 'delete', getStr('delBoxDetail'), enabled=False)
        copy = action(getStr('dupBox'), self.copySelectedShape,
                      'Ctrl+D', 'copy', getStr('dupBoxDetail'),
                      enabled=False)

        advancedMode = action(getStr('advancedMode'), self.toggleAdvancedMode,
                              'Ctrl+Shift+A', 'expert', getStr('advancedModeDetail'),
                              checkable=True)

        hideAll = action('&Hide\nRectBox', partial(self.togglePolygons, False),
                         'Ctrl+H', 'hide', getStr('hideAllBoxDetail'),
                         enabled=False)
        showAll = action('&Show\nRectBox', partial(self.togglePolygons, True),
                         'Ctrl+A', 'hide', getStr('showAllBoxDetail'),
                         enabled=False)

        zoom = QWidgetAction(self)
        zoom.setDefaultWidget(self.zoomWidget)
        self.zoomWidget.setWhatsThis(
            u"Zoom in or out of the image. Also accessible with"
            " %s and %s from the canvas." % (fmtShortcut("Ctrl+[-+]"),
                                             fmtShortcut("Ctrl+Wheel")))
        self.zoomWidget.setEnabled(False)

        zoomIn = action(getStr('zoomin'), partial(self.addZoom, 10),
                        'Ctrl++', 'zoom-in', getStr('zoominDetail'), enabled=False)
        zoomOut = action(getStr('zoomout'), partial(self.addZoom, -10),
                         'Ctrl+-', 'zoom-out', getStr('zoomoutDetail'), enabled=False)
        zoomOrg = action(getStr('originalsize'), partial(self.setZoom, 100),
                         'Ctrl+=', 'zoom', getStr('originalsizeDetail'), enabled=False)
        fitWindow = action(getStr('fitWin'), self.setFitWindow,
                           'Ctrl+F', 'fit-window', getStr('fitWinDetail'),
                           checkable=True, enabled=False)
        fitWidth = action(getStr('fitWidth'), self.setFitWidth,
                          'Ctrl+Shift+F', 'fit-width', getStr('fitWidthDetail'),
                          checkable=True, enabled=False)
        # Group zoom controls into a list for easier toggling.
        zoomActions = (self.zoomWidget, zoomIn, zoomOut,
                       zoomOrg, fitWindow, fitWidth)
        self.zoomMode = self.MANUAL_ZOOM
        self.scalers = {
            self.FIT_WINDOW: self.scaleFitWindow,
            self.FIT_WIDTH: self.scaleFitWidth,
            # Set to one to scale to 100% when loading files.
            self.MANUAL_ZOOM: lambda: 1,
        }

        edit = action(getStr('editLabel'), self.editLabel,
                      'Ctrl+Shift+E', 'edit', getStr('editLabelDetail'),
                      enabled=False)

        shapeLineColor = action(getStr('shapeLineColor'), self.chshapeLineColor,
                                icon='color_line', tip=getStr('shapeLineColorDetail'),
                                enabled=False)
        shapeFillColor = action(getStr('shapeFillColor'), self.chshapeFillColor,
                                icon='color', tip=getStr('shapeFillColorDetail'),
                                enabled=False)

        labels = self.dock.toggleViewAction()
        labels.setText(getStr('showHide'))
        labels.setShortcut('Ctrl+Shift+L')

        # Label list context menu.
        labelMenu = QMenu()
        addActions(labelMenu, (edit, delete))
        self.labelList.setContextMenuPolicy(Qt.CustomContextMenu)
        self.labelList.customContextMenuRequested.connect(
            self.popLabelListMenu)

        # Draw squares/rectangles
        self.drawSquaresOption = QAction('Draw Squares', self)
        self.drawSquaresOption.setShortcut('Ctrl+Shift+R')
        self.drawSquaresOption.setCheckable(True)
        self.drawSquaresOption.setChecked(settings.get(SETTING_DRAW_SQUARE, False))
        self.drawSquaresOption.triggered.connect(self.toogleDrawSquare)

        # Store actions for further handling.
        self.actions = struct(save=save, saveAs=saveAs, open=open, close=close, resetAll = resetAll,
                              lineColor=color1, create=create, delete=delete, edit=edit, copy=copy,
                              createMode=createMode, editMode=editMode, advancedMode=advancedMode,
                              shapeLineColor=shapeLineColor, shapeFillColor=shapeFillColor,
                              zoom=zoom, zoomIn=zoomIn, zoomOut=zoomOut, zoomOrg=zoomOrg,
                              fitWindow=fitWindow, fitWidth=fitWidth,
                              zoomActions=zoomActions,
                              fileMenuActions=(
                                  open, opendir, save, saveAs, close, resetAll, quit),
                              beginner=(), advanced=(),
                              editMenu=(edit, copy, delete,
                                        None, color1, self.drawSquaresOption),
                              beginnerContext=(create, edit, copy, delete),
                              advancedContext=(createMode, editMode, edit, copy,
                                               delete, shapeLineColor, shapeFillColor),
                              onLoadActive=(
                                  close, create, createMode, editMode),
                              onShapesPresent=(saveAs, hideAll, showAll))

        self.menus = struct(
            file=self.menu('&File'),
            edit=self.menu('&Edit'),
            view=self.menu('&View'),
            recentFiles=QMenu('Open &Recent'),
            labelList=labelMenu)

        # Auto saving : Enable auto saving if pressing next
        self.autoSaving = QAction(getStr('autoSaveMode'), self)
        self.autoSaving.setCheckable(True)
        ###self.autoSaving.setChecked(settings.get(SETTING_AUTO_SAVE, False))
        self.autoSaving.setChecked(True)
        # Sync single class mode from PR#106
        self.singleClassMode = QAction(getStr('singleClsMode'), self)
        self.singleClassMode.setShortcut("Ctrl+Shift+S")
        self.singleClassMode.setCheckable(True)
        self.singleClassMode.setChecked(settings.get(SETTING_SINGLE_CLASS, False))
        self.lastLabel = None
        # Add option to enable/disable labels being displayed at the top of bounding boxes
        self.displayLabelOption = QAction(getStr('displayLabel'), self)
        self.displayLabelOption.setShortcut("Ctrl+Shift+P")
        self.displayLabelOption.setCheckable(True)
        self.displayLabelOption.setChecked(settings.get(SETTING_PAINT_LABEL, False))
        self.displayLabelOption.triggered.connect(self.togglePaintLabelsOption)

        self.darkModeOption = QAction('Dark Mode', self)
        self.darkModeOption.setShortcut("Ctrl+Shift+T")
        self.darkModeOption.setCheckable(True)
        self.darkModeOption.setChecked(True)
        self.darkModeOption.triggered.connect(self.toggleDarkMode)

        addActions(self.menus.file,
                   (opendir,openAnnotation, changeDatasetDir, self.menus.recentFiles, save, saveAs, close, resetAll, quit))
        addActions(self.menus.view, (
            self.autoSaving,
            self.singleClassMode,
            self.displayLabelOption,
            labels, advancedMode, self.darkModeOption, None,
            hideAll, showAll, None,
            zoomIn, zoomOut, zoomOrg, None,
            fitWindow, fitWidth))

        self.menus.file.aboutToShow.connect(self.updateFileMenu)

        # Custom context menu for the canvas widget:
        addActions(self.canvas.menus[0], self.actions.beginnerContext)
        addActions(self.canvas.menus[1], (
            action('&Copy here', self.copyShape),
            action('&Move here', self.moveShape)))

        self.tools = self.toolbar('Tools')
        self.actions.beginner = (
            opendir, changeDatasetDir, openNextImg, openPrevImg, verify, save, None, create, copy, delete, None,
            zoomIn, zoom, zoomOut, fitWindow, fitWidth, trainAI, extractDataset)

        self.actions.advanced = (
            opendir, changeDatasetDir, openNextImg, openPrevImg, verify, save, None,
            createMode, editMode, None,
            hideAll, showAll, trainAI,extractDataset)

        self.statusBar().showMessage('%s started.' % __appname__)
        self.statusBar().show()

        # Application state.
        self.image = QImage()
        self.filePath = ustr(defaultFilename)
        self.recentFiles = []
        self.maxRecent = 7
        self.lineColor = None
        self.fillColor = None
        self.zoom_level = 100
        self.fit_window = False
        # Add Chris
        self.difficult = False

        ## Fix the compatible issue for qt4 and qt5. Convert the QStringList to python list
        if settings.get(SETTING_RECENT_FILES):
            if have_qstring():
                recentFileQStringList = settings.get(SETTING_RECENT_FILES)
                self.recentFiles = [ustr(i) for i in recentFileQStringList]
            else:
                self.recentFiles = recentFileQStringList = settings.get(SETTING_RECENT_FILES)

        size = settings.get(SETTING_WIN_SIZE, QSize(600, 500))
        position = QPoint(0, 0)
        saved_position = settings.get(SETTING_WIN_POSE, position)
        # Fix the multiple monitors issue
        for i in range(QApplication.desktop().screenCount()):
            if QApplication.desktop().availableGeometry(i).contains(saved_position):
                position = saved_position
                break
        self.resize(size)
        self.move(position)
        saveDir = ustr(settings.get(SETTING_SAVE_DIR, None))
        self.lastOpenDir = ustr(settings.get(SETTING_LAST_OPEN_DIR, None))
        # if self.defaultSaveDir is None and saveDir is not None and os.path.exists(saveDir):
        #     self.defaultSaveDir = saveDir
        #     self.statusBar().showMessage('%s started. Annotation will be saved to %s' %
        #                                  (__appname__, self.defaultSaveDir))
        #     self.statusBar().show()

        self.restoreState(settings.get(SETTING_WIN_STATE, QByteArray()))
        Shape.line_color = self.lineColor = QColor(settings.get(SETTING_LINE_COLOR, DEFAULT_LINE_COLOR))
        Shape.fill_color = self.fillColor = QColor(settings.get(SETTING_FILL_COLOR, DEFAULT_FILL_COLOR))
        self.canvas.setDrawingColor(self.lineColor)
        # Add chris
        Shape.difficult = self.difficult

        self.shortcut_1 = QShortcut(QKeySequence('1'),self)
        self.shortcut_1.activated.connect(partial(self.editLabelWithShortcut,1))
        self.shortcut_2 = QShortcut(QKeySequence('2'),self)
        self.shortcut_2.activated.connect(partial(self.editLabelWithShortcut,2))
        self.shortcut_3 = QShortcut(QKeySequence('3'),self)
        self.shortcut_3.activated.connect(partial(self.editLabelWithShortcut,3))
        self.shortcut_4 = QShortcut(QKeySequence('4'),self)
        self.shortcut_4.activated.connect(partial(self.editLabelWithShortcut,4))
        self.shortcut_5 = QShortcut(QKeySequence('5'),self)
        self.shortcut_5.activated.connect(partial(self.editLabelWithShortcut,5))
        self.shortcut_6 = QShortcut(QKeySequence('6'),self)
        self.shortcut_6.activated.connect(partial(self.editLabelWithShortcut,6))
        self.shortcut_7 = QShortcut(QKeySequence('7'),self)
        self.shortcut_7.activated.connect(partial(self.editLabelWithShortcut,7))
        self.shortcut_8 = QShortcut(QKeySequence('8'),self)
        self.shortcut_8.activated.connect(partial(self.editLabelWithShortcut,8))
        self.shortcut_9 = QShortcut(QKeySequence('9'),self)
        self.shortcut_9.activated.connect(partial(self.editLabelWithShortcut,9))
        self.shortcut_10 = QShortcut(QKeySequence('0'),self)
        self.shortcut_10.activated.connect(partial(self.editLabelWithShortcut,10))
        self.shortcut_10 = QShortcut(QKeySequence('-'),self)
        self.shortcut_10.activated.connect(partial(self.editLabelWithShortcut,11))
        self.shortcut_10 = QShortcut(QKeySequence('='),self)
        self.shortcut_10.activated.connect(partial(self.editLabelWithShortcut,12))
        self.shortcut_a = QShortcut(QKeySequence('`'),self)
        self.shortcut_a.activated.connect(self.toggleActiveItem)
        self.shortcut_d = QShortcut(QKeySequence('Backspace'),self)
        self.shortcut_d.activated.connect(self.deleteFile)
        self.shortcut_l = QShortcut(QKeySequence('l'),self)
        self.shortcut_l.activated.connect(self.openLoginDialog)
        self.shortcut_u = QShortcut(QKeySequence('u'),self)
        self.shortcut_u.activated.connect(self.openUploadDialog)
        self.shortcut_r = QShortcut(QKeySequence('r'),self)
        self.shortcut_r.activated.connect(self.openReviewQuestion)
        self.shortcut_y = QShortcut(QKeySequence('y'),self)
        self.shortcut_y.activated.connect(lambda: self.approveReview(True))
        self.shortcut_n = QShortcut(QKeySequence('n'),self)
        self.shortcut_n.activated.connect(lambda: self.approveReview(False))

        def xbool(x):
            if isinstance(x, QVariant):
                return x.toBool()
            return bool(x)

        if xbool(settings.get(SETTING_ADVANCE_MODE, False)):
            self.actions.advancedMode.setChecked(True)
            self.toggleAdvancedMode()

        # Populate the File menu dynamically.
        self.updateFileMenu()

        #Replace with loadFile
        # Callbacks:
        self.zoomWidget.valueChanged.connect(self.paintCanvas)

        self.populateModeActions()

        # Display cursor coordinates at the right of status bar
        self.labelCoordinates = QLabel('')
        self.statusBar().addPermanentWidget(self.labelCoordinates)


        if defaultImg:
            self.filePath=defaultImg
            self.defaultSaveDir="/".join(defaultImg.split('/')[:-1])
            self.loadFile(defaultImg)
        else:
            # Since loading the file may take some time, make sure it runs in the background. #Load tag_low_confidence
            print("Loading low conf")
            if self.filePath and os.path.isdir(self.filePath):
                self.queueEvent(partial(self.importDirImages, self.filePath or ""))


    def keyReleaseEvent(self, event):
        if event.key() == Qt.Key_Control:
            self.canvas.setDrawingShapeToSquare(False)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Control:
            # Draw rectangle if Ctrl is pressed
            self.canvas.setDrawingShapeToSquare(True)


    def noShapes(self):
        return not self.itemsToShapes

    def toggleAdvancedMode(self, value=True):
        self._beginner = not value
        self.canvas.setEditing(True)
        self.populateModeActions()
        if value:
            self.actions.createMode.setEnabled(True)
            self.actions.editMode.setEnabled(False)
            self.dock.setFeatures(self.dock.features() | self.dockFeatures)
        else:
            self.dock.setFeatures(self.dock.features() ^ self.dockFeatures)

    def populateModeActions(self):
        if self.beginner():
            tool, menu = self.actions.beginner, self.actions.beginnerContext
        else:
            tool, menu = self.actions.advanced, self.actions.advancedContext
        self.tools.clear()
        addActions(self.tools, tool)
        self.canvas.menus[0].clear()
        addActions(self.canvas.menus[0], menu)
        self.menus.edit.clear()
        actions = (self.actions.create,) if self.beginner()\
            else (self.actions.createMode, self.actions.editMode)
        addActions(self.menus.edit, actions + self.actions.editMenu)

    def setBeginner(self):
        self.tools.clear()
        addActions(self.tools, self.actions.beginner)

    def setAdvanced(self):
        self.tools.clear()
        addActions(self.tools, self.actions.advanced)

    def setDirty(self):
        self.dirty = True
        self.actions.save.setEnabled(True)

        if(self.canvas.verified):
            self.canvas.verified=False
            self.paintCanvas()

    def setDirty_Aa(self):
        self.dirty = True
        if self.verify_token is not None:
            self.verification_token(self.verify_token)

        if(self.canvas.verified):
            self.canvas.verified=False
            self.paintCanvas()

        if (self.verification):
            self.actions.save.setEnabled(True)
            self.actions.saveAs.setEnabled(True)
            self.actions.verify.setEnabled(True)
            self.actions.changeDatasetDir.setEnabled(True)
            self.actions.trainAI.setEnabled(True)
            
    def setClean(self):
        self.dirty = False
        self.actions.save.setEnabled(False)
        self.actions.create.setEnabled(True)

    def toggleActions(self, value=True):
        """Enable/Disable widgets which depend on an opened image."""
        for z in self.actions.zoomActions:
            z.setEnabled(value)
        for action in self.actions.onLoadActive:
            action.setEnabled(value)

    def queueEvent(self, function):
        QTimer.singleShot(0, function)

    def status(self, message, delay=5000):
        self.statusBar().showMessage(message, delay)

    def resetState(self):
        self.itemsToShapes.clear()
        self.shapesToItems.clear()
        self.labelList.clear()
        self.filePath = None
        self.imageData = None
        self.labelFile = None
        self.canvas.resetState()
        self.labelCoordinates.clear()
        self.comboBox.cb.clear()

    def currentItem(self):
        items = self.labelList.selectedItems()
        if items:
            return items[0]
        return None

    def addRecentFile(self, filePath):
        if filePath in self.recentFiles:
            self.recentFiles.remove(filePath)
        elif len(self.recentFiles) >= self.maxRecent:
            self.recentFiles.pop()
        self.recentFiles.insert(0, filePath)

    def beginner(self):
        return self._beginner

    def advanced(self):
        return not self.beginner()

    def getAvailableScreencastViewer(self):
        osName = platform.system()

        if osName == 'Windows':
            return ['C:\\Program Files\\Internet Explorer\\iexplore.exe']
        elif osName == 'Linux':
            return ['xdg-open']
        elif osName == 'Darwin':
            return ['open']

    def createShape(self):
        assert self.beginner()
        self.canvas.setEditing(False)
        self.actions.create.setEnabled(False)

    def toggleDrawingSensitive(self, drawing=True):
        """In the middle of drawing, toggling between modes should be disabled."""
        self.actions.editMode.setEnabled(not drawing)
        if not drawing and self.beginner():
            # Cancel creation.
            print('Cancel creation.')
            self.canvas.setEditing(True)
            self.canvas.restoreCursor()
            self.actions.create.setEnabled(True)

    def toggleDrawMode(self, edit=True):
        self.canvas.setEditing(edit)
        self.actions.createMode.setEnabled(edit)
        self.actions.editMode.setEnabled(not edit)

    def setCreateMode(self):
        assert self.advanced()
        self.toggleDrawMode(False)

    def setEditMode(self):
        assert self.advanced()
        self.toggleDrawMode(True)
        self.labelSelectionChanged()

    def updateFileMenu(self):
        currFilePath = self.filePath

        def exists(filename):
            return os.path.exists(filename)
        menu = self.menus.recentFiles
        menu.clear()
        files = [f for f in self.recentFiles if f !=
                 currFilePath and exists(f)]
        for i, f in enumerate(files):
            icon = newIcon('labels')
            action = QAction(
                icon, '&%d %s' % (i + 1, QFileInfo(f).fileName()), self)
            action.triggered.connect(partial(self.loadRecent, f))
            menu.addAction(action)

    def popLabelListMenu(self, point):
        self.menus.labelList.exec_(self.labelList.mapToGlobal(point))

    def editLabelWithShortcut(self,i):
        if not self.canvas.editing():
            return
        item = self.currentItem()
        if not item:
            return
        text = None
        if i <= len(self.labelHist):
            text = self.labelHist[i-1]

        if text is not None:
            item.setText(text)
            item.setBackground(generateColorByText(text))
            self.setDirty()
            self.updateComboBox()


    def editLabel(self):
        if not self.canvas.editing():
            return
        item = self.currentItem()
        if not item:
            return
        text = self.labelDialog.popUp(item.text())
        if text is not None:
            item.setText(text)
            item.setBackground(generateColorByText(text))
            self.setDirty()
            self.updateComboBox()

    def fileitemDoubleClicked(self, item=None):
        currIndex = self.mImgList.index(ustr(item.text()))
        if currIndex < len(self.mImgList):
            filename = self.mImgList[currIndex]
            if filename:
                self.loadFile(filename)

    def toggleActiveItem(self):
        item = self.currentItem()
        if item and self.canvas.editing():
            self.labelList.clearSelection()
            self.canvas.deSelectShape()
        else:
            if self.labelList.count():
                self.labelList.setCurrentItem(self.labelList.item(self.labelList.count()-1))
                self.labelList.item(self.labelList.count()-1).setSelected(True)

    # # Add chris
    # def btnstate(self, item= None):
    #     """ Function to handle difficult examples
    #     Update on each object """
    #     if not self.canvas.editing():
    #         return

    #     item = self.currentItem()
    #     if not item: # If not selected Item, take the first one
    #         item = self.labelList.item(self.labelList.count()-1)

    #     try:
    #         shape = self.itemsToShapes[item]
    #     except:
    #         pass
    #     # Checked and Update
    #     try:
    #         if difficult != shape.difficult:
    #             shape.difficult = difficult
    #             self.setDirty()
    #         else:  # User probably changed item visibility
    #             self.canvas.setShapeVisible(shape, item.checkState() == Qt.Checked)
    #     except:
    #         pass

    # React to canvas signals.
    def shapeSelectionChanged(self, selected=False):
        if self._noSelectionSlot:
            self._noSelectionSlot = False
        else:
            shape = self.canvas.selectedShape
            if shape:
                try:
                    self.shapesToItems[shape].setSelected(True) 
                except:
                    print('Error: shape not in shapesToItems list')
                    self.labelList.clearSelection()
            else:
                self.labelList.clearSelection()
        self.actions.delete.setEnabled(selected)
        self.actions.copy.setEnabled(selected)
        self.actions.edit.setEnabled(selected)
        self.actions.shapeLineColor.setEnabled(selected)
        self.actions.shapeFillColor.setEnabled(selected)

    def addLabel(self, shape):
        shape.paintLabel = self.displayLabelOption.isChecked()
        item = HashableQListWidgetItem(shape.label)
        item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
        item.setCheckState(Qt.Checked)
        item.setBackground(generateColorByText(shape.label))
        self.itemsToShapes[item] = shape
        self.shapesToItems[shape] = item
        self.labelList.addItem(item)
        for action in self.actions.onShapesPresent:
            action.setEnabled(True)
        self.updateComboBox()

    def remLabel(self, shape):
        if shape is None:
            # print('rm empty label')
            return
        item = self.shapesToItems[shape]
        self.labelList.takeItem(self.labelList.row(item))
        del self.shapesToItems[shape]
        del self.itemsToShapes[item]
        self.updateComboBox()

    def loadLabels(self, shapes):
        s = []
        for label, points, line_color, fill_color, difficult in shapes:
            shape = Shape(label=label)
            for x, y in points:

                # Ensure the labels are within the bounds of the image. If not, fix them.
                x, y, snapped = self.canvas.snapPointToCanvas(x, y)
                if snapped:
                    self.setDirty()

                shape.addPoint(QPointF(x, y))
            shape.difficult = difficult
            shape.close()
            s.append(shape)

            if line_color:
                shape.line_color = QColor(*line_color)
            else:
                shape.line_color = generateColorByText(label)

            if fill_color:
                shape.fill_color = QColor(*fill_color)
            else:
                shape.fill_color = generateColorByText(label)

            self.addLabel(shape)
        self.updateComboBox()
        self.canvas.loadShapes(s)

    def updateComboBox(self):
        # Get the unique labels and add them to the Combobox.
        itemsTextList = [str(self.labelList.item(i).text()) for i in range(self.labelList.count())]
            
        uniqueTextList = list(set(itemsTextList))
        # Add a null row for showing all the labels
        uniqueTextList.append("")
        uniqueTextList.sort()

        self.comboBox.update_items(uniqueTextList)

    def saveLabels(self, annotationFilePath):
        annotationFilePath = ustr(annotationFilePath)
        if self.labelFile is None:
            self.labelFile = LabelFile()
            self.labelFile.verified = self.canvas.verified
        # p=""
        # p=p.join(annotationFilePath.split('/')[:-1])
        # if not os.path.exists(p):
        #     os.mkdir(p)

        if not os.path.exists('tempDataSetDir/'):
            os.mkdir('tempDataSetDir/')

        def format_shape(s):
            return dict(label=s.label,
                        line_color=s.line_color.getRgb(),
                        fill_color=s.fill_color.getRgb(),
                        points=[(p.x(), p.y()) for p in s.points],
                       # add chris
                        difficult = s.difficult)
        shapes = [format_shape(shape) for shape in self.canvas.shapes]
        for shape in shapes:
            print(shape['label'])
            if shape['label'] not in self.labelHist:
                self.errorMessage('Failed To Save Img', 'Undefined Class')
                return False
        # Can add differrent annotation formats here
        try:
            if self.usingYoloFormat is True:
                if annotationFilePath[-4:].lower() != ".txt":
                    annotationFilePath += TXT_EXT

                self.labelFile.saveYoloFormat(annotationFilePath, shapes, self.filePath, self.imageData, self.labelHist,
                                                   self.lineColor.getRgb(), self.fillColor.getRgb())
            else:
                self.labelFile.save(annotationFilePath, shapes, self.filePath, self.imageData,
                                    self.lineColor.getRgb(), self.fillColor.getRgb())
            print('Image:{0} -> Annotation:{1}'.format(self.filePath, annotationFilePath))
            return True
        except LabelFileError as e:
            self.errorMessage(u'Error saving label data', u'<b>%s</b>' % e)
            return False
        except PermissionError:
            self.errorMessage("No Saving Permission",f'No Permission on {self.filePath}. \nAbort Saving')
            return False

    def copySelectedShape(self):
        copiedShape=self.canvas.copySelectedShape()
        if(copiedShape)==False:
            return
        self.addLabel(copiedShape)
        # fix copy and delete
        self.shapeSelectionChanged(True)
    
    def comboSelectionChanged(self, index):
        text = self.comboBox.cb.itemText(index)
        for i in range(self.labelList.count()):
            if text == "":
                self.labelList.item(i).setCheckState(2) 
            elif text != self.labelList.item(i).text():
                self.labelList.item(i).setCheckState(0)
            else:
                self.labelList.item(i).setCheckState(2)

    def labelSelectionChanged(self):
        item = self.currentItem()
        if item and self.canvas.editing():
            self._noSelectionSlot = True
            self.canvas.selectShape(self.itemsToShapes[item])
            shape = self.itemsToShapes[item]

    def labelItemChanged(self, item):
        shape = self.itemsToShapes[item]
        label = item.text()
        if label != shape.label:
            shape.label = item.text()
            shape.line_color = generateColorByText(shape.label)
            self.setDirty()
        else:  # User probably changed item visibility
            self.canvas.setShapeVisible(shape, item.checkState() == Qt.Checked)

    # Callback functions:
    def newShape(self):
        """
        position MUST be in global coordinates.
        """
        text=self.labelHist[0]
        if text is not None:
            self.prevLabelText = text
            generate_color = generateColorByText(text)
            shape = self.canvas.setLastLabel(text, generate_color, generate_color)
            self.addLabel(shape)
            if self.beginner():  # Switch to edit mode.
                self.canvas.setEditing(True)
                self.actions.create.setEnabled(True)
            else:
                self.actions.editMode.setEnabled(True)
            self.setDirty()

            if text not in self.labelHist:
                self.labelHist.append(text)
        else:
            # self.canvas.undoLastLine()
            self.canvas.resetAllLines()

    def scrollRequest(self, delta, orientation):
        units = - delta / (8 * 15)
        bar = self.scrollBars[orientation]
        bar.setValue(bar.value() + bar.singleStep() * units)

    def setZoom(self, value):
        self.actions.fitWidth.setChecked(False)
        self.actions.fitWindow.setChecked(False)
        self.zoomMode = self.MANUAL_ZOOM
        self.zoomWidget.setValue(value)

    def addZoom(self, increment=10):
        self.setZoom(self.zoomWidget.value() + increment)

    def zoomRequest(self, delta):
        # get the current scrollbar positions
        # calculate the percentages ~ coordinates
        h_bar = self.scrollBars[Qt.Horizontal]
        v_bar = self.scrollBars[Qt.Vertical]

        # get the current maximum, to know the difference after zooming
        h_bar_max = h_bar.maximum()
        v_bar_max = v_bar.maximum()

        # get the cursor position and canvas size
        # calculate the desired movement from 0 to 1
        # where 0 = move left
        #       1 = move right
        # up and down analogous
        cursor = QCursor()
        pos = cursor.pos()
        relative_pos = QWidget.mapFromGlobal(self, pos)

        cursor_x = relative_pos.x()
        cursor_y = relative_pos.y()

        w = self.scrollArea.width()
        h = self.scrollArea.height()

        # the scaling from 0 to 1 has some padding
        # you don't have to hit the very leftmost pixel for a maximum-left movement
        margin = 0.1
        move_x = (cursor_x - margin * w) / (w - 2 * margin * w)
        move_y = (cursor_y - margin * h) / (h - 2 * margin * h)

        # clamp the values from 0 to 1
        move_x = min(max(move_x, 0), 1)
        move_y = min(max(move_y, 0), 1)

        # zoom in
        units = delta / (8 * 15)
        scale = 10
        self.addZoom(scale * units)

        # get the difference in scrollbar values
        # this is how far we can move
        d_h_bar_max = h_bar.maximum() - h_bar_max
        d_v_bar_max = v_bar.maximum() - v_bar_max

        # get the new scrollbar values
        new_h_bar_value = h_bar.value() + move_x * d_h_bar_max
        new_v_bar_value = v_bar.value() + move_y * d_v_bar_max

        h_bar.setValue(new_h_bar_value)
        v_bar.setValue(new_v_bar_value)

    def setFitWindow(self, value=True):
        if value:
            self.actions.fitWidth.setChecked(False)
        self.zoomMode = self.FIT_WINDOW if value else self.MANUAL_ZOOM
        self.adjustScale()

    def setFitWidth(self, value=True):
        if value:
            self.actions.fitWindow.setChecked(False)
        self.zoomMode = self.FIT_WIDTH if value else self.MANUAL_ZOOM
        self.adjustScale()

    def togglePolygons(self, value):
        for item, shape in self.itemsToShapes.items():
            item.setCheckState(Qt.Checked if value else Qt.Unchecked)

    def loadFile(self, filePath=None):
        """Load the specified file, or the last opened file if None."""
        self.resetState()
        self.canvas.setEnabled(False)
        if filePath is None:
            filePath = self.settings.get(SETTING_FILENAME)

        # Make sure that filePath is a regular python string, rather than QString
        filePath = ustr(filePath)

        # Fix bug: An  index error after select a directory when open a new file.
        unicodeFilePath = ustr(filePath)
        unicodeFilePath = os.path.abspath(unicodeFilePath)
        # Tzutalin 20160906 : Add file list and dock to move faster
        # Highlight the file item
        if unicodeFilePath and self.fileListWidget.count() > 0:
            if unicodeFilePath in self.mImgList:
                index = self.mImgList.index(unicodeFilePath)
                fileWidgetItem = self.fileListWidget.item(index)
                fileWidgetItem.setSelected(True)
            else:
                self.fileListWidget.clear()
                self.mImgList.clear()

        # if unicodeFilePath and os.path.exists(unicodeFilePath):
        if unicodeFilePath:
            if LabelFile.isLabelFile(unicodeFilePath):
                try:
                    self.labelFile = LabelFile(unicodeFilePath)
                except LabelFileError as e:
                    self.errorMessage(u'Error opening file',
                                      (u"<p><b>%s</b></p>"
                                       u"<p>Make sure <i>%s</i> is a valid label file.")
                                      % (e, unicodeFilePath))
                    self.status("Error reading %s" % unicodeFilePath)
                    return False
                self.imageData = self.labelFile.imageData
                self.lineColor = QColor(*self.labelFile.lineColor)
                self.fillColor = QColor(*self.labelFile.fillColor)
                self.canvas.verified = self.labelFile.verified
            else:
                # Load image:
                # read data first and store for saving into label file.
                self.imageData = read(unicodeFilePath)
                self.labelFile = None
                self.canvas.verified = False
            image = QImage.fromData(self.imageData)
            if image.isNull():
                self.errorMessage(u'Error opening file',
                                  u"<p>Make sure <i>%s</i> is a valid image file." % unicodeFilePath)
                self.status("Error reading %s" % unicodeFilePath)
                return False
            self.status("Loaded %s" % os.path.basename(unicodeFilePath))
            self.image = image
            self.filePath = unicodeFilePath
            self.canvas.loadPixmap(QPixmap.fromImage(image))
            if self.labelFile:
                self.loadLabels(self.labelFile.shapes)
            self.setClean()
            self.canvas.setEnabled(True)
            self.adjustScale(initial=True)
            self.paintCanvas()
            self.addRecentFile(self.filePath)
            self.toggleActions(True)

            # Label xml file and show bound box according to its filename
            if not self.reviewModeOn:
                if self.defaultSaveDir:
                    basename = os.path.basename(
                        os.path.splitext(self.filePath)[0])
                    txtPath = os.path.join(self.defaultSaveDir, basename + TXT_EXT)
                    if os.path.isfile(txtPath):
                        self.loadYOLOTXTByFilename(txtPath)
            else:
                txtPath = self.filePath[:-3]+"txt"
                self.loadYOLOTXTByFilename(txtPath,cloud=True)


            self.setWindowTitle(__appname__ + ' ' + filePath)

            # Default : select last item if there is at least one item
            if self.labelList.count():
                self.labelList.setCurrentItem(self.labelList.item(self.labelList.count()-1))
                self.labelList.item(self.labelList.count()-1).setSelected(True)

            self.canvas.setFocus(True)
            return True
        return False

    def resizeEvent(self, event):
        try:
            if self.canvas and not self.image.isNull()\
            and self.zoomMode != self.MANUAL_ZOOM:
                self.adjustScale()
            super(MainWindow, self).resizeEvent(event)
        except:
            pass

    def paintCanvas(self):
        assert not self.image.isNull(), "cannot paint null image"
        self.canvas.scale = 0.01 * self.zoomWidget.value()
        self.canvas.adjustSize()
        self.canvas.update()

    def adjustScale(self, initial=False):
        value = self.scalers[self.FIT_WINDOW if initial else self.zoomMode]()
        self.zoomWidget.setValue(int(100 * value))

    def scaleFitWindow(self):
        """Figure out the size of the pixmap in order to fit the main widget."""
        e = 2.0  # So that no scrollbars are generated.
        w1 = self.centralWidget().width() - e
        h1 = self.centralWidget().height() - e
        a1 = w1 / h1
        # Calculate a new scale value based on the pixmap's aspect ratio.
        w2 = self.canvas.pixmap.width() - 0.0
        h2 = self.canvas.pixmap.height() - 0.0
        a2 = w2 / h2
        return w1 / w2 if a2 >= a1 else h1 / h2

    def scaleFitWidth(self):
        # The epsilon does not seem to work too well here.
        w = self.centralWidget().width() - 2.0
        return w / self.canvas.pixmap.width()

    def closeEvent(self, event):
        if not self.mayContinue():
            event.ignore()
        settings = self.settings
        # If it loads images from dir, don't load it at the begining
        if self.dirname is None:
            settings[SETTING_FILENAME] = self.filePath if self.filePath else ''
        else:
            settings[SETTING_FILENAME] = ''

        settings[SETTING_WIN_SIZE] = self.size()
        settings[SETTING_WIN_POSE] = self.pos()
        settings[SETTING_WIN_STATE] = self.saveState()
        settings[SETTING_LINE_COLOR] = self.lineColor
        settings[SETTING_FILL_COLOR] = self.fillColor
        settings[SETTING_RECENT_FILES] = self.recentFiles
        settings[SETTING_ADVANCE_MODE] = not self._beginner
        if self.defaultSaveDir and os.path.exists(self.defaultSaveDir):
            settings[SETTING_SAVE_DIR] = ustr(self.defaultSaveDir)
        else:
            settings[SETTING_SAVE_DIR] = ''

        if self.lastOpenDir and os.path.exists(self.lastOpenDir):
            settings[SETTING_LAST_OPEN_DIR] = self.lastOpenDir
        else:
            settings[SETTING_LAST_OPEN_DIR] = ''

        settings[SETTING_AUTO_SAVE] = self.autoSaving.isChecked()
        settings[SETTING_SINGLE_CLASS] = self.singleClassMode.isChecked()
        settings[SETTING_PAINT_LABEL] = self.displayLabelOption.isChecked()
        settings[SETTING_DRAW_SQUARE] = self.drawSquaresOption.isChecked()
        settings.save()

    def loadRecent(self, filename):
        if self.mayContinue():
            self.loadFile(filename)

    def scanAllImages(self, folderPath):
        extensions = ['.%s' % fmt.data().decode("ascii").lower() for fmt in QImageReader.supportedImageFormats()]
        images = []

        for root, dirs, files in os.walk(folderPath):
            for file in files:
                if file.lower().endswith(tuple(extensions)):
                    relativePath = os.path.join(root, file)
                    path = ustr(os.path.abspath(relativePath))
                    images.append(path)
        natural_sort(images, key=lambda x: x.lower())
        return images

    def changeSavedirDialog(self, _value=False):
        if self.defaultSaveDir is not None:
            path = ustr(self.defaultSaveDir)
        else:
            path = '.'

        dirpath = ustr(QFileDialog.getExistingDirectory(self,
                                                       '%s - Save annotations to the directory' % __appname__, path,  QFileDialog.ShowDirsOnly
                                                       | QFileDialog.DontResolveSymlinks))

        if dirpath is not None and len(dirpath) > 1:
            self.defaultSaveDir = dirpath

        self.statusBar().showMessage('%s . Annotation will be saved to %s' %
                                     ('Change saved folder', self.defaultSaveDir))
        self.statusBar().show()

    def changeDatasetDirDialog(self, _value=False):
        if self.datasetDir is not None:
            path = ustr(self.datasetDir)
        else:
            path = '.'
        directory= ustr(QFileDialog.getExistingDirectory(self,
                                                       '%s - Select Training Dataset Directory' % __appname__, path,  QFileDialog.ShowDirsOnly
                                                       | QFileDialog.DontResolveSymlinks))
        if directory is not None and len(directory) > 1:
            self.closeReviewMode()
            self.datasetDir = directory
            self.readLabelNum(self.datasetDir)

            self.statusBar().showMessage('Changed training dataset directory. Verified img and label will be saved to %s' %
                                        (self.datasetDir))
            self.statusBar().show()

    def closeReviewMode(self):
        if self.reviewModeOn:
            self.reviewModeOn=False
            self.canvas.disabled=False
            self.commentField.hide()
            self.setLabelNum()
            self.defaultSaveDir=self.lastOpenDir
            self.importDirImages(self.lastOpenDir)

    def openExtractDatasetDialog(self):
        self.extractDatasetDialog.show()
        
    def trainAIDialog(self, _value=False):

        labelNumStr=f"Labelled Object In Dataset:\n({self.datasetDir})\n"
        for i,label in enumerate(self.classCount):
            labelNumStr+=self.labelHist[i]+"\t: "+str(label)+"\n"

        dialogStr=f"Do you want to start training Yolov3 model with labelled images in {self.datasetDir} ?\n"
        dialogStr+="Make sure AIVC2 is closed before you start the training.\n"
        dialogStr+="Click 'Yes' to select the model.\nTo start training from scratch, select 'darknet53.conv.74'\nTo continue training checkpoint, select half trained model (e.g.,'yolov3_glove_1000.weight')\n\n"
        for i,label in enumerate(self.classCount):
            dialogStr+=f'{self.labelHist[i]}: {label}\n'

        yes, no = QMessageBox.Yes, QMessageBox.No

        a = QMessageBox.question(self, 'Train Yolov3', dialogStr, yes | no)
        if yes == a:
        # if yes == QMessageBox.warning(self, 'Train Yolov3', dialogStr, yes | no):
            trainingImages = []
            validateImages = []
            for filename in os.listdir(self.datasetDir):
                if filename.endswith(".png") or filename.endswith(".jpg"):
                    if(random.random()>0.1):
                        trainingImages.append(self.datasetDir+'/'+filename)
                    else:
                        validateImages.append(self.datasetDir+'/'+filename)
            with open(f'{THIS_DIR}/data/train.txt', 'w') as outfile:
                for image in trainingImages:
                    outfile.write(image)
                    outfile.write("\n")
                outfile.close()
            with open(f'{THIS_DIR}/data/test.txt', 'w') as outfile:
                for image in validateImages:
                    outfile.write(image)
                    outfile.write("\n")
                outfile.close()

            objStr=f"classes={len(self.labelHist)}\ntrain={THIS_DIR}/data/train.txt\nvalid={THIS_DIR}/data/test.txt\nnames={THIS_DIR}/data/obj.names\nbackup={THIS_DIR}/backup/"
            with open(f'{THIS_DIR}/data/obj.data', 'w') as outfile:
                outfile.write(objStr)
            clsStr=''
            for className in self.labelHist:
                clsStr+=className+'\n'
            with open(f'{THIS_DIR}/data/obj.names', 'w') as outfile:
                outfile.write(clsStr)

            print('data/train.txt Generated')
            print('Start Training Yolov3 Model')
            print(f'Trained Model Will Be Stored in {THIS_DIR}/backup/')
            if not os.path.exists(f'{THIS_DIR}/backup'):
                os.makedirs(f'{THIS_DIR}/backup') 

            self.trainTread = Train_Thread(self,len(self.labelHist))
            self.trainTread.emitError.connect(self.emitError)
            self.trainTread.start()

    def openAnnotationDialog(self, _value=False):
        if self.filePath is None:
            self.statusBar().showMessage('Please select image first')
            self.statusBar().show()
            return

        path = os.path.dirname(ustr(self.filePath))\
            if self.filePath else '.'

    def openDirDialog(self, _value=False, dirpath=None, silent=False):
        if not self.mayContinue():
            return

        defaultOpenDirPath = dirpath if dirpath else '.'
        if self.lastOpenDir and os.path.exists(self.lastOpenDir):
            defaultOpenDirPath = self.lastOpenDir
        else:
            defaultOpenDirPath = os.path.dirname(self.filePath) if self.filePath else '.'
        if silent!=True :
            targetDirPath = ustr(QFileDialog.getExistingDirectory(self,
                                                         '%s - Open Directory' % __appname__, defaultOpenDirPath,
                                                         QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks))
        else:
            targetDirPath = ustr(defaultOpenDirPath)
        if(targetDirPath):
            self.lastOpenDir=targetDirPath
            if self.reviewModeOn:
                self.closeReviewMode()
            else:
                self.defaultSaveDir=self.lastOpenDir
                self.importDirImages(self.lastOpenDir)

    def importDirImages(self, dirpath):
        if not self.mayContinue() or not dirpath:
            return
        self.lastOpenDir = dirpath
        self.dirname = dirpath
        self.filePath = None
        self.fileListWidget.clear()
        self.mImgList = self.scanAllImages(dirpath)
        self.openNextImg()
        for imgPath in self.mImgList:
            item = QListWidgetItem(imgPath)
            self.fileListWidget.addItem(item)

    def verifyImg(self, _value=False):
        if self.reviewModeOn:
            return
        # Proceding next image without dialog if having any label
        if self.filePath is not None:
            if not os.path.isfile(self.filePath):
                print("Can't save img already deleted")
                return
            try:
                self.labelFile.verified=True
            except AttributeError:
                # If the labelling file does not exist yet, create if and
                # re-save it with the verified attribute.
                #if self.filePath in self.mImgList:
                self.saveFile()
                if self.labelFile != None:
                    self.labelFile.toggleVerify()
                else:
                    return
                    
            self.canvas.verified = self.labelFile.verified
            self.paintCanvas()
            imgFileName = os.path.basename(self.filePath)
            savedFileName = os.path.splitext(imgFileName)[0]
            ret=self._saveFile(self.datasetDir + '/' + savedFileName)
            if not ret:
                return
            if self.filePath.split('\\')[:-1] != self.datasetDir.split('/'):
                try:
                    copyfile(self.filePath, self.datasetDir + '/' + imgFileName)
                except SameFileError:
                    print("Saving into same file")
            self.updateLabelNum(savedFileName)
            #self.setLabelNum(self.datasetDir)

    def openPrevImg(self, _value=False):
        # Proceding prev image without dialog if having any label
        if not self.reviewModeOn:
            if self.autoSaving.isChecked():
                if self.defaultSaveDir is not None:
                    if self.dirty is True:
                        self.saveFile()
                        if(self.dirname==self.datasetDir):
                            img=self.filePath.split('\\')[-1][:-4]
                            self.updateLabelNum(img)
                else:
                    self.changeSavedirDialog()
                    return
            if not self.mayContinue():
                return
        else:
            self.commentField.clear()

        if len(self.mImgList) <= 0:
            return

        if self.filePath is None:
            return
        filename=''
        if self.filePath in self.mImgList:
            currIndex = self.mImgList.index(self.filePath)
            if currIndex - 1 >= 0:
                filename = self.mImgList[currIndex - 1]
        else:
            filename = self.mImgList[-1]
        if filename:
            self.loadFile(filename)
            if self.reviewModeOn:
                self.reviewImg=filename.split('\\')[-1][:-4]
                self.loadReviewMetadata()
            self.uploadDialog.hide()
            

    def openNextImg(self, _value=False):
        # Proceding prev image without dialog if having any label
        if not self.reviewModeOn:
            if self.autoSaving.isChecked():
                if self.defaultSaveDir is not None:
                    if self.dirty is True:
                        self.saveFile()
                        if(self.dirname==self.datasetDir):
                            img=self.filePath.split('\\')[-1][:-4]
                            self.updateLabelNum(img)
                # else:
                #     self.changeSavedirDialog()
                #     return

            if not self.mayContinue():
                return
        else:
            self.commentField.clear()

        if len(self.mImgList) <= 0:
            return

        filename = None
        if self.filePath is None:
            filename = self.mImgList[0]
        else:
            if self.filePath in self.mImgList:
                currIndex = self.mImgList.index(self.filePath)
                if currIndex + 1 < len(self.mImgList):
                    filename = self.mImgList[currIndex + 1]
            else:#Deleted last img
                filename=self.mImgList[-1]
        if filename:
            self.loadFile(filename)
            if self.reviewModeOn:
                self.reviewImg=filename.split('\\')[-1][:-4]
                self.loadReviewMetadata()
            self.uploadDialog.hide()

    def loadUserMetadata(self):
        if self.mUser:
            self.mUser.reload()
            self.profile.form_labNum.setText(str(self.mUser.labeledImgNum))
            self.profile.form_revNum.setText(str(self.mUser.reviewedImgNum))
            self.profile.form_falseNum.setText(str(self.mUser.falseLabelNum))
            self.profile.form_relabNum.setText(str(self.mUser.relabeledImgNum))
                            
    def loadReviewMetadata(self):
        print("LOADMETADATA")
        if self.reviewImg:
            imgName=self.reviewImg
            lab=MLabel.objects(pk=imgName).first()
            f=f"{lab.acquireFrom}_{lab.color}_{lab.AIClass}"
            metadataStr=f"Image:{lab.pk}\nFrom:{f}\nLabelUser:{lab.labelUser}\nCreatedAt:{lab.createdAt}"
            for idx,r in enumerate(lab.reviews):
                metadataStr+=f"\nReviewUser{idx+1}:{r.user}\nReviewPassed{idx+1}:{r.passed}\nComment{idx+1}:{r.comment}"
            if lab.toRelabel:
                metadataStr+="\nTORELABEL!"
            self.infoLabel.setText(metadataStr)
        self.loadUserMetadata()

    def openFile(self, _value=False):
        if not self.mayContinue():
            return
        path = os.path.dirname(ustr(self.filePath)) if self.filePath else '.'
        formats = ['*.%s' % fmt.data().decode("ascii").lower() for fmt in QImageReader.supportedImageFormats()]
        filters = "Image & Label files (%s)" % ' '.join(formats + ['*%s' % LabelFile.suffix])
        filename = QFileDialog.getOpenFileName(self, '%s - Choose Image or Label file' % __appname__, path, filters)
        if filename:
            if isinstance(filename, (tuple, list)):
                filename = filename[0]
            self.loadFile(filename)

    def saveFile(self, _value=False):
        if self.defaultSaveDir is not None and len(ustr(self.defaultSaveDir)):
            if self.filePath:
                imgFileName = os.path.basename(self.filePath)
                savedFileName = os.path.splitext(imgFileName)[0]
                savedPath = os.path.join(ustr(self.defaultSaveDir), savedFileName)
                self._saveFile(savedPath)
        else:
            imgFileDir = os.path.dirname(self.filePath)
            imgFileName = os.path.basename(self.filePath)
            savedFileName = os.path.splitext(imgFileName)[0]
            savedPath = os.path.join(imgFileDir, savedFileName)
            self._saveFile(savedPath if self.labelFile
                           else self.saveFileDialog(removeExt=False))

    def saveFileAs(self, _value=False):
        assert not self.image.isNull(), "cannot save empty image"
        self._saveFile(self.saveFileDialog())

    def saveFileDialog(self, removeExt=True):
        caption = '%s - Choose File' % __appname__
        filters = 'File (*%s)' % LabelFile.suffix
        openDialogPath = self.currentPath()
        dlg = QFileDialog(self, caption, openDialogPath, filters)
        dlg.setDefaultSuffix(LabelFile.suffix[1:])
        dlg.setAcceptMode(QFileDialog.AcceptSave)
        filenameWithoutExtension = os.path.splitext(self.filePath)[0]
        dlg.selectFile(filenameWithoutExtension)
        dlg.setOption(QFileDialog.DontUseNativeDialog, False)
        if dlg.exec_():
            fullFilePath = ustr(dlg.selectedFiles()[0])
            if removeExt:
                return os.path.splitext(fullFilePath)[0] # Return file path without the extension.
            else:
                return fullFilePath
        return ''

    def _saveFile(self, annotationFilePath):
        if annotationFilePath and self.saveLabels(annotationFilePath):
            self.setClean()
            self.statusBar().showMessage('Saved to  %s' % annotationFilePath)
            self.statusBar().show()
            return True
        else:
            return False

    def deleteFile(self):
        if self.filePath is None:
            return
        if not os.path.isfile(self.filePath):
            print("Img not exist")
            return
        datasetDir = self.datasetDir
        filePath = self.filePath
        filename = os.path.basename(filePath).split('.')[:-1]
        filename = '.'.join(filename)
            
        if os.path.abspath(datasetDir) == os.path.dirname(filePath):
            self.openNextImg()
            self.deleteLabelNum(filename)
            os.remove(os.path.join(datasetDir,os.path.basename(filePath)))
            try:
                os.remove(os.path.join(datasetDir,filename + '.txt'))
                print(f'Deleted {filename}.txt')
            except FileNotFoundError:
                print('No label file to be delete')
            self.fileListWidget.clear()
            self.mImgList.remove(filePath)
            for imgPath in self.mImgList:
                item = QListWidgetItem(imgPath)
                self.fileListWidget.addItem(item)

            self.statusBar().showMessage(f"Removed {filename} in current directory")
            self.statusBar().show()

        else:
            if os.path.isfile(os.path.abspath(os.path.join(datasetDir,filename + '.txt'))):
                #self.openNextImg()
                self.deleteLabelNum(filename)
                os.remove(os.path.join(datasetDir,os.path.basename(filePath)))
                os.remove(os.path.join(datasetDir,filename + '.txt'))
                self.statusBar().showMessage(f"Removed {filename} in {datasetDir}")
                self.statusBar().show()
            else:
                self.statusBar().showMessage(f"{filename} is not in {datasetDir}")
                self.statusBar().show()
    #def getReviewSpot(self, mlab):


    def approveReview(self,accept):
        if (not self.reviewModeOn) or (not self.reviewImg):
            return
        comment=self.commentField.text()
        lab=MLabel.objects(pk=self.reviewImg).first()
        labUser=MUser.objects(email=lab.labelUser).first()
        replace=False
        prevReject=False
        otherReject=False
        for r in lab.reviews:
            if r.passed==False:
                prevReject=True
            if r.user==self.userDialog.user['email']:
                r.passed=accept
                r.comment=comment
                replace=True
            elif r.passed==False:
                otherReject=True
        currentReject=otherReject
        if not accept:
            currentReject=True
        lab.toRelabel=currentReject
        if not replace:
            newReview=MReview(user=self.userDialog.user['email'],passed=accept,comment=comment)
            self.mUser.reviewedImgNum+=1
            self.mUser.save()
            lab.reviews.append(newReview)
        print(prevReject)
        print(currentReject)
        if prevReject:
            if not currentReject:
                labUser.falseLabelNum-=1
                print("---")
        else:
            if currentReject:
                labUser.falseLabelNum+=1
                print("+++")

        labUser.save()
        lab.save()
        #MLabel.objects(imgPath=self.reviewImg).update_one(**{'set__'+reviewSpot:(self.userDialog.user['email'])},set__firstReviewPassed=accept)
        self.loadReviewMetadata()
        
    def openReviewQuestion(self):
        if not self.userDialog.authenticated:
            self.openLoginDialog()
            return
        self.checkMongoConnection()
        if not self.connectedMongo:
            return
        yes, no = QMessageBox.Yes, QMessageBox.No
        msg = u'Do you want to start review label?'
        if yes == QMessageBox.warning(self, u'Review Label', msg, yes | no):
            self.reviewModeOn=True
            self.canvas.disabled=True
            self.infoLabel.setText("No Label To Review")
            self.commentField.show()
            labels=MLabel.objects(reviews__2__exists=False,toRelabel=False,labelUser__ne=self.userDialog.user['email'],reviews__user__ne=self.userDialog.user['email'],error=0,exception__exists=False)
            self.fileListWidget.clear()
            self.mImgList = []
            for l in labels:
                self.mImgList.append(f"\\\\{NAS_IP}\\AIVC_Cloud\\{l.color}\\{l.id}.jpg")
            self.openNextImg()
            for imgPath in self.mImgList:
                item = QListWidgetItem(imgPath)
                self.fileListWidget.addItem(item)
        else:
            return
    def openUploadDialog(self):
        if self.reviewModeOn:
            return
        if not self.userDialog.authenticated:
            self.openLoginDialog()
            return
        if not self.filePath:
            return
        self.checkMongoConnection()
        if not self.connectedMongo:
            return
        if os.path.isfile(self.filePath):
            self.uploadDialog.form_image.setText(self.filePath)
            self.uploadDialog.form_user.setText(self.userDialog.user['email'])
            try:
                sideStr=self.filePath.split('_')[-3]
                if sideStr in SIDE_SHORT:
                    self.uploadDialog.form_side.setCurrentIndex(SIDE_SHORT.index(sideStr))
            except:
                print("Failed To Read Side")
            self.uploadDialog.show()
        else:
            print(f"Image {self.filePath} not exist")
            return
    def openLoginDialog(self):
        if not self.userDialog.authenticated:
            self.userDialog.show()

    def closeFile(self, _value=False):
        if not self.mayContinue():
            return
        self.resetState()
        self.setClean()
        self.toggleActions(False)
        self.canvas.setEnabled(False)
        self.actions.saveAs.setEnabled(False)

    def resetAll(self):
        self.settings.reset()
        self.close()
        proc = QProcess()
        proc.startDetached(os.path.abspath(__file__))

    def mayContinue(self):
        return not (self.dirty and not self.discardChangesDialog())

    def discardChangesDialog(self):
        yes, no = QMessageBox.Yes, QMessageBox.No
        msg = u'You have unsaved changes, proceed anyway?'
        return yes == QMessageBox.warning(self, u'Attention', msg, yes | no)
    def emitError(self,title,message):
        self.errorMessage(title,message)
    def errorMessage(self, title, message):
        return QMessageBox.critical(self, title,
                                    '<p><b>%s</b></p>%s' % (title, message))

    def currentPath(self):
        return os.path.dirname(self.filePath) if self.filePath else '.'

    def chooseColor1(self):
        color = self.colorDialog.getColor(self.lineColor, u'Choose line color',
                                          default=DEFAULT_LINE_COLOR)
        if color:
            self.lineColor = color
            Shape.line_color = color
            self.canvas.setDrawingColor(color)
            self.canvas.update()
            self.setDirty()

    def deleteSelectedShape(self):
        self.remLabel(self.canvas.deleteSelected())
        self.setDirty()
        if self.noShapes():
            for action in self.actions.onShapesPresent:
                action.setEnabled(False)

    def chshapeLineColor(self):
        color = self.colorDialog.getColor(self.lineColor, u'Choose line color',
                                          default=DEFAULT_LINE_COLOR)
        if color:
            self.canvas.selectedShape.line_color = color
            self.canvas.update()
            self.setDirty()

    def chshapeFillColor(self):
        color = self.colorDialog.getColor(self.fillColor, u'Choose fill color',
                                          default=DEFAULT_FILL_COLOR)
        if color:
            self.canvas.selectedShape.fill_color = color
            self.canvas.update()
            self.setDirty()

    def copyShape(self):
        self.canvas.endMove(copy=True)
        self.addLabel(self.canvas.selectedShape)
        self.setDirty()

    def moveShape(self):
        self.canvas.endMove(copy=False)
        self.setDirty()


    def loadYOLOTXTByFilename(self, txtPath, cloud=False):
        print(txtPath)
        if self.filePath is None:
            return
        # if os.path.isfile(txtPath) is False:
        #     return
        #print(f"label:{self.labelHist}")
        tYoloParseReader = YoloReader(txtPath, self.image, self.labelHist,cloud)
        shapes = tYoloParseReader.getShapes()
        self.loadLabels(shapes)
        self.canvas.verified = tYoloParseReader.verified

    def togglePaintLabelsOption(self):
        for shape in self.canvas.shapes:
            shape.paintLabel = self.displayLabelOption.isChecked()

    def toggleDarkMode(self):
        self.canvas.setDarkMode(self.darkModeOption.isChecked())

    def toogleDrawSquare(self):
        self.canvas.setDrawingShapeToSquare(self.drawSquaresOption.isChecked())
        
    def loadFileListWidget(self,images):
        #natural_sort(images, key=lambda x: x.lower())
        self.mImgList=images
        self.fileListWidget.clear()
        for imgPath in self.mImgList:
            item = QListWidgetItem(imgPath)
            self.fileListWidget.addItem(item)
        self.filePath = None
        self.openNextImg()
        # if self.loadingDialogCS:
        #     self.loadingDialogCS.close()
        self.classSelect.setEnabled(True)

    def classSelectChange(self,i):
        if i == 0:
            self.importDirImages(self.lastOpenDir)
            # self.filePath = None
            # self.openNextImg()
        else:
            self.classSelect.setEnabled(False)
            self.loadingDialogCS=LoadingDialog(parent=self,title=f"Loading Class {self.labelHist[i-1]}")
            classSelectChangeThread=ClassSelectChangeThread(i-1,self.labelHist[i-1],self.lastOpenDir,self)
            classSelectChangeThread.doneLoading.connect(self.loadFileListWidget)
            classSelectChangeThread.updateLoading.connect(self.loadingDialogCS.update)
            classSelectChangeThread.start(3)


def inverted(color):
    return QColor(*[255 - v for v in color.getRgb()])


def read(filename):
    print("read")
    try:
        if os.path.isfile(filename):
            print("normal open")
            with open(filename, 'rb') as f:
                return f.read()
        else:
            print("SMB open")
            with open_file(filename,mode='rb', username="AImodel", password="aimodel123") as fd:
                return fd.read()
    except Exception as e:
        print(f"Read File Exception!:{e}")
        return None



def toggle_stylesheet(checked):
    app = QApplication.instance()
    if app is None:
        raise RuntimeError("No Qt Application found.")
    if checked:
        app.setStyleSheet(qdarkstyle.load_stylesheet())
    else:
        app.setStyleSheet("")
    


def get_main_app(argv=[]):
    """
    Standard boilerplate Qt application code.
    Do everything but app.exec_() -- so that we can test the application in one thread
    """
    app = QApplication(argv)
    app.setApplicationName(__appname__)
    app.setWindowIcon(newIcon("app"))
    win = MainWindow(argv[1] if len(argv) >= 2 else None,
                     argv[2] if len(argv) >= 3 else None,
                     argv[3] if len(argv) >= 4 else None)

    if win.darkModeOption.isChecked():
        checked = True
    else:
        checked = False
    toggle_stylesheet(checked)
    win.darkModeOption.triggered.connect(lambda checked: toggle_stylesheet(checked))
    win.show()
    return app, win


def main():
    '''construct main app and run it'''
    app, _win = get_main_app(sys.argv)
    return app.exec_()

if __name__ == '__main__':
    sys.exit(main())




