from PyQt5.QtWidgets import *
from PyQt5.QtCore import *            
from PyQt5.Qt import *            
import datetime
from authClient import login,verifyToken
import logging
configLogger=logging.getLogger("ConfigLogger")
logger=logging.getLogger("Logger")

TIME_FORMAT="%Y-%m-%d %H:%M:%S"
class UserDialog(QDialog):
    userLoggedIn=pyqtSignal()
    userLoggedOut=pyqtSignal()
    user=None
    authenticated=False
    jwtToken=None
    def __init__(self, parent=None):
        super().__init__(parent, flags=Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
        self.setWindowTitle("Login")
        self.connectedMongo=False
        self.secTimer=QTimer(self)
        self.secTimer.timeout.connect(self.checkAuthExpire)
        self.secTimer.start(10000)
        self.vLayout=QVBoxLayout()
        self.setLayout(self.vLayout)

        #Login Widget
        self.loginWidget=QWidget()
        self.vLayout.addWidget(self.loginWidget)
        self.loginWidget.hide()
        self.loginVLayout=QVBoxLayout()
        self.loginWidget.setLayout(self.loginVLayout)
        self.dataForm=QFormLayout()
        self.loginVLayout.addLayout(self.dataForm)
        self.form_email=QLineEdit()
        self.form_email.setPlaceholderText("email")
        self.form_email.setFixedWidth(110)
        self.form_email.setAlignment(Qt.AlignRight)
        emailWidget=QWidget()
        hLayout=QHBoxLayout()
        hLayout.addWidget(self.form_email)
        hLayout.addWidget(QLabel("@topglove.com.my"))
        hLayout.setContentsMargins(0,0,0,0)
        emailWidget.setLayout(hLayout)
        self.form_pwd=QLineEdit()
        self.form_pwd.setEchoMode(QLineEdit.Password)
        self.dataForm.setWidget(0,QFormLayout.LabelRole, QLabel("Email"))
        self.dataForm.setWidget(0,QFormLayout.FieldRole, emailWidget)
        self.dataForm.setWidget(1,QFormLayout.LabelRole, QLabel("Password"))
        self.dataForm.setWidget(1,QFormLayout.FieldRole, self.form_pwd)
        self.errorLabel=QLabel("")
        self.loginVLayout.addWidget(self.errorLabel)
        btnHLayout=QHBoxLayout()
        self.loginVLayout.addLayout(btnHLayout)
        self.loginBtn=QPushButton("Login")
        self.loginBtn.clicked.connect(self.onLoginClicked)
        btnHLayout.addWidget(self.loginBtn)
        self.registerBtn=QPushButton("Register")
        self.registerBtn.clicked.connect(self.onRegisterClicked)
        btnHLayout.addWidget(self.registerBtn)

        self.setFixedSize(QSize(300, 130))
        self.hide()

        #User Widget
        self.userForm=QFormLayout()
        self.text_email=QLabel()
        self.text_authLvl=QLabel()
        self.text_expAt=QLabel()
        self.btn_logout=QPushButton("Logout")
        self.userWidget=QWidget()
        self.vLayout.addWidget(self.userWidget)
        self.userWidget.hide()
        self.userWidget.setLayout(self.userForm)
        self.userForm.setWidget(0,QFormLayout.LabelRole, QLabel("Email"))
        self.userForm.setWidget(0,QFormLayout.FieldRole, self.text_email)
        self.userForm.setWidget(1,QFormLayout.LabelRole, QLabel("AuthorityLvl"))
        self.userForm.setWidget(1,QFormLayout.FieldRole, self.text_authLvl)
        self.userForm.setWidget(2,QFormLayout.LabelRole, QLabel("ExpireAt"))
        self.userForm.setWidget(2,QFormLayout.FieldRole, self.text_expAt)
        self.userForm.setWidget(3,QFormLayout.LabelRole , self.btn_logout)
        self.btn_logout.clicked.connect(self.logout)
        self.refreshWindow()
    def onRegisterClicked(self):
        url = QUrl("http://10.39.0.11:3000/users")
        QDesktopServices.openUrl(url)

    def onLoginClicked(self):
        email=self.form_email.text()
        pwd=self.form_pwd.text()
        if (not email) or (not pwd):
            self.errorLabel.setText("Please fill in the blanks to continue!")
        else:
            res,msg=login(email,pwd)
            if res:
                self.jwtToken=msg
                self.getUserData()
                self.errorLabel.setText(f"")
                self.hide()
                self.form_pwd.setText("")
            else:
                self.errorLabel.setText(msg)
    def getUserData(self):
        if self.jwtToken:
            res,msg=verifyToken(self.jwtToken)
            if res:
                self.authenticated=True
                self.user=msg
                logger.info(f"User {self.user['email']} [{self.user['authorityLvl']}] Logged In")
                configLogger.info(f"User {self.user['email']} [{self.user['authorityLvl']}] Logged In")
                self.setUser()
                # #Get user details on mongodb
                # if not self.connectedMongo:
                #     self.connectedMongo=connectMongo()
                #     if not self.connectedMongo:
                #         self.uploadDialog.connectionLabel.setText(f"Unable to connect {MONGO_ADDR}")
                #         self.uploadDialog.uploadBtn.setEnabled(False)
                #     else:
                #         self.uploadDialog.connectionLabel.setText(f"Connected {MONGO_ADDR}")
                #         self.uploadDialog.uploadBtn.setEnabled(True)
                # user=MUser.objects(email=msg['email']).first()
                # print(user)
                self.userLoggedIn.emit()
            else:
                self.authenticated=False
                self.user=None
                self.jwtToken=None

    def setUser(self):
        self.text_email.setText(self.user['email']+"@topglove.com.my")
        self.text_authLvl.setText(str(self.user['authorityLvl']))
        self.text_expAt.setText(self.user['expireAt'])
        self.refreshWindow()

    def refreshWindow(self):
        if self.authenticated:
            self.setWindowTitle("Profile")
            self.loginWidget.hide()
            self.userWidget.show()
        else:
            self.setWindowTitle("Login")
            self.loginWidget.show()
            self.userWidget.hide()

    def logout(self):
        logger.info(f"User {self.user['email']} [{self.user['authorityLvl']}] Logged Out")
        configLogger.info(f"User {self.user['email']} [{self.user['authorityLvl']}] Logged Out")
        self.authenticated=False
        self.user=None
        self.jwtToken=None
        self.refreshWindow()  
        self.userLoggedOut.emit()      

    def checkAuthExpire(self):
        if self.authenticated:
            expireTime= datetime.datetime.strptime(self.user['expireAt'], TIME_FORMAT)
            if datetime.datetime.now()>expireTime:
                self.logout()
                return False
            else:
                return True
        else:
            return False