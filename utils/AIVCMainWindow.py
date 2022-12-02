# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'AIVCMainWindow.ui'
#
# Created by: PyQt5 UI code generator 5.12.2
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_AIVCMainWindow(object):
    def setupUi(self, AIVCMainWindow):
        AIVCMainWindow.setObjectName("AIVCMainWindow")
        AIVCMainWindow.resize(1439, 932)
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(11)
        AIVCMainWindow.setFont(font)
        AIVCMainWindow.setMouseTracking(False)
        AIVCMainWindow.setFocusPolicy(QtCore.Qt.StrongFocus)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(":/utils/icons/TG_icon.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        AIVCMainWindow.setWindowIcon(icon)
        AIVCMainWindow.setTabShape(QtWidgets.QTabWidget.Rounded)
        self.CentralWidget = QtWidgets.QWidget(AIVCMainWindow)
        self.CentralWidget.setObjectName("CentralWidget")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.CentralWidget)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.headerLayout = QtWidgets.QHBoxLayout()
        self.headerLayout.setObjectName("headerLayout")
        self.label_logo = QtWidgets.QLabel(self.CentralWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_logo.sizePolicy().hasHeightForWidth())
        self.label_logo.setSizePolicy(sizePolicy)
        self.label_logo.setMaximumSize(QtCore.QSize(100, 40))
        self.label_logo.setPixmap(QtGui.QPixmap(":/utils/icons/tg_logo.png"))
        self.label_logo.setScaledContents(True)
        self.label_logo.setTextInteractionFlags(QtCore.Qt.NoTextInteraction)
        self.label_logo.setObjectName("label_logo")
        self.headerLayout.addWidget(self.label_logo)
        self.label_researcher = QtWidgets.QLabel(self.CentralWidget)
        self.label_researcher.setMaximumSize(QtCore.QSize(160, 40))
        self.label_researcher.setText("")
        self.label_researcher.setPixmap(QtGui.QPixmap(":/utils/icons/ResearcherLogoHorizontal.jpg"))
        self.label_researcher.setScaledContents(True)
        self.label_researcher.setObjectName("label_researcher")
        self.headerLayout.addWidget(self.label_researcher)
        spacerItem = QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Minimum)
        self.headerLayout.addItem(spacerItem)
        self.label_title = QtWidgets.QLabel(self.CentralWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_title.sizePolicy().hasHeightForWidth())
        self.label_title.setSizePolicy(sizePolicy)
        self.label_title.setMaximumSize(QtCore.QSize(1200, 80))
        font = QtGui.QFont()
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_title.setFont(font)
        self.label_title.setAlignment(QtCore.Qt.AlignCenter)
        self.label_title.setWordWrap(True)
        self.label_title.setTextInteractionFlags(QtCore.Qt.NoTextInteraction)
        self.label_title.setObjectName("label_title")
        self.headerLayout.addWidget(self.label_title)
        self.label_version = QtWidgets.QLabel(self.CentralWidget)
        self.label_version.setScaledContents(False)
        self.label_version.setObjectName("label_version")
        self.headerLayout.addWidget(self.label_version)
        spacerItem1 = QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Minimum)
        self.headerLayout.addItem(spacerItem1)
        self.headerLayout.setStretch(2, 25)
        self.headerLayout.setStretch(3, 40)
        self.headerLayout.setStretch(5, 7)
        self.verticalLayout_2.addLayout(self.headerLayout)
        self.tab_main = QtWidgets.QTabWidget(self.CentralWidget)
        self.tab_main.setEnabled(True)
        self.tab_main.setObjectName("tab_main")
        self.tab_fingertip = QtWidgets.QWidget()
        self.tab_fingertip.setEnabled(True)
        self.tab_fingertip.setObjectName("tab_fingertip")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.tab_fingertip)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setSpacing(0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.tabWidget = QtWidgets.QTabWidget(self.tab_fingertip)
        self.tabWidget.setObjectName("tabWidget")
        self.tab_fingertip_cam = QtWidgets.QWidget()
        self.tab_fingertip_cam.setObjectName("tab_fingertip_cam")
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout(self.tab_fingertip_cam)
        self.horizontalLayout_5.setContentsMargins(1, 1, 1, 1)
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.scrollArea_2 = QtWidgets.QScrollArea(self.tab_fingertip_cam)
        self.scrollArea_2.setWidgetResizable(True)
        self.scrollArea_2.setObjectName("scrollArea_2")
        self.scrollAreaWidgetContents = QtWidgets.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 1025, 800))
        self.scrollAreaWidgetContents.setObjectName("scrollAreaWidgetContents")
        self.gridLayout_4 = QtWidgets.QGridLayout(self.scrollAreaWidgetContents)
        self.gridLayout_4.setContentsMargins(5, 5, 5, 5)
        self.gridLayout_4.setObjectName("gridLayout_4")
        self.grid_fingertip_cam = QtWidgets.QGridLayout()
        self.grid_fingertip_cam.setObjectName("grid_fingertip_cam")
        self.gridLayout_4.addLayout(self.grid_fingertip_cam, 0, 0, 1, 1)
        self.scrollArea_2.setWidget(self.scrollAreaWidgetContents)
        self.horizontalLayout_5.addWidget(self.scrollArea_2)
        self.tabWidget.addTab(self.tab_fingertip_cam, "")
        self.tab_chain_data = QtWidgets.QWidget()
        self.tab_chain_data.setObjectName("tab_chain_data")
        self.horizontalLayout_10 = QtWidgets.QHBoxLayout(self.tab_chain_data)
        self.horizontalLayout_10.setContentsMargins(1, 1, 1, 1)
        self.horizontalLayout_10.setObjectName("horizontalLayout_10")
        self.scrollArea_3 = QtWidgets.QScrollArea(self.tab_chain_data)
        self.scrollArea_3.setWidgetResizable(True)
        self.scrollArea_3.setObjectName("scrollArea_3")
        self.scrollAreaWidgetContents_3 = QtWidgets.QWidget()
        self.scrollAreaWidgetContents_3.setGeometry(QtCore.QRect(0, 0, 1025, 800))
        self.scrollAreaWidgetContents_3.setObjectName("scrollAreaWidgetContents_3")
        self.gridLayout_7 = QtWidgets.QGridLayout(self.scrollAreaWidgetContents_3)
        self.gridLayout_7.setContentsMargins(5, 5, 5, 5)
        self.gridLayout_7.setObjectName("gridLayout_7")
        self.grid_chain_data = QtWidgets.QGridLayout()
        self.grid_chain_data.setObjectName("grid_chain_data")
        self.gridLayout_7.addLayout(self.grid_chain_data, 0, 0, 1, 1)
        self.scrollArea_3.setWidget(self.scrollAreaWidgetContents_3)
        self.horizontalLayout_10.addWidget(self.scrollArea_3)
        self.tabWidget.addTab(self.tab_chain_data, "")
        self.verticalLayout.addWidget(self.tabWidget)
        self.tab_main.addTab(self.tab_fingertip, "")
        self.tab_rasm = QtWidgets.QWidget()
        self.tab_rasm.setObjectName("tab_rasm")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.tab_rasm)
        self.verticalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_3.setSpacing(0)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.tabWidget_2 = QtWidgets.QTabWidget(self.tab_rasm)
        self.tabWidget_2.setObjectName("tabWidget_2")
        self.tab_rasm_cam = QtWidgets.QWidget()
        self.tab_rasm_cam.setObjectName("tab_rasm_cam")
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout(self.tab_rasm_cam)
        self.horizontalLayout_7.setContentsMargins(1, 1, 1, 1)
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.scrollArea = QtWidgets.QScrollArea(self.tab_rasm_cam)
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setObjectName("scrollArea")
        self.scrollAreaWidgetContents_2 = QtWidgets.QWidget()
        self.scrollAreaWidgetContents_2.setGeometry(QtCore.QRect(0, 0, 1025, 800))
        self.scrollAreaWidgetContents_2.setObjectName("scrollAreaWidgetContents_2")
        self.gridLayout_3 = QtWidgets.QGridLayout(self.scrollAreaWidgetContents_2)
        self.gridLayout_3.setContentsMargins(5, 5, 5, 5)
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.grid_rasm_cam = QtWidgets.QGridLayout()
        self.grid_rasm_cam.setObjectName("grid_rasm_cam")
        self.gridLayout_3.addLayout(self.grid_rasm_cam, 0, 0, 1, 1)
        self.scrollArea.setWidget(self.scrollAreaWidgetContents_2)
        self.horizontalLayout_7.addWidget(self.scrollArea)
        self.tabWidget_2.addTab(self.tab_rasm_cam, "")
        self.tab_rasm_data = QtWidgets.QWidget()
        self.tab_rasm_data.setObjectName("tab_rasm_data")
        self.gridLayout_5 = QtWidgets.QGridLayout(self.tab_rasm_data)
        self.gridLayout_5.setContentsMargins(1, 1, 1, 1)
        self.gridLayout_5.setObjectName("gridLayout_5")
        self.scrollArea_4 = QtWidgets.QScrollArea(self.tab_rasm_data)
        self.scrollArea_4.setWidgetResizable(True)
        self.scrollArea_4.setObjectName("scrollArea_4")
        self.scrollAreaWidgetContents_4 = QtWidgets.QWidget()
        self.scrollAreaWidgetContents_4.setGeometry(QtCore.QRect(0, 0, 98, 28))
        self.scrollAreaWidgetContents_4.setObjectName("scrollAreaWidgetContents_4")
        self.gridLayout_8 = QtWidgets.QGridLayout(self.scrollAreaWidgetContents_4)
        self.gridLayout_8.setContentsMargins(5, 5, 5, 5)
        self.gridLayout_8.setObjectName("gridLayout_8")
        self.grid_rasm_data = QtWidgets.QGridLayout()
        self.grid_rasm_data.setObjectName("grid_rasm_data")
        self.gridLayout_8.addLayout(self.grid_rasm_data, 0, 0, 1, 1)
        self.scrollArea_4.setWidget(self.scrollAreaWidgetContents_4)
        self.gridLayout_5.addWidget(self.scrollArea_4, 0, 0, 1, 1)
        self.tabWidget_2.addTab(self.tab_rasm_data, "")

        self.tab_rasm_chart = QtWidgets.QWidget()
        self.tab_rasm_chart.setObjectName("tab_rasm_chart")
        self.gridLayout_6 = QtWidgets.QGridLayout(self.tab_rasm_chart)
        self.gridLayout_6.setContentsMargins(1, 1, 1, 1)
        self.gridLayout_6.setObjectName("gridLayout_6")
        self.scrollArea_5 = QtWidgets.QScrollArea(self.tab_rasm_chart)
        self.scrollArea_5.setWidgetResizable(True)
        self.scrollArea_5.setObjectName("scrollArea_5")
        self.scrollAreaWidgetContents_5 = QtWidgets.QWidget()
        self.scrollAreaWidgetContents_5.setGeometry(QtCore.QRect(0, 0, 98, 28))
        self.scrollAreaWidgetContents_5.setObjectName("scrollAreaWidgetContents_5")
        self.gridLayout_9 = QtWidgets.QGridLayout(self.scrollAreaWidgetContents_5)
        self.gridLayout_9.setContentsMargins(5, 5, 5, 5)
        self.gridLayout_9.setObjectName("gridLayout_9")
        self.grid_rasm_chart = QtWidgets.QGridLayout()
        self.grid_rasm_chart.setObjectName("grid_rasm_chart")
        self.gridLayout_9.addLayout(self.grid_rasm_chart, 0, 0, 1, 1)
        self.scrollArea_5.setWidget(self.scrollAreaWidgetContents_5)
        self.gridLayout_6.addWidget(self.scrollArea_5, 0, 0, 1, 1)
        self.tabWidget_2.addTab(self.tab_rasm_chart, "")

        self.verticalLayout_3.addWidget(self.tabWidget_2)
        self.tab_main.addTab(self.tab_rasm, "")
        self.verticalLayout_2.addWidget(self.tab_main)
        self.horizontalLayout_2.addLayout(self.verticalLayout_2)
        self.gridLayout_2 = QtWidgets.QGridLayout()
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.table_defect_data = QtWidgets.QTableWidget(self.CentralWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.table_defect_data.sizePolicy().hasHeightForWidth())
        self.table_defect_data.setSizePolicy(sizePolicy)
        self.table_defect_data.setMaximumSize(QtCore.QSize(16777215, 230))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(8)
        self.table_defect_data.setFont(font)
        self.table_defect_data.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.table_defect_data.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.table_defect_data.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.table_defect_data.setAutoScroll(False)
        self.table_defect_data.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table_defect_data.setAlternatingRowColors(True)
        self.table_defect_data.setCornerButtonEnabled(False)
        self.table_defect_data.setObjectName("table_defect_data")
        self.table_defect_data.setColumnCount(5)
        self.table_defect_data.setRowCount(4)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setVerticalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setVerticalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setVerticalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setVerticalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setItem(0, 0, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setItem(0, 1, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setItem(0, 2, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setItem(0, 3, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setItem(0, 4, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setItem(1, 0, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setItem(1, 1, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setItem(1, 2, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setItem(1, 3, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setItem(1, 4, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setItem(2, 0, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setItem(2, 1, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setItem(2, 2, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setItem(2, 3, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setItem(2, 4, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setItem(3, 0, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setItem(3, 1, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setItem(3, 2, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setItem(3, 3, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_defect_data.setItem(3, 4, item)
        self.table_defect_data.horizontalHeader().setCascadingSectionResizes(True)
        self.table_defect_data.horizontalHeader().setDefaultSectionSize(50)
        self.table_defect_data.horizontalHeader().setSortIndicatorShown(False)
        self.table_defect_data.horizontalHeader().setStretchLastSection(False)
        self.gridLayout_2.addWidget(self.table_defect_data, 10, 1, 1, 4)
        self.text_aveLineSpeed = QtWidgets.QLabel(self.CentralWidget)
        self.text_aveLineSpeed.setObjectName("text_aveLineSpeed")
        self.gridLayout_2.addWidget(self.text_aveLineSpeed, 11, 2, 1, 1)

        self.text_aveProbFormer = QtWidgets.QLabel(self.CentralWidget)
        self.text_aveProbFormer.setObjectName("text_aveProbFormer")
        self.gridLayout_2.addWidget(self.text_aveProbFormer, 13, 2, 1, 1)

        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.btn_start = QtWidgets.QPushButton(self.CentralWidget)
        self.btn_start.setMinimumSize(QtCore.QSize(30, 35))
        self.btn_start.setMaximumSize(QtCore.QSize(250, 35))
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(":/utils/icons/Capture.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.btn_start.setIcon(icon1)
        self.btn_start.setIconSize(QtCore.QSize(35, 35))
        self.btn_start.setObjectName("btn_start")
        self.horizontalLayout_3.addWidget(self.btn_start)
        self.btn_label = QtWidgets.QPushButton(self.CentralWidget)
        self.btn_label.setMinimumSize(QtCore.QSize(30, 35))
        self.btn_label.setMaximumSize(QtCore.QSize(250, 35))
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(":/utils/icons/create.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.btn_label.setIcon(icon2)
        self.btn_label.setIconSize(QtCore.QSize(33, 33))
        self.btn_label.setObjectName("btn_label")
        self.horizontalLayout_3.addWidget(self.btn_label)
        self.btn_login = QtWidgets.QPushButton(self.CentralWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.btn_login.sizePolicy().hasHeightForWidth())
        self.btn_login.setSizePolicy(sizePolicy)
        self.btn_login.setMinimumSize(QtCore.QSize(33, 33))
        self.btn_login.setMaximumSize(QtCore.QSize(33, 33))
        self.btn_login.setText("")
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap(":/utils/icons/login.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.btn_login.setIcon(icon3)
        self.btn_login.setIconSize(QtCore.QSize(28, 28))
        self.btn_login.setObjectName("btn_login")
        self.horizontalLayout_3.addWidget(self.btn_login)
        self.btn_exit = QtWidgets.QPushButton(self.CentralWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.btn_exit.sizePolicy().hasHeightForWidth())
        self.btn_exit.setSizePolicy(sizePolicy)
        self.btn_exit.setMinimumSize(QtCore.QSize(33, 33))
        self.btn_exit.setMaximumSize(QtCore.QSize(33, 33))
        self.btn_exit.setText("")
        icon4 = QtGui.QIcon()
        icon4.addPixmap(QtGui.QPixmap(":/utils/icons/exit.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.btn_exit.setIcon(icon4)
        self.btn_exit.setIconSize(QtCore.QSize(26, 26))
        self.btn_exit.setObjectName("btn_exit")
        self.horizontalLayout_3.addWidget(self.btn_exit)
        self.gridLayout_2.addLayout(self.horizontalLayout_3, 3, 1, 1, 4)
        spacerItem2 = QtWidgets.QSpacerItem(20, 2, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_2.addItem(spacerItem2, 2, 1, 1, 4)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setSpacing(6)
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        spacerItem3 = QtWidgets.QSpacerItem(1, 1, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem3)
        # syafii edit
        self.btn_model = QtWidgets.QPushButton(self.CentralWidget)
        self.btn_model.setMinimumSize(QtCore.QSize(33, 33))
        self.btn_model.setMaximumSize(QtCore.QSize(33, 33))
        self.btn_model.setText("")
        icon9 = QtGui.QIcon()
        icon9.addPixmap(QtGui.QPixmap(":/utils/icons//brain2.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.btn_model.setIcon(icon9)
        self.btn_model.setIconSize(QtCore.QSize(26, 26))
        self.btn_model.setObjectName("btn_model")
        self.horizontalLayout_4.addWidget(self.btn_model)
        # syafii edit
        self.btn_plc = QtWidgets.QPushButton(self.CentralWidget)
        self.btn_plc.setMinimumSize(QtCore.QSize(33, 33))
        self.btn_plc.setMaximumSize(QtCore.QSize(33, 33))
        self.btn_plc.setText("")
        icon5 = QtGui.QIcon()
        icon5.addPixmap(QtGui.QPixmap(":/utils/icons/plc.jpg"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.btn_plc.setIcon(icon5)
        self.btn_plc.setIconSize(QtCore.QSize(26, 26))
        self.btn_plc.setObjectName("btn_plc")
        self.horizontalLayout_4.addWidget(self.btn_plc)
        self.btn_history = QtWidgets.QPushButton(self.CentralWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.btn_history.sizePolicy().hasHeightForWidth())
        self.btn_history.setSizePolicy(sizePolicy)
        self.btn_history.setMinimumSize(QtCore.QSize(33, 33))
        self.btn_history.setMaximumSize(QtCore.QSize(33, 33))
        self.btn_history.setText("")
        icon6 = QtGui.QIcon()
        icon6.addPixmap(QtGui.QPixmap(":/utils/icons/history.jpg"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.btn_history.setIcon(icon6)
        self.btn_history.setIconSize(QtCore.QSize(24, 24))
        self.btn_history.setObjectName("btn_history")
        self.horizontalLayout_4.addWidget(self.btn_history)
        self.btn_info = QtWidgets.QPushButton(self.CentralWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.btn_info.sizePolicy().hasHeightForWidth())
        self.btn_info.setSizePolicy(sizePolicy)
        self.btn_info.setMinimumSize(QtCore.QSize(33, 33))
        self.btn_info.setMaximumSize(QtCore.QSize(33, 33))
        self.btn_info.setText("")
        icon7 = QtGui.QIcon()
        icon7.addPixmap(QtGui.QPixmap(":/utils/icons/zoom.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.btn_info.setIcon(icon7)
        self.btn_info.setIconSize(QtCore.QSize(28, 28))
        self.btn_info.setObjectName("btn_info")
        self.horizontalLayout_4.addWidget(self.btn_info)
        self.btn_setting = QtWidgets.QPushButton(self.CentralWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.btn_setting.sizePolicy().hasHeightForWidth())
        self.btn_setting.setSizePolicy(sizePolicy)
        self.btn_setting.setMinimumSize(QtCore.QSize(33, 33))
        self.btn_setting.setMaximumSize(QtCore.QSize(33, 33))
        self.btn_setting.setText("")
        icon8 = QtGui.QIcon()
        icon8.addPixmap(QtGui.QPixmap(":/utils/icons/settings.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.btn_setting.setIcon(icon8)
        self.btn_setting.setIconSize(QtCore.QSize(28, 28))
        self.btn_setting.setObjectName("btn_setting")
        self.horizontalLayout_4.addWidget(self.btn_setting)
        self.gridLayout_2.addLayout(self.horizontalLayout_4, 1, 3, 1, 2)
        spacerItem4 = QtWidgets.QSpacerItem(20, 2, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_2.addItem(spacerItem4, 4, 1, 1, 4)
        self.label = QtWidgets.QLabel(self.CentralWidget)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setTextInteractionFlags(QtCore.Qt.NoTextInteraction)
        self.label.setObjectName("label")
        self.gridLayout_2.addWidget(self.label, 7, 1, 1, 4)
        self.text_curLineSpeed = QtWidgets.QLabel(self.CentralWidget)
        self.text_curLineSpeed.setObjectName("text_curLineSpeed")
        self.gridLayout_2.addWidget(self.text_curLineSpeed, 12, 2, 1, 1)
        self.label_5 = QtWidgets.QLabel(self.CentralWidget)
        self.label_5.setObjectName("label_5")
        self.gridLayout_2.addWidget(self.label_5, 12, 1, 1, 1)
        self.label_startTime = QtWidgets.QLabel(self.CentralWidget)
        self.label_startTime.setObjectName("label_startTime")
        self.gridLayout_2.addWidget(self.label_startTime, 9, 3, 1, 2)
        self.label_3 = QtWidgets.QLabel(self.CentralWidget)
        self.label_3.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.label_3.setObjectName("label_3")
        self.gridLayout_2.addWidget(self.label_3, 9, 2, 1, 1)
        self.img_view = QtWidgets.QLabel(self.CentralWidget)
        self.img_view.setMinimumSize(QtCore.QSize(360, 270))
        self.img_view.setMaximumSize(QtCore.QSize(360, 270))
        self.img_view.setFrameShape(QtWidgets.QFrame.Panel)
        self.img_view.setScaledContents(False)
        self.img_view.setAlignment(QtCore.Qt.AlignCenter)
        self.img_view.setObjectName("img_view")
        self.gridLayout_2.addWidget(self.img_view, 6, 1, 1, 4)
        self.select_duration = QtWidgets.QComboBox(self.CentralWidget)
        self.select_duration.setObjectName("select_duration")
        self.select_duration.addItem("")
        self.select_duration.addItem("")
        self.select_duration.addItem("")
        self.select_duration.addItem("")
        self.select_duration.addItem("")
        self.select_duration.addItem("")
        self.gridLayout_2.addWidget(self.select_duration, 9, 1, 1, 1)
        self.listWidget = QtWidgets.QListWidget(self.CentralWidget)
        self.listWidget.setMinimumSize(QtCore.QSize(0, 90))
        self.listWidget.setMaximumSize(QtCore.QSize(16777215, 130))
        self.listWidget.setObjectName("listWidget")
        self.gridLayout_2.addWidget(self.listWidget, 5, 1, 1, 4)
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.label_user = QtWidgets.QLabel(self.CentralWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_user.sizePolicy().hasHeightForWidth())
        self.label_user.setSizePolicy(sizePolicy)
        self.label_user.setMinimumSize(QtCore.QSize(0, 30))
        self.label_user.setMaximumSize(QtCore.QSize(150, 100))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_user.setFont(font)
        self.label_user.setAlignment(QtCore.Qt.AlignCenter)
        self.label_user.setTextInteractionFlags(QtCore.Qt.NoTextInteraction)
        self.label_user.setObjectName("label_user")
        self.horizontalLayout_6.addWidget(self.label_user)
        self.gridLayout_2.addLayout(self.horizontalLayout_6, 1, 1, 1, 2)
        self.label_clock = QtWidgets.QLabel(self.CentralWidget)
        palette = QtGui.QPalette()
        brush = QtGui.QBrush(QtGui.QColor(0, 60, 182))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Text, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 60, 182))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Text, brush)
        brush = QtGui.QBrush(QtGui.QColor(120, 120, 120))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Text, brush)
        self.label_clock.setPalette(palette)
        font = QtGui.QFont()
        font.setPointSize(14)
        font.setBold(True)
        font.setWeight(75)
        self.label_clock.setFont(font)
        self.label_clock.setAlignment(QtCore.Qt.AlignCenter)
        self.label_clock.setTextInteractionFlags(QtCore.Qt.NoTextInteraction)
        self.label_clock.setObjectName("label_clock")
        self.gridLayout_2.addWidget(self.label_clock, 0, 1, 1, 4)
        self.label_2 = QtWidgets.QLabel(self.CentralWidget)
        self.label_2.setObjectName("label_2")
        self.gridLayout_2.addWidget(self.label_2, 11, 1, 1, 1)

        self.label_6 = QtWidgets.QLabel(self.CentralWidget)
        self.label_6.setObjectName("label_6")
        self.gridLayout_2.addWidget(self.label_6, 13, 1, 1, 1)

        spacerItem5 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout_2.addItem(spacerItem5, 13, 1, 1, 1)
        self.horizontalLayout_2.addLayout(self.gridLayout_2)
        self.horizontalLayout_2.setStretch(0, 75)
        AIVCMainWindow.setCentralWidget(self.CentralWidget)

        self.retranslateUi(AIVCMainWindow)
        self.tab_main.setCurrentIndex(1)
        self.tabWidget.setCurrentIndex(0)
        self.tabWidget_2.setCurrentIndex(0)
        self.select_duration.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(AIVCMainWindow)

    def retranslateUi(self, AIVCMainWindow):
        _translate = QtCore.QCoreApplication.translate
        AIVCMainWindow.setWindowTitle(_translate("AIVCMainWindow", "Integrated AIVC System"))
        self.label_title.setText(_translate("AIVCMainWindow", "AIVC System"))
        self.label_version.setText(_translate("AIVCMainWindow", "version"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_fingertip_cam), _translate("AIVCMainWindow", "Camera"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_chain_data), _translate("AIVCMainWindow", "Data"))
        self.tab_main.setTabText(self.tab_main.indexOf(self.tab_fingertip), _translate("AIVCMainWindow", "FK/TH"))
        self.tabWidget_2.setTabText(self.tabWidget_2.indexOf(self.tab_rasm_cam), _translate("AIVCMainWindow", "Camera"))
        self.tabWidget_2.setTabText(self.tabWidget_2.indexOf(self.tab_rasm_data), _translate("AIVCMainWindow", "Data"))
        self.tabWidget_2.setTabText(self.tabWidget_2.indexOf(self.tab_rasm_chart), _translate("AIVCMainWindow", "Chart"))
        self.tab_main.setTabText(self.tab_main.indexOf(self.tab_rasm), _translate("AIVCMainWindow", "RASM"))
        item = self.table_defect_data.verticalHeaderItem(0)
        item.setText(_translate("AIVCMainWindow", "Defective Rate"))
        item = self.table_defect_data.verticalHeaderItem(1)
        item.setText(_translate("AIVCMainWindow", "Good Glove"))
        item = self.table_defect_data.verticalHeaderItem(2)
        item.setText(_translate("AIVCMainWindow", "Produced Glove"))
        item = self.table_defect_data.verticalHeaderItem(3)
        item.setText(_translate("AIVCMainWindow", "Empty Link"))
        item = self.table_defect_data.horizontalHeaderItem(0)
        item.setText(_translate("AIVCMainWindow", "LI"))
        item = self.table_defect_data.horizontalHeaderItem(1)
        item.setText(_translate("AIVCMainWindow", "RI"))
        item = self.table_defect_data.horizontalHeaderItem(2)
        item.setText(_translate("AIVCMainWindow", "LO"))
        item = self.table_defect_data.horizontalHeaderItem(3)
        item.setText(_translate("AIVCMainWindow", "RO"))
        item = self.table_defect_data.horizontalHeaderItem(4)
        item.setText(_translate("AIVCMainWindow", "Total"))
        __sortingEnabled = self.table_defect_data.isSortingEnabled()
        self.table_defect_data.setSortingEnabled(False)
        item = self.table_defect_data.item(0, 0)
        item.setText(_translate("AIVCMainWindow", "0"))
        item = self.table_defect_data.item(0, 1)
        item.setText(_translate("AIVCMainWindow", "0"))
        item = self.table_defect_data.item(0, 2)
        item.setText(_translate("AIVCMainWindow", "0"))
        item = self.table_defect_data.item(0, 3)
        item.setText(_translate("AIVCMainWindow", "0"))
        item = self.table_defect_data.item(0, 4)
        item.setText(_translate("AIVCMainWindow", "0"))
        item = self.table_defect_data.item(1, 0)
        item.setText(_translate("AIVCMainWindow", "0"))
        item = self.table_defect_data.item(1, 1)
        item.setText(_translate("AIVCMainWindow", "0"))
        item = self.table_defect_data.item(1, 2)
        item.setText(_translate("AIVCMainWindow", "0"))
        item = self.table_defect_data.item(1, 3)
        item.setText(_translate("AIVCMainWindow", "0"))
        item = self.table_defect_data.item(1, 4)
        item.setText(_translate("AIVCMainWindow", "0"))
        item = self.table_defect_data.item(2, 0)
        item.setText(_translate("AIVCMainWindow", "0"))
        item = self.table_defect_data.item(2, 1)
        item.setText(_translate("AIVCMainWindow", "0"))
        item = self.table_defect_data.item(2, 2)
        item.setText(_translate("AIVCMainWindow", "0"))
        item = self.table_defect_data.item(2, 3)
        item.setText(_translate("AIVCMainWindow", "0"))
        item = self.table_defect_data.item(2, 4)
        item.setText(_translate("AIVCMainWindow", "0"))
        item = self.table_defect_data.item(3, 0)
        item.setText(_translate("AIVCMainWindow", "0"))
        item = self.table_defect_data.item(3, 1)
        item.setText(_translate("AIVCMainWindow", "0"))
        item = self.table_defect_data.item(3, 2)
        item.setText(_translate("AIVCMainWindow", "0"))
        item = self.table_defect_data.item(3, 3)
        item.setText(_translate("AIVCMainWindow", "0"))
        item = self.table_defect_data.item(3, 4)
        item.setText(_translate("AIVCMainWindow", "0"))
        self.table_defect_data.setSortingEnabled(__sortingEnabled)
        self.text_aveLineSpeed.setText(_translate("AIVCMainWindow", "--"))
        #self.text_aveProbFormer.setText(_translate("AIVCMainWindow", "--"))
        self.btn_start.setText(_translate("AIVCMainWindow", "Stop Capturing"))
        self.btn_label.setText(_translate("AIVCMainWindow", "Label"))
        self.label.setText(_translate("AIVCMainWindow", "Defect Data"))
        self.text_curLineSpeed.setText(_translate("AIVCMainWindow", "--"))
        self.label_5.setText(_translate("AIVCMainWindow", "Current Line Speed:"))
        self.label_startTime.setText(_translate("AIVCMainWindow", "Time"))
        self.label_3.setText(_translate("AIVCMainWindow", "Since"))
        self.img_view.setText(_translate("AIVCMainWindow", "No Image Selected"))
        self.select_duration.setCurrentText(_translate("AIVCMainWindow", "Start"))
        self.select_duration.setItemText(0, _translate("AIVCMainWindow", "Start"))
        self.select_duration.setItemText(1, _translate("AIVCMainWindow", "Day"))
        self.select_duration.setItemText(2, _translate("AIVCMainWindow", "Hour"))
        self.select_duration.setItemText(3, _translate("AIVCMainWindow", "30 minute"))
        self.select_duration.setItemText(4, _translate("AIVCMainWindow", "15 minute"))
        self.select_duration.setItemText(5, _translate("AIVCMainWindow", "Minute"))
        self.label_user.setText(_translate("AIVCMainWindow", "User"))
        self.label_clock.setText(_translate("AIVCMainWindow", "DD/MM/YYYY HH:MM:SS"))
        self.label_2.setText(_translate("AIVCMainWindow", "Average Line Speed:"))
        #self.label_6.setText(_translate("AIVCMainWindow", "Average Prob. Former:"))


import utils.icons
