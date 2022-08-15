from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
TIME_FORMAT="%Y-%m-%d %H:%M:%S"
class IndexedButton(QPushButton):
    def __init__(self, seq, name='', parent=None):
        super().__init__(name,parent=parent)
        self.seq=seq

class ChildButton(QPushButton):
    def __init__(self, upper, name='', parent=None):
        super().__init__(name,parent=parent)
        self.upper=upper
class ChildCheckBox(QCheckBox):
    def __init__(self, upper, name='', parent=None):
        super().__init__(name,parent=parent)
        self.upper=upper

class IndexedCheckBox(QCheckBox):
    def __init__(self, seq, name, parent=None):
        super().__init__(name,parent=parent)
        self.seq=seq

class IndexedSpinBox(QSpinBox):
    def __init__(self, seq, _min=0, _max=0, parent=None):
        super().__init__(parent=parent)
        self.seq=seq
        self._min=_min
        self._max=_max
        self.setRange(_min,_max)
        self.setSingleStep(1)

class RasmAnchorOffsetLineEdit(QWidget):
    def __init__(self, seq, parent=None):
        super().__init__(parent=parent)
        self.seq=seq
        self.setMaximumWidth(120)
        hbox=QHBoxLayout()
        hbox.setContentsMargins(0,0,0,0)
        self.setLayout(hbox)
        hbox.setSpacing(0)
        hbox.addWidget(QLabel('Anchor Offset:'))
        self.lineEdit=LineEditLimInt(min=-50, max=50, hint='number',parent=self)
        hbox.addWidget(self.lineEdit)
        self.lineEdit.setMaximumWidth(20)
        self.hide()

class LRSpinBox(QWidget):
    def __init__(self, seq, name, parent=None):
        super().__init__(parent=parent)
        self.seq=seq
        self.setMaximumWidth(120)
        self.setMaximumHeight(20)
        hbox=QHBoxLayout()
        hbox.setContentsMargins(0,0,0,0)
        hbox.setSpacing(0)
        self.setLayout(hbox)
        self.label=QLabel(name)
        self.label.setMaximumWidth(50)
        hbox.addWidget(self.label)
        self.leftButton=QPushButton('<',self)
        self.leftButton.setMaximumWidth(15)
        hbox.addWidget(self.leftButton)
        self.lineEdit=LineEditLimInt(min=0, max=11, hint='Not Assigned',parent=self)##Consider just use label
        self.lineEdit.setMaximumWidth(20)
        hbox.addWidget(self.lineEdit)
        self.rightButton=QPushButton('>',self)
        self.rightButton.setMaximumWidth(15)
        hbox.addWidget(self.rightButton)
        self.hide()

class MySpinBox(QWidget):
    def __init__(self, seq, name, _min=0, _max=200, step=1, parent=None):
        super().__init__(parent=parent)
        self.setMaximumWidth(120)
        self.seq=seq
        hbox=QHBoxLayout()
        hbox.setContentsMargins(0,0,0,0)
        hbox.setSpacing(0)
        self.setLayout(hbox)
        self.label=QLabel(name)
        self.label.setMaximumWidth(60)
        hbox.addWidget(self.label)
        self.spinBox=QSpinBox(self)
        self.spinBox.setMaximumWidth(40)
        hbox.addWidget(self.spinBox)
        self.spinBox.setRange(_min,_max)
        self.spinBox.setSingleStep(step)
        self.hide()

class LineEditLimInt(QLineEdit):
    def __init__(self, parent=None, min=0, max=256, hint=None, upper=None):
        super().__init__(parent=parent)
        self.upper=upper
        self.min=min
        self.max=max
        #self.validator = QIntValidator(min, max)
        #self.setValidator(validator)
        self.textChanged.connect(self.validate)
        if hint is not None:
            self.setPlaceholderText(str(hint))
        self.val=0
    def validate(self):
        try:
            self.val = int(self.text())
        except Exception:
            self.val = 0
            self.setText('')
        if self.val>self.max:
            self.val=self.max
            self.setText(str(self.val))
        elif self.val<self.min:
            self.val=self.min
            self.setText(str(self.val))

class IndexedLELI(LineEditLimInt):
    def __init__(self, parent=None, min=0, max=256, hint=None, idx=0):
        super().__init__(parent=parent, min=min, max=max,hint=hint)
        self.idx=idx

        


