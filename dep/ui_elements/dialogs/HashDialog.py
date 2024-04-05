from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_HashDialog(object):
    # button functions
    def button_clicked(self, HashDialog, button_name):
        if button_name == "OK":
            self.accepted = True
            HashDialog.accept()
        else:
            self.accepted = False
            HashDialog.reject()

    def _return(self):
        if hasattr(self, 'accepted'):
            if self.accepted:
                return self.HashInput_lineEdit.text()

    def setupUi(self, HashDialog):
        HashDialog.setObjectName("HashDialog")
        HashDialog.resize(590, 89)
        HashDialog.setMinimumSize(QtCore.QSize(590, 0))
        HashDialog.setMaximumSize(QtCore.QSize(16777215, 89))
        self.gridLayout_2 = QtWidgets.QGridLayout(HashDialog)
        self.gridLayout_2.setContentsMargins(5, 5, 5, 5)
        self.gridLayout_2.setSpacing(5)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setSpacing(6)
        self.horizontalLayout.setObjectName("horizontalLayout")
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.Cancel_pushButton = QtWidgets.QPushButton(HashDialog)
        self.Cancel_pushButton.setObjectName("Cancel_pushButton")
        self.horizontalLayout.addWidget(self.Cancel_pushButton)
        self.OK_pushButton = QtWidgets.QPushButton(HashDialog)
        self.OK_pushButton.setObjectName("OK_pushButton")
        self.horizontalLayout.addWidget(self.OK_pushButton)
        self.gridLayout_2.addLayout(self.horizontalLayout, 2, 0, 1, 1)
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.HashInput_lineEdit = QtWidgets.QLineEdit(HashDialog)
        self.HashInput_lineEdit.setObjectName("HashInput_lineEdit")
        self.verticalLayout.addWidget(self.HashInput_lineEdit)
        self.label = QtWidgets.QLabel(HashDialog)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.verticalLayout.addWidget(self.label)
        self.gridLayout_2.addLayout(self.verticalLayout, 1, 0, 1, 1)
        spacerItem1 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout_2.addItem(spacerItem1, 0, 0, 1, 1)

        self.retranslateUi(HashDialog)
        QtCore.QMetaObject.connectSlotsByName(HashDialog)

        # buttons
        self.Cancel_pushButton.clicked.connect(lambda: self.button_clicked(HashDialog, "Cancel"))
        self.OK_pushButton.clicked.connect(lambda: self.button_clicked(HashDialog, "OK"))

    def retranslateUi(self, HashDialog):
        _translate = QtCore.QCoreApplication.translate
        HashDialog.setWindowTitle(_translate("HashDialog", "Hash Dialog"))
        self.Cancel_pushButton.setText(_translate("HashDialog", "Cancel"))
        self.OK_pushButton.setText(_translate("HashDialog", "OK"))
        self.label.setText(_translate("HashDialog", "Supported Hash Types: MD5, SHA1, SHA256 (Local Hash scanning only supported with MD5 hashes)"))
