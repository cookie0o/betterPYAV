from PyQt5.QtCore import QThreadPool, QTimer
from PyQt5 import QtCore, QtWidgets
import inspect
import sys
import os
# ui resources
from dep.ui import Ui_MainWindow


# load outside c
from dep.py.loadLib import libs

# import outside py functions
from dep.py.functions import (
    openLinkDialog, changePage, FileDialog, 
    ErrorBox, get_Hashes, is_MD5_hash
)
from dep.py.settingsfunc import (
    Load_settings, SaveApply_settings,
    start_settings, close_settings
)
from dep.py.hashUpdate import HashWorker
from dep.py.scan import ScanWorker

# import algo
from dep.ML.file_algo_check import file_MLCheck

# outside ui elements
from dep.ui_elements.dialogs.HashDialog import Ui_HashDialog


current_dir = os.path.dirname(os.path.realpath(__file__))


class Constructor(QtWidgets.QWidget, Ui_MainWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        import dep.ui_res.ui_rc
        self.setupUi(self)
        self.Build()

    # on close event
    def closeEvent(self, event):
        # save close settings
        close_settings(self, current_dir)
        # close
        event.accept()



    # .self functions
    # scan file Thread
    def scan(self, current_dir, filepath, type):
        _self = self
        self.thread = QtCore.QThread()
        self.worker = ScanWorker(_self, current_dir, filepath, type)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit,)
        self.thread.start()

    # Update Hashes Thread
    def HashUpdateTread(self, current_dir):
        _self = self
        self.timer = QTimer()
        self.timer.stop()

        # create update thread
        HashUpdate_pool = QThreadPool.globalInstance()
        HashUpdate_pool.start(HashWorker(_self, current_dir).run)

        # run update hash thread when the timer runs out
        self.timer.timeout.connect(lambda: HashWorker(_self, current_dir).run)

        # Get the hours and minutes defined by the user and define the timer delay
        UserDefinedInterval = self.UpdateInterval_timeEdit.time().toString("hh:mm:ss")
        hours, minutes, seconds = map(int, UserDefinedInterval.split(':'))
        _UserDefinedInterval = (hours * 3600 + minutes * 60) * 1000

        # start the timer with the user defined update time
        self.timer.start(_UserDefinedInterval)

    # get current function data
    def def_data(self):
        function_name = inspect.currentframe().f_back.f_code.co_name + "()"
        caller_frame = inspect.stack()[1]
        function_file_path = caller_frame.filename
        return (function_name,  ("\\"+os.path.relpath(function_file_path, current_dir)))

    # show hash dialog window
    def show_HashDialog(self):
        self.HashDialog_window = QtWidgets.QDialog()
        self.HashDialog_ui = Ui_HashDialog()
        self.HashDialog_ui.setupUi(self.HashDialog_window)
        result = self.HashDialog_window.exec_()
        # check if it was accepted or rejected(canceled)
        if result == QtWidgets.QDialog.Accepted:
            return self.HashDialog_ui._return()
        elif result == QtWidgets.QDialog.Rejected:
            return None
    

    # function rooting for self.
    def changePage(self, page, LoadingReason=None):
        return changePage(self, page, LoadingReason)
    def ErrorBox(self, Error, def_data, Title="Error"):
        return ErrorBox(self, Error, def_data, Title)
    def get_Hashes(self, filepath):
        return get_Hashes(self, filepath) 
    def is_MD5_hash(self, hash):
        return is_MD5_hash(self, hash)
    def file_MLCheck(self, current_dir, filepath):
        return file_MLCheck(self, current_dir, filepath)


    def Build(self):
        print (current_dir)

        # disable checkBoxes
        self.HashCheck_noInput_checkBox.setEnabled(False)
        self.Method_HashCheck_checkBox.setEnabled(False)
        self.Method_HashCheck_checkBox.setChecked(True)
        self.VirusTotalCheck_noInput_checkBox.setEnabled(False)
        self.MetaDefenderCheck_noInput_checkBox.setEnabled(False)
        self.HashCheckDetection_noInput_checkBox.setEnabled(False)
        self.MLCheck_noInput_checkBox.setEnabled(False)
        self.MLCheckDetection_noInput_checkBox.setEnabled(False)
        
        # load shared libs and define arg types
        libs(self, current_dir)
        
        # side buttons
        self.HomePage_pushButton.clicked.connect(lambda: self.changePage("HomePage"))
        self.SettingsPage_pushButton.clicked.connect(lambda: self.changePage("SettingsPage"))
        self.HomePage_pushButton_2.clicked.connect(lambda: self.changePage( "HomePage"))
        self.SettingsPage_pushButton_2.clicked.connect(lambda: self.changePage("SettingsPage"))
        self.HomePage_pushButton_3.clicked.connect(lambda: self.changePage( "HomePage"))
        self.SettingsPage_pushButton_3.clicked.connect(lambda: self.changePage("SettingsPage"))
        
        # buttons (Home Page)
        self.ReportAIssue_pushButton.clicked.connect(lambda: openLinkDialog("https://github.com/cookie0o/betterPYAV/issues"))
        self.ScanAFile_pushButton.clicked.connect(lambda: (
            self.changePage("LoadingPage", "Waiting for Input"),
            self.scan(current_dir, FileDialog(self), "HashFile")
        ))
        self.ScanAHash_pushButton.clicked.connect (lambda: (
            self.changePage("LoadingPage", "Waiting for Input"),
            self.scan(current_dir, self.show_HashDialog(), "HashFile")
        ))
        
        
        # buttons (Settings Page)
        self.SaveSettings_pushButton.clicked.connect(lambda: SaveApply_settings(self, current_dir))
        
        
        # load and apply settings
        Load_settings(self, current_dir)
        # load start settings (only called on start)
        start_settings(self, current_dir)
        self.show()

        self.HashUpdateTread(current_dir)

        self.Version.setText(f"Version: {QtWidgets.QApplication.applicationVersion()}")


def main(appName, appVersion):
    # enable and handle high dpi displays
    if hasattr(QtCore.Qt, 'AA_EnableHighDpiScaling'):
        QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling, True)
    if hasattr(QtCore.Qt, 'AA_UseHighDpiPixmaps'):
        QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps, True)

        
    # create application
    app = QtWidgets.QApplication(sys.argv)
    # define values
    app.setApplicationName(appName +" "+ appVersion)
    app.setApplicationVersion(appVersion)

    Constructor().show()

    # show ui
    sys.exit(app.exec_())

    
if __name__ == "__main__":
    # open file and read app info
    with open (os.path.join(current_dir, "dep/appInfo.txt")) as F:
        appName = F.readline()
        appVersion = F.readline()
    F.close()
    
    # start app
    main(appName, appVersion)