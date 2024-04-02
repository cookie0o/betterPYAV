from PyQt5.QtWidgets import QMessageBox, QFileDialog
from PyQt5.QtCore import QThread
import webbrowser

def openLinkDialog(link):
    dlg = QMessageBox()
    dlg.setWindowTitle("Link Dialog")
    dlg.setText("Do you want to open this Link in your Browser?\n"+str(link))
    dlg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
    dlg.setIcon(QMessageBox.Question)
    button = dlg.exec()

    if button == QMessageBox.Yes:
        webbrowser.open(str(link))
    else:
        return
    

def changePage(self, page, LoadingReason="Loading..."):
    if LoadingReason == None: LoadingReason = "Loading..."

    if page == "HomePage":
        self.stackedWidget.setCurrentIndex(0)
        
    elif page == "LoadingPage":
        self.stackedWidget.setCurrentIndex(1)
        self.LoadingReason_label.setText(str(LoadingReason))

    elif page == "ResultsPage":
        self.stackedWidget.setCurrentIndex(2)
        
    elif page == "SettingsPage":
        self.stackedWidget.setCurrentIndex(3)

         
def FileDialog(self, MainWindow):
    options = QFileDialog.Options()
    file_path, _ = QFileDialog.getOpenFileName(MainWindow, "Open File", "", "All Files (*);;Text Files (*.txt)", options=options)
    return file_path


def ErrorBox(self, Error, def_data, Title="Error"):
    # unpack function data
    function_name, function_file_path = def_data
    # build error msg
    _Error = (f"""
              {Error}
              Origin:
              {function_name} in
              {function_file_path}
            """)
    # build and show error message
    error_box = QMessageBox()
    error_box.setIcon(QMessageBox.Critical)
    error_box.setWindowTitle(Title)
    error_box.setText(_Error)
    # show Error Box
    error_box.exec_()
    return