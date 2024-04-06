from PyQt5.QtWidgets import QMessageBox, QFileDialog
import webbrowser
import hashlib
import os

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

         
def FileDialog(self):
    options = QFileDialog.Options()
    file_path, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files (*);;Text Files (*.txt)", options=options)
    if os.path.exists(file_path):
        return file_path
    else:
        self.ErrorBox("Path selected is not valid or does not exist", (self.def_data()), "File Dialog Error")
        return None


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


def get_Hashes(self, filepath):
    # get the MD5, SHA1 and SHA-256 hash of a file
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    # return hashes
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def is_MD5_hash(self, hash):
    # check if a hash is MD5 using its default length
    if len(str(hash)) == 32:
        return True
    else:
        return False