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

         
def FileDialog(self, MainWindow):
    options = QFileDialog.Options()
    file_path, _ = QFileDialog.getOpenFileName(MainWindow, "Open File", "", "All Files (*);;Text Files (*.txt)", options=options)
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
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    with open(filepath, "rb") as f:
        # Read the file in chunks to efficiently handle large files
        chunk = 0
        while chunk := f.read(4096):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    return {
        md5_hash.hexdigest(),
        sha1_hash.hexdigest(),
        sha256_hash.hexdigest()
    }


# check if a hash is MD5 using its default length
def is_MD5_hash(self, hash):
    if len(str(hash)) == 32:
        return True
    else:
        return False