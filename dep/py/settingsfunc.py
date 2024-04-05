from PyQt5 import QtCore
import configparser
import qdarktheme
import os

config = configparser.ConfigParser()

def Load_settings(self, current_dir):
    # define config path and read config
    settings_path = os.path.join(current_dir, "dep/settings.ini")
    config.read(settings_path)
    
    # read settings
    theme               = str(config.get('Settings', 'theme'))
    # methods
    HashCheck_Method    = True if str(config.get('Settings', 'HashCheck_Method')).lower() == 'true' else False
    VirusTotal_Method   = True if str(config.get('Settings', 'VirusTotal_Method')).lower() == 'true' else False
    MetaDefender_Method = True if str(config.get('Settings', 'MetaDefender_Method')).lower() == 'true' else False
    # api keys
    VirusTotal_ApiKey   = str(config.get('Settings', 'VirusTotal_ApiKey'))
    MetaDefender_ApiKey = str(config.get('Settings', 'MetaDefender_ApiKey'))
    # hash setting
    UpdateHashes        = True if str(config.get('Settings', 'UpdateHashes')).lower() == 'true' else False
    UpdateInterval      = str(config.get('Settings', 'UpdateInterval'))
    
    # apply settings
    # theme
    qdarktheme.setup_theme(theme)
    self.theme_comboBox.setCurrentText(theme)
    # methods
    self.Method_HashCheck_checkBox.setChecked(HashCheck_Method)
    self.Method_VirusTotal_checkBox.setChecked(VirusTotal_Method)
    self.Method_MetaDefender_checkBox.setChecked(MetaDefender_Method)
    # api keys
    self.VirusTotal_ApiKey_lineEdit.setText(VirusTotal_ApiKey)
    self.MetaDefender_ApiKey_lineEdit.setText(MetaDefender_ApiKey)
    # hash setting
    self.UpdateHashes_checkBox.setChecked(UpdateHashes)
    self.UpdateInterval_timeEdit.setTime(QtCore.QTime.fromString(UpdateInterval, "hh:mm:ss"))
    self.HashUpdateTread(current_dir)


    
def SaveApply_settings(self, current_dir):
    # define config path and read config
    settings_path = os.path.join(current_dir, "dep/settings.ini")
    
    # get states/values from the ui
    theme = str(self.theme_comboBox.currentText())
    
    
    # save values
    config["Settings"]["theme"] = theme
    # methods
    config["Settings"]["HashCheck_Method"] = str(self.Method_HashCheck_checkBox.isChecked())
    config["Settings"]["VirusTotal_Method"] = str(self.Method_VirusTotal_checkBox.isChecked())
    config["Settings"]["MetaDefender_Method"] = str(self.Method_MetaDefender_checkBox.isChecked())
    # api keys
    config["Settings"]["VirusTotal_ApiKey"] = str(self.VirusTotal_ApiKey_lineEdit.text())
    config["Settings"]["MetaDefender_ApiKey"] = str(self.MetaDefender_ApiKey_lineEdit.text())
    # hash setting
    config["Settings"]["UpdateHashes"] = str(self.UpdateHashes_checkBox.isChecked())
    config["Settings"]["UpdateInterval"] = str(self.UpdateInterval_timeEdit.time().toString("hh:mm:ss"))
    
    # write to file
    with open(settings_path, 'w') as configfile:
        config.write(configfile)
    configfile.close()
    
    # apply settings
    Load_settings(self, current_dir)