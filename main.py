from dotenv import load_dotenv
load_dotenv()
from PySide6.QtWidgets import QApplication
from gui.main_window import MainWindow
app = QApplication([])
window = MainWindow()
window.show()
app.exec()
