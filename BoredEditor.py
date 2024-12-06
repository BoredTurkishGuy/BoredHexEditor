import sys
import subprocess
import importlib.util

PackageNameMap = {
    "PyQt5": "PyQt5",
    "capstone": "capstone",
    "keystone-engine": "keystone"
}

def InstallAndImport(Package):
    ImportName = PackageNameMap.get(Package, Package)
    Spec = importlib.util.find_spec(ImportName)
    if Spec is None:
        subprocess.check_call([sys.executable, "-m", "pip", "install", Package])
        Spec = importlib.util.find_spec(ImportName)
        if Spec is None:
            sys.exit(1)

Requirements = []
with open("requirements.txt", "r") as F:
    for Line in F:
        Line = Line.strip()
        if Line and not Line.startswith("#"):
            if "==" in Line:
                Package = Line.split("==")[0].strip()
            else:
                Package = Line
            Requirements.append(Package)

for Pkg in Requirements:
    InstallAndImport(Pkg)

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QPushButton, QLabel,
    QLineEdit, QFileDialog, QTableWidget, QTableWidgetItem, QAbstractItemView, QProgressBar,
    QMessageBox, QInputDialog, QTreeWidget, QTreeWidgetItem, QTabWidget, QMenu
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from keystone import Ks, KS_ARCH_X86, KS_MODE_64



class FileLoaderThread(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(bytearray)

    def __init__(self, filePath):
        super().__init__()
        self.filePath = filePath

    def run(self):
        try:
            with open(self.filePath, "rb") as file:
                fileData = bytearray()
                chunkSize = 1024 * 1024
                fileSize = file.seek(0, 2)
                file.seek(0)
                loaded = 0
                while chunk := file.read(chunkSize):
                    fileData.extend(chunk)
                    loaded += len(chunk)
                    self.progress.emit(int((loaded / fileSize) * 100))
                self.finished.emit(fileData)
        except Exception:
            self.finished.emit(None)


class BoredEditor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.fileData = None
        self.filePath = None
        self.loaderThread = None
        self.virtualMemory = {}
        self.breakPoints = set()
        self.hexRowCount = 100
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Bored Hex Editor")
        self.setGeometry(100, 100, 1600, 900)
        mainWidget = QWidget()
        mainLayout = QVBoxLayout()
        mainWidget.setLayout(mainLayout)
        self.setCentralWidget(mainWidget)
        self.tabWidget = QTabWidget()
        self.hexTab = QWidget()
        self.memoryTab = QWidget()
        self.disassemblyTab = QWidget()
        self.stackTab = QWidget()
        self.registerTab = QWidget()
        self.initHexTab()
        self.initMemoryTab()
        self.initDisassemblyTab()
        self.initStackTab()
        self.initRegisterTab()
        self.tabWidget.addTab(self.hexTab, "Hex Viewer")
        self.tabWidget.addTab(self.memoryTab, "Memory Viewer")
        self.tabWidget.addTab(self.disassemblyTab, "Disassembly")
        self.tabWidget.addTab(self.stackTab, "Stack Viewer")
        self.tabWidget.addTab(self.registerTab, "Register Viewer")
        mainLayout.addWidget(self.tabWidget)

    def initHexTab(self):
        layout = QVBoxLayout()
        buttonLayout = QHBoxLayout()
        self.openButton = QPushButton("Open File")
        self.saveButton = QPushButton("Save File")
        self.searchButton = QPushButton("Search")
        self.jumpButton = QPushButton("Jump to Address")
        self.openButton.clicked.connect(self.openFile)
        self.saveButton.clicked.connect(self.saveFile)
        self.searchButton.clicked.connect(self.searchPattern)
        self.jumpButton.clicked.connect(self.jumpToAddress)
        self.progressBar = QProgressBar()
        self.progressBar.setValue(0)
        buttonLayout.addWidget(self.openButton)
        buttonLayout.addWidget(self.saveButton)
        buttonLayout.addWidget(self.searchButton)
        buttonLayout.addWidget(self.jumpButton)
        layout.addLayout(buttonLayout)
        layout.addWidget(self.progressBar)
        self.hexTable = QTableWidget()
        self.hexTable.setColumnCount(17)
        self.hexTable.setHorizontalHeaderLabels(["Offset"] + [f"{i:02X}" for i in range(16)] + ["ASCII"])
        self.hexTable.setSelectionMode(QAbstractItemView.SingleSelection)
        self.hexTable.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.hexTable.setContextMenuPolicy(Qt.CustomContextMenu)
        self.hexTable.customContextMenuRequested.connect(self.showHexContextMenu)
        layout.addWidget(self.hexTable)
        self.hexTab.setLayout(layout)

        self.loadTimer = QTimer()
        self.loadTimer.timeout.connect(self.updateVisibleHexRows)

    def initMemoryTab(self):
        layout = QVBoxLayout()
        self.memoryView = QTreeWidget()
        self.memoryView.setHeaderLabels(["Region", "Start", "End", "Size"])
        layout.addWidget(self.memoryView)
        self.memoryTab.setLayout(layout)

    def initDisassemblyTab(self):
        layout = QVBoxLayout()
        self.disassemblyText = QTreeWidget()
        self.disassemblyText.setHeaderLabels(["Address", "Instruction"])
        self.disassemblyText.setContextMenuPolicy(Qt.CustomContextMenu)
        self.disassemblyText.customContextMenuRequested.connect(self.showDisassemblyContextMenu)
        self.reassembleButton = QPushButton("Reassemble")
        self.reassembleButton.clicked.connect(self.reassembleCode)
        layout.addWidget(self.disassemblyText)
        layout.addWidget(self.reassembleButton)
        self.disassemblyTab.setLayout(layout)

    def initStackTab(self):
        layout = QVBoxLayout()
        self.stackView = QTreeWidget()
        self.stackView.setHeaderLabels(["Address", "Value"])
        layout.addWidget(self.stackView)
        self.stackTab.setLayout(layout)

    def initRegisterTab(self):
        layout = QVBoxLayout()
        self.registerView = QTreeWidget()
        self.registerView.setHeaderLabels(["Register", "Value"])
        self.registerView.setContextMenuPolicy(Qt.CustomContextMenu)
        self.registerView.customContextMenuRequested.connect(self.showRegisterContextMenu)
        self.updateRegisters()
        layout.addWidget(self.registerView)
        self.registerTab.setLayout(layout)

    def updateRegisters(self):
        self.registerView.clear()
        for reg in ["RAX", "RBX", "RCX", "RDX", "RSP", "RBP", "RIP"]:
            QTreeWidgetItem(self.registerView, [reg, "0x0000000000000000"])

    def openFile(self):
        if self.loaderThread is not None and self.loaderThread.isRunning():
            QMessageBox.warning(self, "Warning", "File is still loading. Please wait.")
            return

        filePath, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files (*)")
        if filePath:
            self.cleanupThread()
            self.resetState()
            self.filePath = filePath
            self.progressBar.setValue(0)
            self.loaderThread = FileLoaderThread(filePath)
            self.loaderThread.progress.connect(self.progressBar.setValue)
            self.loaderThread.finished.connect(self.fileLoaded)
            self.loaderThread.start()

    def cleanupThread(self):
        if self.loaderThread is not None:
            self.loaderThread.quit()
            self.loaderThread.wait()
            self.loaderThread = None

    def resetState(self):
        self.fileData = None
        self.hexTable.clearContents()
        self.hexTable.setRowCount(0)
        self.memoryView.clear()
        self.disassemblyText.clear()
        self.updateRegisters()

    def fileLoaded(self, fileData):
        if fileData is None:
            QMessageBox.critical(self, "Error", "Failed to load file.")
            return
        self.fileData = fileData
        self.populateHexTable()
        self.populateMemoryView()
        self.disassembleCode()
        QMessageBox.information(self, "Success", f"File loaded: {self.filePath}")

    def closeEvent(self, event):
        self.cleanupThread()
        event.accept()

    def saveFile(self):
        if self.filePath is None:
            QMessageBox.warning(self, "Warning", "No file loaded.")
            return
        try:
            with open(self.filePath, "wb") as file:
                file.write(self.fileData)
            QMessageBox.information(self, "Success", "File saved successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save file: {e}")

    def populateHexTable(self):
        self.hexTable.setRowCount(self.hexRowCount)
        self.updateVisibleHexRows()
        self.loadTimer.start(100)

    def updateVisibleHexRows(self):
        visibleRegion = self.hexTable.viewport().rect()
        topRow = self.hexTable.rowAt(visibleRegion.top())
        bottomRow = self.hexTable.rowAt(visibleRegion.bottom())
        if bottomRow == -1:
            bottomRow = self.hexRowCount - 1

        for row in range(topRow, bottomRow + 1):
            offset = row * 16
            offsetItem = QTableWidgetItem(f"{offset:08X}")
            self.hexTable.setItem(row, 0, offsetItem)
            asciiString = ""
            for col in range(1, 17):
                index = offset + col - 1
                if index < len(self.fileData):
                    byteValue = self.fileData[index]
                    byteItem = QTableWidgetItem(f"{byteValue:02X}")
                    self.hexTable.setItem(row, col, byteItem)
                    asciiString += chr(byteValue) if 32 <= byteValue <= 126 else "."
                else:
                    self.hexTable.setItem(row, col, QTableWidgetItem(""))
            asciiItem = QTableWidgetItem(asciiString)
            self.hexTable.setItem(row, 17, asciiItem)

    def showHexContextMenu(self, position):
        menu = QMenu()
        editAction = menu.addAction("Edit Byte")
        action = menu.exec_(self.hexTable.viewport().mapToGlobal(position))
        if action == editAction:
            self.editByteAtContextMenu(position)

    def editByteAtContextMenu(self, position):
        item = self.hexTable.itemAt(position)
        if not item:
            return
        col = self.hexTable.currentColumn()
        row = self.hexTable.currentRow()
        address = (row * 16) + (col - 1)
        if 0 <= address < len(self.fileData):
            newValue, ok = QInputDialog.getInt(self, "Edit Byte", f"Enter new value for 0x{address:08X} (hex):", 0, 0, 255)
            if ok:
                self.fileData[address] = newValue
                self.updateVisibleHexRows()

    def showDisassemblyContextMenu(self, position):
        menu = QMenu()
        editAction = menu.addAction("Edit Instruction")
        action = menu.exec_(self.disassemblyText.viewport().mapToGlobal(position))
        if action == editAction:
            self.editInstruction(position)

    def editInstruction(self, position):
        item = self.disassemblyText.itemAt(position)
        if not item:
            return
        address = item.text(0)
        instruction = item.text(1)
        newInstruction, ok = QInputDialog.getText(self, "Edit Instruction", f"Modify instruction at {address}:", text=instruction)
        if ok:
            item.setText(1, newInstruction)

    def reassembleCode(self):
        assemblyCode = []
        for i in range(self.disassemblyText.topLevelItemCount()):
            item = self.disassemblyText.topLevelItem(i)
            assemblyCode.append(f"{item.text(1)}")
        try:
            ks = Ks(KS_ARCH_X86, KS_MODE_64)
            encoding, _ = ks.asm("\n".join(assemblyCode))
            self.fileData = bytearray(encoding)
            QMessageBox.information(self, "Reassemble", "Code reassembled successfully!")
            self.populateHexTable()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to reassemble: {e}")

    def showRegisterContextMenu(self, position):
        menu = QMenu()
        editAction = menu.addAction("Edit Register")
        action = menu.exec_(self.registerView.viewport().mapToGlobal(position))
        if action == editAction:
            self.editRegister(position)

    def editRegister(self, position):
        item = self.registerView.itemAt(position)
        if not item:
            return
        register = item.text(0)
        value = item.text(1)
        newValue, ok = QInputDialog.getText(self, "Edit Register", f"Modify value of {register}:", text=value)
        if ok:
            item.setText(1, newValue)

    def populateMemoryView(self):
        self.memoryView.clear()
        region = QTreeWidgetItem(self.memoryView, ["Binary", "0x00000000", f"0x{len(self.fileData):08X}", f"{len(self.fileData)} bytes"])
        self.virtualMemory["Binary"] = (0, len(self.fileData))
        self.memoryView.addTopLevelItem(region)

    def searchPattern(self):
        pattern, ok = QInputDialog.getText(self, "Search", "Enter hex or ASCII pattern:")
        if not ok or not pattern:
            return
        patternBytes = bytes.fromhex(pattern) if all(c in "0123456789ABCDEFabcdef " for c in pattern) else pattern.encode()
        foundAt = []
        for i in range(len(self.fileData) - len(patternBytes) + 1):
            if self.fileData[i:i + len(patternBytes)] == patternBytes:
                foundAt.append(i)
        if foundAt:
            QMessageBox.information(self, "Search Result", f"Pattern found at offsets: {', '.join(f'0x{addr:08X}' for addr in foundAt)}")
        else:
            QMessageBox.information(self, "Search Result", "Pattern not found.")

    def disassembleCode(self):
        if self.fileData is None:
            return
        disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        code = bytes(self.fileData[:256])
        self.disassemblyText.clear()
        for instruction in disassembler.disasm(code, 0):
            QTreeWidgetItem(self.disassemblyText, [f"0x{instruction.address:08X}", f"{instruction.mnemonic} {instruction.op_str}"])

    def jumpToAddress(self):
        address, ok = QInputDialog.getInt(self, "Jump to Address", "Enter address (hex):", 0, 0, len(self.fileData) - 1)
        if ok:
            self.hexTable.scrollToItem(self.hexTable.item(address // 16, 0), QAbstractItemView.PositionAtTop)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    editor = BoredEditor()
    editor.show()
    sys.exit(app.exec_())
