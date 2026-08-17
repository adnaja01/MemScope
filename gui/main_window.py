from PySide6.QtWidgets import QMainWindow, QPushButton, QVBoxLayout, QWidget, QLabel, QFileDialog, QTextEdit, QProgressBar, QComboBox, QTabWidget, QLineEdit, QGroupBox, QFormLayout, QCheckBox, QScrollArea, QSplitter, QTableWidget, QTableWidgetItem, QHeaderView, QHBoxLayout, QCompleter, QDateEdit, QStackedWidget, QMessageBox, QSpinBox
from PySide6.QtCore import QObject, QThread, Signal, Slot, Qt, QTimer, QEvent, QDate
import platform
import os
import subprocess
import time
import getpass
from datetime import datetime
from acquisition.ram_capture import take_snapshot, DUMP_DIR
from acquisition.preflight import check_storage_for_acquisition, format_bytes
from analysis.analyzer import analyze_memory_by_tabs, get_preset_scans, run_advanced_volatility_command
from hashing.hash_utils import hash_file
from database.db_manager import init_database_if_needed, get_or_create_default_case, insert_dump, insert_analysis_session, insert_plugin_result, insert_suspicious_finding, insert_advanced_command, get_dump_history, get_dump_details, get_connection

class SnapshotWorker(QObject):
    finished = Signal(str)
    error = Signal(str)
    log = Signal(str)

    def __init__(self, os_type, custom_path=None):
        super().__init__()
        self.os_type = os_type
        self.custom_path = custom_path

    @Slot()
    def run(self):
        try:
            dump_path = take_snapshot(self.os_type, self.custom_path)
            if dump_path:
                self.finished.emit(dump_path)
            else:
                self.error.emit('[ERROR] RAM snapshot failed.')
        except subprocess.CalledProcessError as e:
            self.error.emit(f'[ERROR] Acquisition failed: {e}')
        except Exception as e:
            self.error.emit(f'[ERROR] Unexpected acquisition error: {e}')

class AnalysisWorker(QObject):
    finished = Signal(dict)
    error = Signal(str)
    log = Signal(str)
    progress = Signal(int)

    def __init__(self, snapshot_file, selected_os, selected_scans):
        super().__init__()
        self.snapshot_file = snapshot_file
        self.selected_os = selected_os
        self.selected_scans = selected_scans

    @Slot()
    def run(self):
        try:
            self.log.emit(f'[INFO] Loaded snapshot: {self.snapshot_file}')
            self.log.emit(f'[INFO] Analysis mode selected: {self.selected_os}')
            self.log.emit(f"[INFO] Selected scans: {', '.join(self.selected_scans)}")
            results = analyze_memory_by_tabs(self.snapshot_file, self.selected_os, self.selected_scans, progress_callback=self.progress.emit, log_callback=self.log.emit)
            self.finished.emit(results)
        except Exception as e:
            self.error.emit(f'[ERROR] Analysis failed: {e}')

class AdvancedWorker(QObject):
    finished = Signal(object)
    error = Signal(str)
    log = Signal(str)

    def __init__(self, snapshot_file, selected_os, command_text):
        super().__init__()
        self.snapshot_file = snapshot_file
        self.selected_os = selected_os
        self.command_text = command_text

    @Slot()
    def run(self):
        try:
            self.log.emit(f'[INFO] Running advanced command: {self.command_text}')
            output = run_advanced_volatility_command(self.snapshot_file, self.selected_os, self.command_text)
            self.finished.emit(output)
        except Exception as e:
            self.error.emit(f'[ERROR] Advanced command failed: {e}')

class CalendarDateEdit(QDateEdit):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCalendarPopup(True)
        self.setFixedHeight(24)

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        self.show()

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle('RAM Snapshot Tool')
        self.resize(1400, 900)
        self.os_type = None
        self.snapshot_file = None
        self.current_dump_id = None
        self.current_analysis_id = None
        self.snapshot_thread = None
        self.snapshot_worker = None
        self.analysis_thread = None
        self.analysis_worker = None
        self.advanced_thread = None
        self.advanced_worker = None
        self.snapshot_start_time = None
        self.analysis_start_time = None
        self.analysis_started_at = None
        self.last_acquisition_time = '-'
        self.last_analysis_time = '-'
        self.last_hash_value = '-'
        self.last_dump_size = '-'
        self.last_dump_size_bytes = 0
        self.last_acquisition_timestamp = '-'
        self.analyst_name = getpass.getuser()
        self.last_analysis_profile = '-'
        init_database_if_needed()
        self.current_case_id = get_or_create_default_case(self.analyst_name)
        self.scan_checkboxes = {}
        self.tab_outputs = {}
        self.build_ui()
        self.update_summary_box()
        self.refresh_scan_catalog()
        self.refresh_history_tab()

    def build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        splitter = QSplitter(Qt.Horizontal)
        root_layout.addWidget(splitter, 1)
        self.left_panel = QWidget()
        left_layout = QVBoxLayout(self.left_panel)
        left_layout.setContentsMargins(6, 6, 6, 6)
        left_layout.setSpacing(8)
        self.acquisition_group = QGroupBox('Acquisition')
        acquisition_layout = QVBoxLayout()
        acquisition_layout.setSpacing(4)
        detect_snapshot_layout = QHBoxLayout()
        detect_snapshot_layout.setSpacing(4)
        self.detect_btn = QPushButton('Detect OS')
        self.detect_btn.setFixedHeight(28)
        detect_snapshot_layout.addWidget(self.detect_btn)
        self.snapshot_btn = QPushButton('Capture RAM')
        self.snapshot_btn.setFixedHeight(28)
        detect_snapshot_layout.addWidget(self.snapshot_btn)
        acquisition_layout.addLayout(detect_snapshot_layout)
        self.load_btn = QPushButton('Load Existing Dump')
        self.load_btn.setFixedHeight(28)
        acquisition_layout.addWidget(self.load_btn)
        self.acquisition_group.setLayout(acquisition_layout)
        left_layout.addWidget(self.acquisition_group)
        self.analysis_group = QGroupBox('Analysis')
        analysis_layout = QVBoxLayout()
        analysis_layout.setSpacing(4)
        os_profile_row = QHBoxLayout()
        os_profile_row.addWidget(QLabel('OS:'))
        self.os_selector = QComboBox()
        self.os_selector.setFixedHeight(26)
        self.os_selector.addItems(['Windows', 'Linux'])
        os_profile_row.addWidget(self.os_selector)
        analysis_layout.addLayout(os_profile_row)
        profile_row = QHBoxLayout()
        profile_row.addWidget(QLabel('Profile:'))
        self.analysis_profile_selector = QComboBox()
        self.analysis_profile_selector.setFixedHeight(26)
        self.analysis_profile_selector.addItems(['Quick Triage', 'Standard Analysis', 'Custom Analysis'])
        profile_row.addWidget(self.analysis_profile_selector)
        analysis_layout.addLayout(profile_row)
        self.analysis_profile_info = QLabel('')
        self.analysis_profile_info.setWordWrap(True)
        self.analysis_profile_info.setStyleSheet('color: #888;')
        analysis_layout.addWidget(self.analysis_profile_info)
        self.ti_enrichment_checkbox = QCheckBox('Enrich with Threat Intelligence after analysis')
        self.ti_enrichment_checkbox.setChecked(True)
        self.ti_enrichment_checkbox.setToolTip('Query VirusTotal, AbuseIPDB, and AlienVault OTX for suspicious indicators found during analysis')
        analysis_layout.addWidget(self.ti_enrichment_checkbox)
        self.analyze_btn = QPushButton('Run Analysis')
        self.analyze_btn.setFixedHeight(32)
        analysis_layout.addWidget(self.analyze_btn)
        self.analysis_group.setLayout(analysis_layout)
        left_layout.addWidget(self.analysis_group)
        self.advanced_group = QGroupBox('Custom Plugin')
        advanced_layout = QVBoxLayout()
        advanced_layout.setSpacing(4)
        self.advanced_command_input = QLineEdit()
        self.advanced_command_input.setPlaceholderText('e.g. windows.psscan.PsScan')
        self.advanced_command_input.setFixedHeight(26)
        advanced_layout.addWidget(self.advanced_command_input)
        self.plugin_search = QComboBox()
        self.plugin_search.setEditable(True)
        self.plugin_search.setInsertPolicy(QComboBox.NoInsert)
        self.plugin_search.lineEdit().setPlaceholderText('Search available plugins...')
        self.plugin_search.setFixedHeight(26)
        self.plugin_search.currentTextChanged.connect(self.on_plugin_search_changed)
        advanced_layout.addWidget(self.plugin_search)
        self.advanced_help_label = QLabel('Enter Volatility plugin name to run custom analysis')
        self.advanced_help_label.setWordWrap(True)
        self.advanced_help_label.setStyleSheet('color: #666; font-size: 10px;')
        advanced_layout.addWidget(self.advanced_help_label)
        self.run_advanced_btn = QPushButton('Run Custom Plugin')
        self.run_advanced_btn.setFixedHeight(28)
        advanced_layout.addWidget(self.run_advanced_btn)
        self.advanced_group.setLayout(advanced_layout)
        self.advanced_group.setVisible(False)
        left_layout.addWidget(self.advanced_group)
        left_layout.addStretch()
        splitter.addWidget(self.left_panel)
        self.right_panel = QWidget()
        right_layout = QVBoxLayout(self.right_panel)
        right_layout.setContentsMargins(6, 6, 6, 6)
        right_layout.setSpacing(10)
        self.summary_box = QGroupBox('Case Summary')
        summary_form = QFormLayout()
        self.summary_dump_name = QLabel('-')
        self.summary_dump_size = QLabel('-')
        self.summary_analyst = QLabel(self.analyst_name)
        self.summary_acquisition_timestamp = QLabel('-')
        self.summary_acquisition_time = QLabel('-')
        self.summary_analysis_time = QLabel('-')
        self.summary_hash = QLabel('-')
        summary_form.addRow('Current dump:', self.summary_dump_name)
        summary_form.addRow('Dump size:', self.summary_dump_size)
        summary_form.addRow('Analyst:', self.summary_analyst)
        summary_form.addRow('Acquired at:', self.summary_acquisition_timestamp)
        summary_form.addRow('Acquisition duration:', self.summary_acquisition_time)
        summary_form.addRow('Analysis duration:', self.summary_analysis_time)
        summary_form.addRow('Hash value:', self.summary_hash)
        self.summary_box.setLayout(summary_form)
        self.summary_box.setVisible(False)
        right_layout.addWidget(self.summary_box)
        self.history_btn = QPushButton('View History')
        self.history_btn.setFixedSize(120, 28)
        self.history_btn.setStyleSheet('font-size: 12px;')
        right_layout.addWidget(self.history_btn, 0, Qt.AlignRight)
        self.tabs = QTabWidget()
        right_layout.addWidget(self.tabs, 1)
        self.general_log_container = QWidget()
        general_log_layout = QVBoxLayout(self.general_log_container)
        general_log_layout.setContentsMargins(0, 0, 0, 0)
        general_log_layout.setSpacing(4)
        self.general_log = QTextEdit()
        self.general_log.setReadOnly(True)
        general_log_layout.addWidget(self.general_log, 1)
        self.tabs.addTab(self.general_log_container, 'General Log')
        self.suspicious_output = QTextEdit()
        self.suspicious_output.setReadOnly(True)
        self.tabs.addTab(self.suspicious_output, 'Suspicious Findings')
        self.tabs.setTabVisible(self.tabs.indexOf(self.suspicious_output), False)
        self.advanced_scroll = QScrollArea()
        self.advanced_scroll.setWidgetResizable(True)
        self.advanced_output = QTableWidget()
        self.advanced_output.setEditTriggers(QTableWidget.NoEditTriggers)
        self.advanced_output.setSelectionBehavior(QTableWidget.SelectRows)
        self.advanced_output.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.advanced_output.verticalHeader().setVisible(False)
        self.advanced_scroll.setWidget(self.advanced_output)
        self.advanced_output_tab_name = 'Advanced Output'
        self.tabs.addTab(self.advanced_scroll, self.advanced_output_tab_name)
        self.tabs.setTabVisible(self.tabs.indexOf(self.advanced_scroll), False)
        self.generate_report_btn = QPushButton('Generate Report')
        self.generate_report_btn.setFixedSize(120, 28)
        self.generate_report_btn.setStyleSheet('font-size: 12px;')
        self.generate_report_btn.setVisible(False)
        right_layout.addWidget(self.generate_report_btn, 0, Qt.AlignRight)
        self.loading_widget = QWidget(central)
        self.loading_widget.setStyleSheet('background: rgba(240,240,240,220); border-radius: 6px; border: 1px solid #aaa;')
        self.loading_widget.setVisible(False)
        self.loading_widget.setFixedSize(340, 70)
        loading_layout = QVBoxLayout(self.loading_widget)
        loading_layout.setContentsMargins(12, 6, 12, 6)
        loading_layout.setAlignment(Qt.AlignCenter)
        self.loading_bar = QProgressBar()
        self.loading_bar.setFixedHeight(16)
        self.loading_bar.setTextVisible(False)
        loading_layout.addWidget(self.loading_bar)
        self.loading_label = QLabel('')
        self.loading_label.setStyleSheet('color: #222; font-size: 13px; font-weight: bold;')
        loading_layout.addWidget(self.loading_label)
        self.history_view = QWidget()
        history_view_layout = QVBoxLayout(self.history_view)
        history_view_layout.setContentsMargins(4, 4, 4, 4)
        history_view_layout.setSpacing(8)
        self.history_view.setVisible(False)
        self.history_back_btn = QPushButton('← Back')
        self.history_back_btn.setFixedSize(80, 28)
        self.history_back_btn.setStyleSheet('font-size: 12px;')
        history_view_layout.addWidget(self.history_back_btn, 0, Qt.AlignLeft)
        self.history_filters = QGroupBox('Filters')
        filters_layout = QFormLayout()
        self.history_filter_filename = QLineEdit()
        self.history_filter_filename.setPlaceholderText('Search by file name...')
        filters_layout.addRow('File Name:', self.history_filter_filename)
        self.history_filter_os = QComboBox()
        self.history_filter_os.addItems(['All', 'Windows', 'Linux'])
        filters_layout.addRow('OS:', self.history_filter_os)
        self.history_filter_profile = QComboBox()
        self.history_filter_profile.addItems(['All', 'Quick Triage', 'Standard Analysis', 'Custom Analysis'])
        filters_layout.addRow('Analysis Profile:', self.history_filter_profile)
        self.history_filter_date_from = CalendarDateEdit()
        self.history_filter_date_from.setDisplayFormat('yyyy-MM-dd')
        filters_layout.addRow('Date From:', self.history_filter_date_from)
        self.history_filter_date_to = CalendarDateEdit()
        self.history_filter_date_to.setDisplayFormat('yyyy-MM-dd')
        filters_layout.addRow('Date To:', self.history_filter_date_to)
        self.history_filter_btn = QPushButton('Apply Filters')
        self.history_filter_btn.setFixedSize(100, 28)
        self.history_filter_clear_btn = QPushButton('Clear')
        self.history_filter_clear_btn.setFixedSize(60, 28)
        filter_btns_layout = QHBoxLayout()
        filter_btns_layout.addWidget(self.history_filter_btn)
        filter_btns_layout.addWidget(self.history_filter_clear_btn)
        filters_layout.addRow('', filter_btns_layout)
        self.history_filters.setLayout(filters_layout)
        history_view_layout.addWidget(self.history_filters)
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(8)
        self.history_table.setHorizontalHeaderLabels(['Dump ID', 'File Name', 'OS', 'Analyst', 'Acquired At', 'Size', 'Analyses', ''])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.history_table.setColumnWidth(7, 90)
        history_view_layout.addWidget(self.history_table, 1)
        self.history_details = QTextEdit()
        self.history_details.setReadOnly(True)
        history_view_layout.addWidget(self.history_details, 1)
        right_layout.addWidget(self.history_view, 1)
        right_layout.addStretch()
        splitter.addWidget(self.right_panel)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([400, 920])
        self.detect_btn.clicked.connect(self.detect_current_os)
        self.snapshot_btn.clicked.connect(self.acquire_snapshot)
        self.load_btn.clicked.connect(self.load_existing_snapshot)
        self.history_btn.clicked.connect(self.show_history_fullscreen)
        self.history_back_btn.clicked.connect(self.hide_history_fullscreen)
        self.analyze_btn.clicked.connect(self.analyze_snapshot)
        self.os_selector.currentTextChanged.connect(self.on_os_changed)
        self.analysis_profile_selector.currentTextChanged.connect(self.refresh_scan_catalog)
        self.run_advanced_btn.clicked.connect(self.run_advanced_command)
        self.history_filter_btn.clicked.connect(self.apply_history_filters)
        self.history_filter_clear_btn.clicked.connect(self.clear_history_filters)
        self.generate_report_btn.clicked.connect(self.generate_report_current)
        self.update_analysis_profile_ui()

    def on_os_changed(self, os_text):
        self.refresh_scan_catalog()
        self.load_available_plugins_for_os(os_text)
        self.update_analysis_profile_ui()

    def current_timestamp(self):
        return datetime.now().strftime('%H:%M:%S')

    def write_general_log(self, message):
        self.general_log.append(f'[{self.current_timestamp()}] {message}')

    def show_loading(self, label_text):
        self.loading_label.setText(label_text)
        self.loading_bar.setValue(0)
        self.loading_bar.setRange(0, 100)
        x = (self.width() - self.loading_widget.width()) // 2
        y = (self.height() - self.loading_widget.height()) // 2
        self.loading_widget.setGeometry(x, y, self.loading_widget.width(), self.loading_widget.height())
        self.loading_widget.raise_()
        self.loading_widget.setVisible(True)

    def update_loading(self, value):
        self.loading_bar.setValue(value)

    def hide_loading(self, hold_percent=False):
        if hold_percent:
            self.loading_bar.setValue(100)
            QTimer.singleShot(5000, self._do_hide_loading)
        else:
            self._do_hide_loading()

    def _do_hide_loading(self):
        self.loading_widget.setVisible(False)

    def clear_result_tabs(self):
        self.suspicious_output.clear()
        self.advanced_output.setRowCount(0)
        for scan_name, widget in list(self.tab_outputs.items()):
            if isinstance(widget, QScrollArea):
                table = widget.widget()
                if table:
                    table.setRowCount(0)
                    table.setColumnCount(0)
            elif isinstance(widget, QTableWidget):
                widget.setRowCount(0)
                widget.setColumnCount(0)
        self.tabs.setTabVisible(self.tabs.indexOf(self.suspicious_output), False)
        self.tabs.setTabVisible(self.tabs.indexOf(self.advanced_scroll), False)
        for widget in list(self.tab_outputs.values()):
            if isinstance(widget, QScrollArea):
                idx = self.tabs.indexOf(widget)
            else:
                idx = -1
            if idx >= 0:
                self.tabs.setTabVisible(idx, False)

    def set_ui_busy(self, busy: bool):
        self.detect_btn.setEnabled(not busy)
        self.snapshot_btn.setEnabled(not busy)
        self.load_btn.setEnabled(not busy)
        self.analyze_btn.setEnabled(not busy)
        self.history_btn.setEnabled(not busy)
        self.os_selector.setEnabled(not busy)
        self.analysis_profile_selector.setEnabled(not busy)
        custom_mode = self.analysis_profile_selector.currentText() == 'Custom Analysis'
        self.run_advanced_btn.setEnabled(not busy and custom_mode)
        self.advanced_command_input.setEnabled(not busy and custom_mode)
        self.plugin_search.setEnabled(not busy and custom_mode)

    def format_size(self, size_bytes):
        if size_bytes is None:
            return '-'
        if size_bytes < 1024:
            return f'{size_bytes} B'
        if size_bytes < 1024 ** 2:
            return f'{size_bytes / 1024:.2f} KB'
        if size_bytes < 1024 ** 3:
            return f'{size_bytes / 1024 ** 2:.2f} MB'
        return f'{size_bytes / 1024 ** 3:.2f} GB'

    def on_plugin_search_changed(self, text):
        self.advanced_command_input.setText(text)

    def load_available_plugins_for_os(self, os_type):
        if not hasattr(self, 'plugin_search'):
            return
        from analysis.analyzer import get_available_plugins
        plugins = get_available_plugins(os_type)
        if plugins:
            self.plugin_search.clear()
            self.plugin_search.addItems(plugins)
            completer = QCompleter(plugins)
            completer.setFilterMode(Qt.MatchContains)
            self.plugin_search.setCompleter(completer)

    def update_summary_box(self):
        dump_name = os.path.basename(self.snapshot_file) if self.snapshot_file else '-'
        self.summary_dump_name.setText(dump_name)
        self.summary_dump_size.setText(self.last_dump_size)
        self.summary_analyst.setText(self.analyst_name)
        self.summary_acquisition_timestamp.setText(self.last_acquisition_timestamp)
        self.summary_acquisition_time.setText(self.last_acquisition_time)
        self.summary_analysis_time.setText(self.last_analysis_time)
        self.summary_hash.setText(self.last_hash_value)

    def detect_current_os(self):
        os_name = platform.system()
        if os_name == 'Windows':
            self.os_type = 'Windows'
        elif os_name == 'Linux':
            self.os_type = 'Linux'
        else:
            self.os_type = 'Unsupported'
        pass
        self.write_general_log(f'[INFO] OS detected: {self.os_type}')
        if self.os_type in ['Windows', 'Linux']:
            self.os_selector.setCurrentText(self.os_type)
            self.load_available_plugins_for_os(self.os_type)
        self.refresh_scan_catalog()

    def update_analysis_profile_ui(self):
        selected_os = self.os_selector.currentText()
        profile = self.analysis_profile_selector.currentText()
        if profile == 'Quick Triage':
            scans = get_preset_scans(selected_os, 'Quick Triage')
            self.analysis_profile_info.setText(f"Quick Triage scans: {', '.join(scans)}")
        elif profile == 'Standard Analysis':
            scans = get_preset_scans(selected_os, 'Full Snapshot')
            self.analysis_profile_info.setText(f"Standard Analysis scans: {', '.join(scans)}")
        else:
            self.analysis_profile_info.setText('Manually select the scans you want to run.')
        self.refresh_scan_catalog()

    def refresh_scan_catalog(self):
        profile = self.analysis_profile_selector.currentText()
        selected_os = self.os_selector.currentText()
        if profile == 'Quick Triage':
            scans = get_preset_scans(selected_os, 'Quick Triage')
            self.analysis_profile_info.setText(f"Quick Triage scans: {', '.join(scans)}")
            self.advanced_group.setVisible(False)
            self.run_advanced_btn.setEnabled(False)
            self.advanced_command_input.setEnabled(False)
            self.plugin_search.setEnabled(False)
        elif profile == 'Standard Analysis':
            scans = get_preset_scans(selected_os, 'Full Snapshot')
            self.analysis_profile_info.setText(f"Standard Analysis scans: {', '.join(scans)}")
            self.advanced_group.setVisible(False)
            self.run_advanced_btn.setEnabled(False)
            self.advanced_command_input.setEnabled(False)
            self.plugin_search.setEnabled(False)
        else:
            self.analysis_profile_info.setText('Custom mode: Enter plugin name in command field below')
            self.advanced_group.setVisible(True)
            self.advanced_group.setEnabled(True)
            self.run_advanced_btn.setEnabled(True)
            self.advanced_command_input.setEnabled(True)
            self.plugin_search.setEnabled(True)
            self.load_available_plugins_for_os(selected_os)

    def get_selected_scans(self):
        profile = self.analysis_profile_selector.currentText()
        selected_os = self.os_selector.currentText()
        if profile == 'Quick Triage':
            return get_preset_scans(selected_os, 'Quick Triage')
        if profile == 'Standard Analysis':
            return get_preset_scans(selected_os, 'Full Snapshot')
        cmd = self.advanced_command_input.text().strip()
        if cmd:
            return [cmd]
        return []

    def _populate_table(self, table, raw_text):
        table.setRowCount(0)
        table.setColumnCount(0)
        if not raw_text or not raw_text.strip():
            return
        lines = [l.strip() for l in raw_text.splitlines() if l.strip()]
        filtered = []
        for line in lines:
            if line.startswith('Volatility 3') or line.startswith('***') or line.startswith('Module'):
                continue
            filtered.append(line)
        if len(filtered) < 2:
            return
        header_cells = filtered[0].split()
        col_count = len(header_cells)
        table.setColumnCount(col_count)
        table.setHorizontalHeaderLabels(header_cells)
        table.setRowCount(len(filtered) - 1)
        for row_idx, line in enumerate(filtered[1:]):
            cells = line.split()
            for col_idx, cell in enumerate(cells):
                if col_idx < col_count:
                    item = QTableWidgetItem(cell)
                    item.setToolTip(cell)
                    table.setItem(row_idx, col_idx, item)
        table.resizeColumnsToContents()

    def ensure_result_tabs(self, scan_names):
        existing_names = set(self.tab_outputs.keys())
        requested_names = set(scan_names)
        for scan_name in list(existing_names):
            if scan_name not in requested_names:
                scroll = self.tab_outputs.pop(scan_name)
                idx = self.tabs.indexOf(scroll)
                if idx >= 0:
                    self.tabs.removeTab(idx)
        for scan_name in scan_names:
            if scan_name not in existing_names:
                scroll = QScrollArea()
                scroll.setWidgetResizable(True)
                table = QTableWidget()
                table.setEditTriggers(QTableWidget.NoEditTriggers)
                table.setSelectionBehavior(QTableWidget.SelectRows)
                table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
                table.verticalHeader().setVisible(False)
                scroll.setWidget(table)
                self.tab_outputs[scan_name] = scroll
                self.tabs.addTab(scroll, scan_name)
        self.tabs.setTabVisible(self.tabs.indexOf(self.suspicious_output), True)
        self.tabs.setTabVisible(self.tabs.indexOf(self.advanced_scroll), True)
        for widget in self.tab_outputs.values():
            idx = self.tabs.indexOf(widget)
            if idx >= 0:
                self.tabs.setTabVisible(idx, True)

    def acquire_snapshot(self):
        if not self.os_type:
            self.write_general_log('[ERROR] Detect OS first!')
            pass
            return
        storage_check = check_storage_for_acquisition(DUMP_DIR, self.os_type)
        if storage_check.message.startswith('[WARNING]'):
            self.write_general_log(storage_check.message)
        elif storage_check.ok:
            self.write_general_log(storage_check.message)
        if not storage_check.ok:
            self.write_general_log(storage_check.message)
            QMessageBox.warning(self, 'Insufficient disk space', f'This machine does not have enough free disk space for a full memory capture.\n\nInstalled RAM: {format_bytes(storage_check.physical_memory_bytes)}\nSpace needed (estimate): {format_bytes(storage_check.required_bytes)}\nFree on drive ({storage_check.dump_dir}): {format_bytes(storage_check.free_bytes)}\n\nFree disk space or save the dump to another drive, then try again.')
            return
        self.snapshot_start_time = time.perf_counter()
        self.set_ui_busy(True)
        self.write_general_log('[INFO] Starting full memory acquisition...')
        self.show_loading('Acquiring Snapshot...')
        self.snapshot_thread = QThread()
        self.snapshot_worker = SnapshotWorker(self.os_type)
        self.snapshot_worker.moveToThread(self.snapshot_thread)
        self.snapshot_thread.started.connect(self.snapshot_worker.run)
        self.snapshot_worker.log.connect(self.write_general_log)
        self.snapshot_worker.finished.connect(self.on_snapshot_finished)
        self.snapshot_worker.error.connect(self.on_snapshot_error)
        self.snapshot_worker.finished.connect(self.snapshot_thread.quit)
        self.snapshot_worker.error.connect(self.snapshot_thread.quit)
        self.snapshot_worker.finished.connect(self.snapshot_worker.deleteLater)
        self.snapshot_worker.error.connect(self.snapshot_worker.deleteLater)
        self.snapshot_thread.finished.connect(self.snapshot_thread.deleteLater)
        self.snapshot_thread.start()

    def on_snapshot_finished(self, dump_path):
        snapshot_time = time.perf_counter() - self.snapshot_start_time
        self.snapshot_file = dump_path
        self.update_loading(70)
        self.write_general_log(f'[INFO] Snapshot saved: {dump_path}')
        self.write_general_log(f'[INFO] RAM acquisition completed in {snapshot_time:.2f} seconds')
        self.last_acquisition_time = f'{snapshot_time:.2f} s'
        self.last_acquisition_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            file_hash = hash_file(dump_path)
            self.last_hash_value = file_hash
            self.write_general_log(f'[FORENSIC] SHA256: {file_hash}')
        except Exception as e:
            self.last_hash_value = '-'
            self.write_general_log(f'[ERROR] Hashing failed: {e}')
        try:
            size_bytes = os.path.getsize(dump_path)
            self.last_dump_size_bytes = size_bytes
            self.last_dump_size = self.format_size(size_bytes)
        except Exception:
            self.last_dump_size_bytes = 0
            self.last_dump_size = '-'
        self.current_dump_id = insert_dump(case_id=self.current_case_id, file_name=os.path.basename(dump_path), file_path=dump_path, os_type=self.os_type or 'Unknown', acquisition_mode='Full Snapshot', analyst=self.analyst_name, hash_sha256=self.last_hash_value, file_size_bytes=self.last_dump_size_bytes, acquired_at=self.last_acquisition_timestamp, acquisition_duration_seconds=round(snapshot_time, 2), notes='')
        self.update_summary_box()
        self.refresh_history_tab()
        pass
        self.update_loading(100)
        self.hide_loading(hold_percent=True)
        self.summary_box.setVisible(True)
        self.set_ui_busy(False)

    def on_snapshot_error(self, message):
        self.write_general_log(message)
        pass
        self.update_loading(0)
        self._do_hide_loading()
        self.set_ui_busy(False)

    def load_existing_snapshot(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open Memory Dump', '', 'RAW files (*.raw);;All Files (*)')
        if file_path:
            self.snapshot_file = file_path
            self.set_ui_busy(True)
            self.show_loading('Loading Snapshot...')
            self.clear_result_tabs()
            self.generate_report_btn.setVisible(False)
            self.write_general_log(f'[INFO] Loaded snapshot: {file_path}')
            try:
                file_hash = hash_file(file_path)
                self.last_hash_value = file_hash
                self.write_general_log(f'[FORENSIC] SHA256: {file_hash}')
            except Exception as e:
                self.last_hash_value = '-'
                self.write_general_log(f'[ERROR] Could not hash loaded file: {e}')
            try:
                size_bytes = os.path.getsize(file_path)
                self.last_dump_size_bytes = size_bytes
                self.last_dump_size = self.format_size(size_bytes)
            except Exception:
                self.last_dump_size_bytes = 0
                self.last_dump_size = '-'
            self.last_acquisition_time = '-'
            self.last_analysis_time = '-'
            self.last_acquisition_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.current_dump_id = insert_dump(case_id=self.current_case_id, file_name=os.path.basename(file_path), file_path=file_path, os_type=self.os_selector.currentText(), acquisition_mode='Loaded Existing Dump', analyst=self.analyst_name, hash_sha256=self.last_hash_value, file_size_bytes=self.last_dump_size_bytes, acquired_at=self.last_acquisition_timestamp, acquisition_duration_seconds=None, notes='Loaded existing snapshot')
            self.update_summary_box()
            self.refresh_history_tab()
            self.summary_box.setVisible(True)
            self.update_loading(100)
            self.hide_loading(hold_percent=True)
            self.set_ui_busy(False)

    def analyze_snapshot(self):
        if not self.snapshot_file:
            self.write_general_log('[ERROR] No snapshot loaded')
            return
        selected_os = self.os_selector.currentText()
        self.last_analysis_profile = self.analysis_profile_selector.currentText()
        selected_scans = self.get_selected_scans()
        if not selected_scans:
            self.write_general_log('[ERROR] Please select at least one scan.')
            return
        self.analysis_start_time = time.perf_counter()
        self.analysis_started_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.clear_result_tabs()
        self.ensure_result_tabs(selected_scans)
        self.show_loading('Analyzing Snapshot...')
        self.write_general_log(f'[INFO] Loaded snapshot: {self.snapshot_file}')
        self.write_general_log(f'[INFO] Analysis mode selected: {selected_os}')
        self.write_general_log(f'[INFO] Analysis profile: {self.last_analysis_profile}')
        self.write_general_log(f"[INFO] Selected scans: {', '.join(selected_scans)}")
        self.set_ui_busy(True)
        self.analysis_thread = QThread()
        self.analysis_worker = AnalysisWorker(self.snapshot_file, selected_os, selected_scans)
        self.analysis_worker.moveToThread(self.analysis_thread)
        self.analysis_thread.started.connect(self.analysis_worker.run)
        self.analysis_worker.log.connect(self.write_general_log)
        self.analysis_worker.progress.connect(self.loading_bar.setValue)
        self.analysis_worker.finished.connect(self.on_analysis_finished)
        self.analysis_worker.error.connect(self.on_analysis_error)
        self.analysis_worker.finished.connect(self.analysis_thread.quit)
        self.analysis_worker.error.connect(self.analysis_thread.quit)
        self.analysis_worker.finished.connect(self.analysis_worker.deleteLater)
        self.analysis_worker.error.connect(self.analysis_worker.deleteLater)
        self.analysis_thread.finished.connect(self.analysis_thread.deleteLater)
        self.analysis_thread.start()

    def on_analysis_finished(self, results):
        analysis_time = time.perf_counter() - self.analysis_start_time
        self.last_analysis_time = f'{analysis_time:.2f} s'
        self.update_summary_box()
        self.general_log.setPlainText(results.get('General Log', ''))
        self.suspicious_output.setPlainText(results.get('Suspicious Findings', ''))
        for scan_name, scroll in self.tab_outputs.items():
            raw = results.get(scan_name, '')
            table = scroll.widget()
            if table:
                self._populate_table(table, raw)
        self.general_log.append(f'\n[{self.current_timestamp()}] [INFO] Memory analysis completed in {analysis_time:.2f} seconds')
        if self.ti_enrichment_checkbox.isChecked():
            self._prompt_ti_enrichment(results)
        if self.current_dump_id is not None:
            self.current_analysis_id = insert_analysis_session(dump_id=self.current_dump_id, analysis_profile=self.last_analysis_profile, started_at=self.analysis_started_at, duration_seconds=round(analysis_time, 2), suspicious_summary=results.get('Suspicious Findings', ''))
            for key, value in results.items():
                if key not in ['General Log', 'Suspicious Findings', 'Advanced Output']:
                    insert_plugin_result(self.current_analysis_id, key, value)
            suspicious_text = results.get('Suspicious Findings', '').splitlines()
            for line in suspicious_text:
                line = line.strip()
                if not line:
                    continue
                severity = 'INFO'
                if line.startswith('[HIGH]'):
                    severity = 'HIGH'
                elif line.startswith('[MEDIUM]'):
                    severity = 'MEDIUM'
                elif line.startswith('[LOW]'):
                    severity = 'LOW'
                insert_suspicious_finding(analysis_id=self.current_analysis_id, severity=severity, category='Auto Summary', finding_text=line)
        self.refresh_history_tab()
        self.summary_box.setVisible(True)
        self.generate_report_btn.setVisible(True)
        self.update_loading(100)
        self.hide_loading(hold_percent=True)
        self.set_ui_busy(False)

    def on_analysis_error(self, message):
        self.write_general_log(message)
        pass
        self.update_loading(0)
        self._do_hide_loading()
        self.set_ui_busy(False)

    def _prompt_ti_enrichment(self, results):
        from PySide6.QtWidgets import QMessageBox
        suspicious_findings = results.get('Suspicious Findings', '').strip()
        if not suspicious_findings:
            return
        findings_count = len([line for line in suspicious_findings.splitlines() if line.strip()])
        if findings_count == 0:
            return
        high_medium_count = sum((1 for line in suspicious_findings.splitlines() if line.startswith('[HIGH]') or line.startswith('[MEDIUM]')))
        msg = f'Found {findings_count} suspicious indicator(s) ({high_medium_count} HIGH/MEDIUM).\n\n'
        msg += 'Would you like to enrich these with Threat Intelligence APIs?\n'
        msg += '(VirusTotal, AbuseIPDB, AlienVault OTX)\n\n'
        msg += 'This will query external APIs for additional context.'
        reply = QMessageBox.question(self, 'Threat Intelligence Enrichment', msg, QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if reply == QMessageBox.Yes:
            self._do_ti_enrichment(results)
        else:
            self.general_log.append(f'[{self.current_timestamp()}] [INFO] TI enrichment skipped by user')

    def _do_ti_enrichment(self, results):
        from threat_intel import get_engine, LookupMode
        self.general_log.append(f'[{self.current_timestamp()}] [INFO] Starting threat intelligence enrichment...')
        try:
            engine = get_engine()
            if not engine.is_available():
                self.general_log.append(f'[{self.current_timestamp()}] [WARNING] No TI providers configured')
                return
            indicators = self._extract_indicators_from_results(results)
            if not indicators['hashes'] and (not indicators['ips']) and (not indicators['domains']):
                self.general_log.append(f'[{self.current_timestamp()}] [INFO] No indicators found for TI enrichment')
                return
            self.general_log.append(f"[{self.current_timestamp()}] [INFO] Checking {len(indicators['hashes'])} hashes, {len(indicators['ips'])} IPs, {len(indicators['domains'])} domains...")
            enrichment = engine.enrich_findings(indicators, mode=LookupMode.CACHE_FIRST)
            ti_findings = []
            for finding in enrichment.findings:
                if finding.risk_score.value in ('HIGH', 'MEDIUM', 'CRITICAL'):
                    ti_findings.append(f'  [{finding.risk_score.value}] {finding.original_value}')
            if ti_findings:
                results['Threat Intelligence'] = '\n'.join(ti_findings)
                risk_level, confidence = engine.get_unified_risk_score(enrichment.findings)
                self.general_log.append(f'[{self.current_timestamp()}] [WARNING] TI Risk Score: {risk_level.value} ({confidence}% confidence)')
                self.general_log.append(f"[{self.current_timestamp()}] [INFO] Malicious IOCs found: {enrichment.stats.get('malicious_found', 0)}")
                if 'Threat Intelligence' in results:
                    self.suspicious_output.append('\n--- Threat Intelligence ---')
                    self.suspicious_output.append(results['Threat Intelligence'])
                from database.db_manager import update_ti_enrichment
                update_ti_enrichment(self.current_analysis_id, results.get('Threat Intelligence', 'No threats found'), risk_level.value if ti_findings else 'LOW', confidence if ti_findings else 100)
            else:
                self.general_log.append(f'[{self.current_timestamp()}] [INFO] No malicious indicators found in TI databases')
                from database.db_manager import update_ti_enrichment
                update_ti_enrichment(self.current_analysis_id, 'No malicious IOCs found', 'LOW', 100)
        except Exception as e:
            self.general_log.append(f'[{self.current_timestamp()}] [ERROR] TI enrichment failed: {e}')

    def _extract_indicators_from_results(self, results: dict) -> dict:
        import re
        import ipaddress
        indicators = {'hashes': set(), 'ips': set(), 'domains': set()}
        network_text = results.get('Network Connections', '')
        if network_text:
            ip_pattern = '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b'
            ips = re.findall(ip_pattern, network_text)
            for ip in ips:
                try:
                    ipaddress.ip_address(ip)
                    if ip not in ('0.0.0.0', '127.0.0.1', '255.255.255.255'):
                        indicators['ips'].add(ip)
                except ValueError:
                    pass
        cmdline_text = results.get('Command Line', '') + '\n' + results.get('Command History', '')
        if cmdline_text:
            url_pattern = 'https?://[^\\s<>"\\\'\\)]+'
            urls = re.findall(url_pattern, cmdline_text)
            for url in urls:
                domain_match = re.search('://([^/:]+)', url)
                if domain_match:
                    domain = domain_match.group(1)
                    if domain and (not domain.replace('.', '').isdigit()):
                        indicators['domains'].add(domain.lower())
        hash_pattern = '\\b[a-fA-F0-9]{32}\\b'
        for key in ['Processes', 'DLL List', 'File Artifacts']:
            text = results.get(key, '')
            hashes = re.findall(hash_pattern, text)
            for h in hashes:
                if h.upper() != '0' * len(h):
                    indicators['hashes'].add(h.upper())
        return {'hashes': list(indicators['hashes']), 'ips': list(indicators['ips']), 'domains': list(indicators['domains'])}

    def run_advanced_command(self):
        if not self.snapshot_file:
            self.write_general_log('[ERROR] No snapshot loaded')
            return
        command_text = self.advanced_command_input.text().strip()
        if not command_text:
            self.write_general_log('[ERROR] Please enter an advanced command.')
            return
        selected_os = self.os_selector.currentText()
        self.set_ui_busy(True)
        self.write_general_log(f'[INFO] Starting advanced command: {command_text}')
        self.show_loading('Running Advanced Command...')
        self.advanced_thread = QThread()
        self.advanced_worker = AdvancedWorker(self.snapshot_file, selected_os, command_text)
        self.advanced_worker.moveToThread(self.advanced_thread)
        self.advanced_thread.started.connect(self.advanced_worker.run)
        self.advanced_worker.log.connect(self.write_general_log)
        self.advanced_worker.finished.connect(self.on_advanced_finished)
        self.advanced_worker.error.connect(self.on_advanced_error)
        self.advanced_worker.finished.connect(self.advanced_thread.quit)
        self.advanced_worker.error.connect(self.advanced_thread.quit)
        self.advanced_worker.finished.connect(self.advanced_worker.deleteLater)
        self.advanced_worker.error.connect(self.advanced_worker.deleteLater)
        self.advanced_thread.finished.connect(self.advanced_thread.deleteLater)
        self.advanced_thread.start()

    def on_advanced_finished(self, output_list):
        output_text = ''
        if isinstance(output_list, list):
            for i, item in enumerate(output_list):
                cmd = item.get('command', 'unknown')
                raw = item.get('output', '')
                output_text += f'\n\n--- {cmd} ---\n\n' + raw
                if i == 0:
                    self._populate_table(self.advanced_output, raw)
        command_text = self.advanced_command_input.text().strip().replace(';', '/').replace('&&', '/').replace('\n', '/')
        if len(command_text) > 25:
            command_text = command_text[:22] + '...'
        idx = self.tabs.indexOf(self.advanced_scroll)
        self.tabs.setTabText(idx, command_text)
        self.tabs.setTabVisible(self.tabs.indexOf(self.advanced_scroll), True)
        if self.current_dump_id is not None:
            insert_advanced_command(dump_id=self.current_dump_id, analyst=self.analyst_name, command_text=self.advanced_command_input.text().strip(), output_text=output_text if output_text else str(output_list), executed_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        self.refresh_history_tab()
        self.update_loading(100)
        self.hide_loading(hold_percent=True)
        self.set_ui_busy(False)

    def on_advanced_error(self, message):
        self.write_general_log(message)
        self.tabs.setTabVisible(self.tabs.indexOf(self.advanced_scroll), True)
        self.update_loading(0)
        self._do_hide_loading()
        self.set_ui_busy(False)

    def show_history_fullscreen(self):
        self.tabs.setVisible(False)
        self.summary_box.setVisible(False)
        self.generate_report_btn.setVisible(False)
        self.history_view.setVisible(True)
        self.history_btn.setVisible(False)

    def hide_history_fullscreen(self):
        self.history_view.setVisible(False)
        self.tabs.setVisible(True)
        self.history_btn.setVisible(True)
        if self.snapshot_file:
            self.summary_box.setVisible(True)
            self.generate_report_btn.setVisible(True)

    def refresh_history_tab(self):
        history = get_dump_history(use_default_date_range=False)
        self.history_table.setRowCount(len(history))
        for row_idx, row in enumerate(history):
            self.history_table.setItem(row_idx, 0, QTableWidgetItem(str(row['dump_id'])))
            self.history_table.setItem(row_idx, 1, QTableWidgetItem(row['file_name'] or ''))
            self.history_table.setItem(row_idx, 2, QTableWidgetItem(row['os_type'] or ''))
            self.history_table.setItem(row_idx, 3, QTableWidgetItem(row['analyst'] or ''))
            self.history_table.setItem(row_idx, 4, QTableWidgetItem(row['acquired_at'] or ''))
            self.history_table.setItem(row_idx, 5, QTableWidgetItem(self.format_size(row['file_size_bytes'] or 0)))
            self.history_table.setItem(row_idx, 6, QTableWidgetItem(str(row['analysis_count'] or 0)))
            report_btn = QPushButton('Report')
            report_btn.setFixedSize(70, 24)
            report_btn.setProperty('dump_id', row['dump_id'])
            report_btn.clicked.connect(lambda checked, did=row['dump_id']: self.generate_report_from_history_row(did))
            self.history_table.setCellWidget(row_idx, 7, report_btn)
        self._set_default_date_filters()

    def _set_default_date_filters(self):
        from datetime import date
        conn = get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT MIN(acquired_at) as min_date FROM dumps')
            row = cursor.fetchone()
            if row and row['min_date']:
                self.history_filter_date_from.setDate(QDate.fromString(row['min_date'][:10], 'yyyy-MM-dd'))
            else:
                self.history_filter_date_from.clear()
        finally:
            conn.close()
        self.history_filter_date_to.setDate(QDate.currentDate())

    def apply_history_filters(self):
        try:
            filename = self.history_filter_filename.text().strip() or None
            os_type = self.history_filter_os.currentText()
            analysis_profile = self.history_filter_profile.currentText()
            date_from = self.history_filter_date_from.text().strip() or None
            date_to = self.history_filter_date_to.text().strip() or None
            history = get_dump_history(filename=filename, date_from=date_from, date_to=date_to, os_type=os_type if os_type != 'All' else None, analysis_profile=analysis_profile if analysis_profile != 'All' else None, use_default_date_range=False)
            self.history_table.setRowCount(len(history))
            for row_idx, row in enumerate(history):
                self.history_table.setItem(row_idx, 0, QTableWidgetItem(str(row['dump_id'])))
                self.history_table.setItem(row_idx, 1, QTableWidgetItem(row['file_name'] or ''))
                self.history_table.setItem(row_idx, 2, QTableWidgetItem(row['os_type'] or ''))
                self.history_table.setItem(row_idx, 3, QTableWidgetItem(row['analyst'] or ''))
                self.history_table.setItem(row_idx, 4, QTableWidgetItem(row['acquired_at'] or ''))
                self.history_table.setItem(row_idx, 5, QTableWidgetItem(self.format_size(row['file_size_bytes'] or 0)))
                self.history_table.setItem(row_idx, 6, QTableWidgetItem(str(row['analysis_count'] or 0)))
                report_btn = QPushButton('Report')
                report_btn.setFixedSize(70, 24)
                report_btn.setProperty('dump_id', row['dump_id'])
                report_btn.clicked.connect(lambda checked, did=row['dump_id']: self.generate_report_from_history_row(did))
                self.history_table.setCellWidget(row_idx, 7, report_btn)
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Failed to apply filters: {e}')

    def clear_history_filters(self):
        self.history_filter_filename.clear()
        self.history_filter_date_from.clear()
        self.history_filter_date_to.clear()
        self.history_filter_os.setCurrentText('All')
        self.history_filter_profile.setCurrentText('All')
        self.refresh_history_tab()

    def on_history_row_selected(self):
        selected_items = self.history_table.selectedItems()
        if not selected_items:
            self.history_details.clear()
            return
        row = selected_items[0].row()
        dump_id_item = self.history_table.item(row, 0)
        if not dump_id_item:
            self.history_details.clear()
            return
        dump_id = int(dump_id_item.text())
        details = get_dump_details(dump_id)
        dump = details.get('dump', {})
        analyses = details.get('analyses', [])
        advanced_commands = details.get('advanced_commands', [])
        text = []
        text.append('=== DUMP DETAILS ===')
        text.append(f"Dump ID: {dump.get('dump_id', '-')}")
        text.append(f"File Name: {dump.get('file_name', '-')}")
        text.append(f"Path: {dump.get('file_path', '-')}")
        text.append(f"OS: {dump.get('os_type', '-')}")
        text.append(f"Analyst: {dump.get('analyst', '-')}")
        text.append(f"Acquired At: {dump.get('acquired_at', '-')}")
        text.append(f"Hash: {dump.get('hash_sha256', '-')}")
        text.append(f"Size: {self.format_size(dump.get('file_size_bytes', 0))}")
        if dump.get('acquisition_duration_seconds'):
            text.append(f"Acquisition Duration: {dump.get('acquisition_duration_seconds')}")
        text.append('')
        if analyses:
            text.append('=== ANALYSIS HISTORY ===')
            for analysis in analyses:
                text.append(f"Analysis ID: {analysis.get('analysis_id', '-')}")
                text.append(f"Profile: {analysis.get('analysis_profile', '-')}")
                text.append(f"Started At: {analysis.get('started_at', '-')}")
                if analysis.get('duration_seconds'):
                    text.append(f"Duration: {analysis.get('duration_seconds')}")
                if analysis.get('suspicious_summary'):
                    text.append('Suspicious Summary:')
                    text.append(analysis.get('suspicious_summary', ''))
                text.append('')
                findings = analysis.get('suspicious_findings', [])
                if findings:
                    text.append('Findings:')
                    for finding in findings:
                        text.append(f"- [{finding.get('severity', 'INFO')}] {finding.get('finding_text', '')}")
                    text.append('')
        if advanced_commands:
            text.append('=== ADVANCED COMMAND HISTORY ===')
            for cmd in advanced_commands:
                text.append(f"Executed At: {cmd.get('executed_at', '-')}")
                text.append(f"Analyst: {cmd.get('analyst', '-')}")
                text.append(f"Command: {cmd.get('command_text', '-')}")
                text.append('')
        self.history_details.setPlainText('\n'.join(text))

    def generate_report_from_history_row(self, dump_id):
        details = get_dump_details(dump_id)
        self._save_report(details)

    def generate_report_current(self):
        if not self.current_dump_id:
            self.write_general_log('[ERROR] No analysis available to generate report.')
            return
        details = get_dump_details(self.current_dump_id)
        self._save_report(details)

    def _save_report(self, details):
        from PySide6.QtWidgets import QMessageBox
        import json
        dump = details.get('dump', {})
        analyses = details.get('analyses', [])
        file_name = dump.get('file_name', 'report')
        report_content = self._build_report_text(details)
        default_filename = f"report_{file_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        file_path, _ = QFileDialog.getSaveFileName(self, 'Save Report', default_filename, 'Text Files (*.txt);;All Files (*)')
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                self.write_general_log(f'[INFO] Report saved: {file_path}')
                QMessageBox.information(self, 'Report Generated', f'Report saved successfully to:\n{file_path}')
            except Exception as e:
                self.write_general_log(f'[ERROR] Failed to save report: {e}')
                QMessageBox.warning(self, 'Error', f'Failed to save report: {e}')

    def _build_report_text(self, details):
        dump = details.get('dump', {})
        analyses = details.get('analyses', [])
        advanced_commands = details.get('advanced_commands', [])
        lines = []
        lines.append('=' * 65)
        lines.append('MEMORY FORENSIC ANALYSIS REPORT'.center(65))
        lines.append('=' * 65)
        lines.append('')
        case_num = dump.get('dump_id', 'N/A')
        lines.append(f'Case Reference: {case_num}')
        lines.append(f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Examiner: {dump.get('analyst', 'N/A')}")
        lines.append('')
        lines.append('-' * 65)
        lines.append('EVIDENCE DETAILS')
        lines.append('-' * 65)
        lines.append(f"Evidence Item:     {dump.get('file_name', 'N/A')}")
        lines.append(f"Evidence Path:    {dump.get('file_path', 'N/A')}")
        lines.append(f"OS Type:           {dump.get('os_type', 'N/A')}")
        lines.append(f"Acquisition Date:  {dump.get('acquired_at', 'N/A')}")
        lines.append(f"File Size:         {self.format_size(dump.get('file_size_bytes', 0))}")
        if dump.get('acquisition_duration_seconds'):
            lines.append(f"Acq. Duration:     {dump.get('acquisition_duration_seconds')}s")
        lines.append(f"SHA-256:           {dump.get('hash_sha256', 'N/A')}")
        lines.append('')
        has_suspicious = False
        ti_findings_present = False
        for analysis in analyses:
            if analysis.get('suspicious_findings'):
                has_suspicious = True
            if analysis.get('threat_intel_summary') and analysis.get('threat_intel_summary') != 'No malicious IOCs found':
                ti_findings_present = True
        if has_suspicious or ti_findings_present:
            lines.append('-' * 65)
            lines.append('EXECUTIVE SUMMARY')
            lines.append('-' * 65)
            total_findings = sum((len(a.get('suspicious_findings', [])) for a in analyses))
            lines.append(f'Analysis Sessions: {len(analyses)}')
            lines.append(f'Total Findings:    {total_findings}')
            if ti_findings_present:
                for a in analyses:
                    if a.get('ti_risk_level'):
                        lines.append(f"TI Risk Level:     {a['ti_risk_level']} ({a.get('ti_confidence', 0)}% confidence)")
                        break
            lines.append('')
        for i, analysis in enumerate(analyses, 1):
            lines.append('-' * 65)
            lines.append(f'ANALYSIS SESSION {i}')
            lines.append('-' * 65)
            lines.append(f"Volatility Profile: {analysis.get('analysis_profile', 'N/A')}")
            lines.append(f"Analysis Started:    {analysis.get('started_at', 'N/A')}")
            if analysis.get('duration_seconds'):
                lines.append(f"Duration:            {analysis.get('duration_seconds')}s")
            lines.append('')
            plugin_results = analysis.get('plugin_results', [])
            if plugin_results:
                lines.append('VOLATILITY PLUGIN OUTPUT:')
                lines.append('')
                for plugin in plugin_results:
                    lines.append(f"[{plugin.get('plugin_name', 'N/A')}]")
                    output = plugin.get('output_text', '')
                    if output:
                        for line in output.splitlines():
                            lines.append(f'  {line}')
                    else:
                        lines.append('  (No output)')
                    lines.append('')
                lines.append('')
            findings = analysis.get('suspicious_findings', [])
            if findings:
                lines.append('FINDINGS:')
                lines.append('')
                for finding in findings:
                    sev = finding.get('severity', 'INFO')
                    cat = finding.get('category', '')
                    txt = finding.get('finding_text', '')
                    lines.append(f'  [{sev}] {cat}: {txt}')
                lines.append('')
            ti_summary = analysis.get('threat_intel_summary')
            if ti_summary and ti_summary != 'No malicious IOCs found':
                lines.append('THREAT INTELLIGENCE:')
                lines.append('')
                lines.append(f"  Risk Level:  {analysis.get('ti_risk_level', 'UNKNOWN')}")
                lines.append(f"  Confidence: {analysis.get('ti_confidence', 0)}%")
                lines.append('')
                lines.append('  Malicious Indicators:')
                for line in ti_summary.splitlines():
                    lines.append(f'    - {line.strip()}')
                lines.append('')
            lines.append('')
        if advanced_commands:
            lines.append('-' * 65)
            lines.append('MANUAL EXAMINATION COMMANDS')
            lines.append('-' * 65)
            for cmd in advanced_commands:
                lines.append(f"Timestamp: {cmd.get('executed_at', 'N/A')}")
                lines.append(f"Command:   {cmd.get('command_text', 'N/A')}")
                lines.append('')
        lines.append('=' * 65)
        lines.append('END OF REPORT')
        lines.append('=' * 65)
        return '\n'.join(lines)
