"""
CryptKey License Generator v2.1
Ed25519-signed license keys – private key never leaves this tool.
Author: Leon Priest <leonpriest76@gmail.com>

Run: python cryptkey_license_generator.py
"""

import sys
import json
import csv
from datetime import timedelta
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel, QComboBox, QSpinBox, QCheckBox,
    QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView,
    QGroupBox, QFrame, QFileDialog, QMessageBox, QSplitter,
    QScrollArea, QDialog,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import (
    QPainter, QLinearGradient, QBrush, QColor, QPen, QGuiApplication,
)

from cryptkey_license import (
    LICENSE_TIERS, _utcnow, machine_id,
    generate_license_key, validate_license_key,
    load_or_create_keypair,
)

# ── Storage paths ─────────────────────────────────────────────────────────────
_DATA_DIR = Path.home() / ".local/share/CryptKey"
_KEY_PATH = _DATA_DIR / "vendor.key"
_LOG_PATH = _DATA_DIR / "issued_licenses.json"

# ── Design tokens ─────────────────────────────────────────────────────────────
C = {
    "bg":        "#0A0C10",
    "surface":   "#111318",
    "surface2":  "#181C26",
    "surface3":  "#1E2333",
    "border":    "#222840",
    "accent":    "#00E5FF",
    "gold":      "#FFB830",
    "green":     "#00FFB2",
    "red":       "#FF4D6D",
    "text":      "#DDE4F0",
    "text_dim":  "#6B7590",
    "text_fade": "#30384D",
}

SS = f"""
QWidget {{
    color: {C['text']};
    font-family: 'Consolas', 'JetBrains Mono', 'Cascadia Code', monospace;
    font-size: 12px;
}}
QMainWindow {{ background: {C['bg']}; }}
QLabel, QCheckBox, QRadioButton {{ background: transparent; }}
QPushButton {{
    background: {C['surface2']}; color: {C['text']};
    border: 1px solid {C['border']}; border-radius: 5px;
    padding: 7px 16px; font-family: 'Consolas', monospace; font-size: 12px;
}}
QPushButton:hover {{
    background: {C['surface3']}; border-color: {C['accent']}; color: {C['accent']};
}}
QPushButton:pressed {{ background: {C['surface']}; }}
QPushButton:disabled {{ color: {C['text_fade']}; border-color: {C['text_fade']}; }}
QPushButton#cta {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 {C['accent']}, stop:1 #00AACC);
    color: #000; font-weight: 700; font-size: 13px;
    border: none; border-radius: 6px; padding: 10px 24px; letter-spacing: 0.5px;
}}
QPushButton#cta:hover {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #33ECFF, stop:1 {C['accent']});
}}
QPushButton#cta:disabled {{ background: {C['surface2']}; color: {C['text_fade']}; }}
QPushButton#gold {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 {C['gold']}, stop:1 #FF8C00);
    color: #000; font-weight: 700; border: none; border-radius: 6px; padding: 8px 16px;
}}
QPushButton#danger {{
    background: transparent; color: {C['red']};
    border: 1px solid {C['red']}; border-radius: 5px; padding: 7px 16px;
}}
QPushButton#danger:hover {{ background: rgba(255,77,109,0.12); }}
QLineEdit {{
    background: {C['surface2']}; border: 1px solid {C['border']};
    border-radius: 5px; padding: 7px 10px; color: {C['text']};
    font-family: 'Consolas', monospace;
    selection-background-color: {C['accent']}; selection-color: #000;
}}
QLineEdit:focus {{ border-color: {C['accent']}; background: {C['surface3']}; }}
QComboBox {{
    background: {C['surface2']}; border: 1px solid {C['border']};
    border-radius: 5px; padding: 7px 10px; color: {C['text']};
    font-family: 'Consolas', monospace;
}}
QComboBox:focus {{ border-color: {C['accent']}; }}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox QAbstractItemView {{
    background: {C['surface2']}; border: 1px solid {C['border']};
    selection-background-color: rgba(0,229,255,0.15);
    selection-color: {C['accent']}; color: {C['text']};
}}
QSpinBox {{
    background: {C['surface2']}; border: 1px solid {C['border']};
    border-radius: 5px; padding: 7px 10px; color: {C['text']};
    font-family: 'Consolas', monospace;
}}
QSpinBox:focus {{ border-color: {C['accent']}; }}
QSpinBox::up-button, QSpinBox::down-button {{
    background: {C['surface3']}; border: none; width: 18px;
}}
QTextEdit {{
    background: {C['surface2']}; border: 1px solid {C['border']};
    border-radius: 5px; padding: 8px; color: {C['green']};
    font-family: 'Consolas', 'JetBrains Mono', monospace; font-size: 11px;
    selection-background-color: {C['accent']}; selection-color: #000;
}}
QGroupBox {{
    background: {C['surface']}; border: 1px solid {C['border']};
    border-radius: 8px; margin-top: 16px; padding: 10px;
    font-size: 10px; font-weight: 700; letter-spacing: 1.5px; color: {C['text_dim']};
}}
QGroupBox::title {{
    subcontrol-origin: margin; subcontrol-position: top left;
    left: 10px; padding: 0 5px; background: {C['surface']}; color: {C['text_dim']};
}}
QTableWidget {{
    background: {C['surface']}; border: 1px solid {C['border']};
    border-radius: 6px; gridline-color: {C['border']}; color: {C['text']}; outline: none;
}}
QTableWidget::item {{ padding: 6px 10px; border: none; }}
QTableWidget::item:selected {{
    background: rgba(0,229,255,0.12); color: {C['accent']};
}}
QHeaderView::section {{
    background: {C['surface2']}; color: {C['text_dim']};
    border: none; border-right: 1px solid {C['border']};
    border-bottom: 1px solid {C['border']};
    padding: 6px 10px; font-size: 10px; font-weight: 700; letter-spacing: 1px;
}}
QCheckBox {{ spacing: 8px; color: {C['text']}; }}
QCheckBox::indicator {{
    width: 16px; height: 16px; border: 1px solid {C['border']};
    border-radius: 3px; background: {C['surface2']};
}}
QCheckBox::indicator:checked {{ background: {C['accent']}; border-color: {C['accent']}; }}
QScrollBar:vertical {{
    background: {C['surface']}; width: 7px; border-radius: 3px;
}}
QScrollBar::handle:vertical {{
    background: {C['border']}; border-radius: 3px; min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{ background: {C['accent']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QSplitter::handle {{ background: {C['border']}; width: 1px; }}
QFrame[frameShape="4"], QFrame[frameShape="5"] {{
    color: {C['border']}; background: {C['border']}; border: none; max-height: 1px;
}}
QDialog {{ background: {C['surface']}; }}
"""


# ── Log helpers ───────────────────────────────────────────────────────────────

def _load_log() -> list:
    try:
        if _LOG_PATH.exists():
            return json.loads(_LOG_PATH.read_text())
    except Exception:
        pass
    return []

def _save_log(records: list):
    _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _LOG_PATH.write_text(json.dumps(records, indent=2, default=str))


# ── Master-password dialog ────────────────────────────────────────────────────

class MasterPasswordDialog(QDialog):
    def __init__(self, is_new_keypair: bool, parent=None):
        super().__init__(parent)
        self.setWindowTitle("CryptKey – Vendor Authentication")
        self.setModal(True)
        self.setMinimumWidth(460)
        self._result_priv = ""
        self._result_pub  = ""
        self._build(is_new_keypair)

    def _build(self, is_new: bool):
        lay = QVBoxLayout(self)
        lay.setSpacing(14)
        lay.setContentsMargins(28, 28, 28, 28)

        icon_lbl = QLabel("⚿")
        icon_lbl.setStyleSheet(
            f"font-size:36px;color:{C['accent']};background:transparent;")
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(icon_lbl)

        title = QLabel("Create Master Password" if is_new else "Enter Master Password")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(
            f"font-size:16px;font-weight:700;color:{C['text']};background:transparent;")
        lay.addWidget(title)

        subtitle_text = (
            "This password encrypts your Ed25519 private signing key on disk.\n"
            "Choose something strong — you cannot recover it if lost."
            if is_new else
            "Unlock your vendor signing key to issue licenses."
        )
        subtitle = QLabel(subtitle_text)
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet(
            f"color:{C['text_dim']};font-size:11px;background:transparent;")
        subtitle.setWordWrap(True)
        lay.addWidget(subtitle)

        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        lay.addWidget(sep)

        self.pw_edit = QLineEdit()
        self.pw_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw_edit.setPlaceholderText("Master password")
        self.pw_edit.setMinimumHeight(36)
        lay.addWidget(self.pw_edit)

        self.confirm_edit = None
        if is_new:
            self.confirm_edit = QLineEdit()
            self.confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.confirm_edit.setPlaceholderText("Confirm master password")
            self.confirm_edit.setMinimumHeight(36)
            lay.addWidget(self.confirm_edit)

        self.error_lbl = QLabel("")
        self.error_lbl.setStyleSheet(
            f"color:{C['red']};font-size:11px;background:transparent;")
        self.error_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self.error_lbl)

        btn_row = QHBoxLayout()
        self.ok_btn = QPushButton("Create Key" if is_new else "Unlock")
        self.ok_btn.setObjectName("cta")
        self.ok_btn.setMinimumHeight(36)
        self.ok_btn.clicked.connect(self._attempt)
        self.pw_edit.returnPressed.connect(self._attempt)
        if self.confirm_edit:
            self.confirm_edit.returnPressed.connect(self._attempt)
        cancel_btn = QPushButton("Exit")
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(self.ok_btn)
        btn_row.addWidget(cancel_btn)
        lay.addLayout(btn_row)

        if is_new:
            note = QLabel(
                "⚠  Your public key will be saved to vendor.pub.json.\n"
                "   Click 'Show Public Key' in the app to get the embed constant.")
            note.setStyleSheet(
                f"color:{C['gold']};font-size:10px;background:transparent;")
            note.setWordWrap(True)
            lay.addWidget(note)

    def _attempt(self):
        pw = self.pw_edit.text()
        if not pw:
            self.error_lbl.setText("Password cannot be empty.")
            return
        if self.confirm_edit is not None:
            if pw != self.confirm_edit.text():
                self.error_lbl.setText("Passwords do not match.")
                return
            if len(pw) < 8:
                self.error_lbl.setText("Password must be at least 8 characters.")
                return
        self.ok_btn.setEnabled(False)
        self.ok_btn.setText("Working…")
        QApplication.processEvents()
        try:
            priv, pub = load_or_create_keypair(_KEY_PATH, pw)
            self._result_priv = priv
            self._result_pub  = pub
            self.accept()
        except ValueError as e:
            self.error_lbl.setText(str(e))
            self.ok_btn.setEnabled(True)
            self.ok_btn.setText("Unlock")

    def credentials(self) -> tuple:
        return self._result_priv, self._result_pub


# ── Header ────────────────────────────────────────────────────────────────────

class HeaderBar(QWidget):
    def __init__(self, pub_key_b64: str, parent=None):
        super().__init__(parent)
        self.setFixedHeight(56)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(20, 0, 20, 0)

        logo = QLabel(
            f"<b>⚿ CryptKey</b>"
            f"  <span style='color:{C['text_fade']};font-size:11px;'>"
            f"License Generator</span>")
        logo.setStyleSheet(f"font-size:17px;color:{C['accent']};letter-spacing:0.5px;")
        logo.setTextFormat(Qt.TextFormat.RichText)
        lay.addWidget(logo)
        lay.addStretch()

        import hashlib, base64
        try:
            fp = hashlib.sha256(base64.b64decode(pub_key_b64)).hexdigest()[:12]
            fp_lbl = QLabel(f"Key fingerprint: {fp}…")
            fp_lbl.setStyleSheet(
                f"color:{C['text_fade']};font-size:10px;margin-right:10px;")
            lay.addWidget(fp_lbl)
        except Exception:
            pass

        badge = QLabel("  Ed25519 ✓  ")
        badge.setStyleSheet(
            f"background:{C['gold']};color:#000;border-radius:8px;"
            f"font-size:9px;font-weight:700;letter-spacing:1.5px;padding:3px 8px;")
        lay.addWidget(badge)

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        g = QLinearGradient(0, 0, self.width(), 0)
        g.setColorAt(0, QColor("#0F131E"))
        g.setColorAt(1, QColor(C['bg']))
        p.fillRect(self.rect(), QBrush(g))
        p.setPen(QPen(QColor(C['border']), 1))
        p.drawLine(0, self.height()-1, self.width(), self.height()-1)


# ── Key output ────────────────────────────────────────────────────────────────

class KeyOutputWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        self.key_edit = QTextEdit()
        self.key_edit.setReadOnly(True)
        self.key_edit.setFixedHeight(72)
        self.key_edit.setPlaceholderText("Generated key will appear here…")
        lay.addWidget(self.key_edit)
        btn_row = QHBoxLayout()
        self.copy_btn = QPushButton("⎘  Copy to Clipboard")
        self.copy_btn.setObjectName("cta")
        self.copy_btn.setEnabled(False)
        self.copy_btn.clicked.connect(self._copy)
        self.status_lbl = QLabel("")
        self.status_lbl.setStyleSheet(
            f"color:{C['green']};font-size:11px;background:transparent;")
        btn_row.addWidget(self.copy_btn)
        btn_row.addWidget(self.status_lbl)
        btn_row.addStretch()
        lay.addLayout(btn_row)
        self._key = ""

    def set_key(self, key: str):
        self._key = key
        self.key_edit.setPlainText(key)
        self.copy_btn.setEnabled(bool(key))
        self.status_lbl.setText("")

    def _copy(self):
        QGuiApplication.clipboard().setText(self._key)
        self.status_lbl.setText("✓ Copied!")
        QTimer.singleShot(2000, lambda: self.status_lbl.setText(""))


# ── Validator ─────────────────────────────────────────────────────────────────

class ValidatorWidget(QWidget):
    def __init__(self, pub_key_b64: str, parent=None):
        super().__init__(parent)
        self._pub = pub_key_b64
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        self.input = QLineEdit()
        self.input.setPlaceholderText("Paste any license key to validate…")
        lay.addWidget(self.input)
        row = QHBoxLayout()
        btn = QPushButton("Validate Key")
        btn.setObjectName("gold")
        btn.clicked.connect(self._validate)
        self.input.returnPressed.connect(self._validate)
        row.addWidget(btn); row.addStretch()
        lay.addLayout(row)
        self.result = QLabel("—")
        self.result.setWordWrap(True)
        self.result.setStyleSheet(
            f"color:{C['text_dim']};font-size:12px;padding:6px 0;background:transparent;")
        lay.addWidget(self.result)

    def _validate(self):
        info = validate_license_key(self.input.text().strip(), self._pub)
        if info["valid"]:
            tier = info["tier"]
            exp  = info.get("expiry")
            mid  = info.get("machine", "ANY")
            msg  = (
                f"✓  <b style='color:{C['green']}'>"
                f"{LICENSE_TIERS[tier]['label'].upper()}</b>"
                f"  —  expires <b>{exp.strftime('%Y-%m-%d') if exp else '?'}</b>"
                f"  —  machine: <code>{mid}</code>")
        else:
            msg = f"✗  <span style='color:{C['red']}'>{info['message']}</span>"
        self.result.setTextFormat(Qt.TextFormat.RichText)
        self.result.setText(msg)


# ── Public key dialog ─────────────────────────────────────────────────────────

class PublicKeyDialog(QDialog):
    def __init__(self, pub_key_b64: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Your Public Key – Embed in App")
        self.setMinimumWidth(580)
        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        lay.setContentsMargins(24, 24, 24, 24)

        title = QLabel("📋  Embed this constant in file_encryptor_enhanced.py")
        title.setStyleSheet(
            f"font-size:14px;font-weight:700;color:{C['text']};background:transparent;")
        lay.addWidget(title)

        info = QLabel(
            "Replace <code>LICENSE_PUBLIC_KEY = \"\"</code> with the line below.\n"
            "This key can <b>only verify</b> — it cannot sign or forge licenses.")
        info.setTextFormat(Qt.TextFormat.RichText)
        info.setWordWrap(True)
        info.setStyleSheet(
            f"color:{C['text_dim']};font-size:12px;background:transparent;")
        lay.addWidget(info)

        snippet = f'LICENSE_PUBLIC_KEY = "{pub_key_b64}"'
        box = QTextEdit()
        box.setReadOnly(True)
        box.setPlainText(snippet)
        box.setFixedHeight(80)
        lay.addWidget(box)

        btn_row = QHBoxLayout()
        copy_btn = QPushButton("⎘  Copy Constant")
        copy_btn.setObjectName("cta")
        copied_lbl = QLabel("")
        copied_lbl.setStyleSheet(
            f"color:{C['green']};font-size:11px;background:transparent;")

        def _copy():
            QGuiApplication.clipboard().setText(snippet)
            copied_lbl.setText("✓ Copied!")
            QTimer.singleShot(2000, lambda: copied_lbl.setText(""))

        copy_btn.clicked.connect(_copy)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        btn_row.addWidget(copy_btn)
        btn_row.addWidget(copied_lbl)
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        lay.addLayout(btn_row)


# ── Generator panel ───────────────────────────────────────────────────────────

class GeneratorPanel(QWidget):
    key_generated = pyqtSignal(dict)

    def __init__(self, priv_key_b64: str, pub_key_b64: str, parent=None):
        super().__init__(parent)
        self._priv = priv_key_b64
        self._pub  = pub_key_b64
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 16, 20, 16)
        lay.setSpacing(14)

        # Customer
        cust_grp = QGroupBox("CUSTOMER")
        cl = QVBoxLayout(cust_grp); cl.setSpacing(8)
        row1 = QHBoxLayout(); row1.setSpacing(10)
        self.name_edit  = QLineEdit(); self.name_edit.setPlaceholderText("Customer name")
        self.email_edit = QLineEdit(); self.email_edit.setPlaceholderText("customer@email.com")
        row1.addWidget(QLabel("Name"));  row1.addWidget(self.name_edit, 2)
        row1.addWidget(QLabel("Email")); row1.addWidget(self.email_edit, 2)
        cl.addLayout(row1)
        row2 = QHBoxLayout(); row2.setSpacing(10)
        self.ref_edit = QLineEdit()
        self.ref_edit.setPlaceholderText("Invoice / order reference (optional)")
        row2.addWidget(QLabel("Ref")); row2.addWidget(self.ref_edit)
        cl.addLayout(row2)
        lay.addWidget(cust_grp)

        # Parameters
        lic_grp = QGroupBox("LICENSE PARAMETERS")
        ll = QVBoxLayout(lic_grp); ll.setSpacing(10)
        row3 = QHBoxLayout(); row3.setSpacing(10)
        row3.addWidget(QLabel("Tier"))
        self.tier_combo = QComboBox()
        for k, caps in LICENSE_TIERS.items():
            self.tier_combo.addItem(f"{caps['label']}  ({caps['price']})", k)
        self.tier_combo.setCurrentIndex(1)
        self.tier_combo.currentIndexChanged.connect(self._update_summary)
        row3.addWidget(self.tier_combo)
        row3.addWidget(QLabel("  Duration"))
        self.days_spin = QSpinBox()
        self.days_spin.setRange(1, 9999); self.days_spin.setValue(365)
        self.days_spin.setSuffix("  days")
        self.days_spin.valueChanged.connect(self._update_summary)
        row3.addWidget(self.days_spin)
        for lbl, d in [("30d", 30), ("90d", 90), ("1y", 365), ("2y", 730), ("∞", 9999)]:
            b = QPushButton(lbl); b.setFixedWidth(46)
            b.clicked.connect(lambda _, days=d: self.days_spin.setValue(days))
            row3.addWidget(b)
        row3.addStretch()
        ll.addLayout(row3)

        row4 = QHBoxLayout(); row4.setSpacing(10)
        self.machine_check = QCheckBox("Lock to machine ID")
        self.machine_check.stateChanged.connect(
            lambda s: self.machine_edit.setEnabled(bool(s)))
        self.machine_edit = QLineEdit()
        self.machine_edit.setPlaceholderText("16-char machine ID from customer")
        self.machine_edit.setEnabled(False)
        self.machine_edit.setFixedWidth(210)
        row4.addWidget(self.machine_check)
        row4.addWidget(self.machine_edit)
        row4.addStretch()
        ll.addLayout(row4)
        lay.addWidget(lic_grp)

        # Summary
        self.summary = QLabel()
        self.summary.setStyleSheet(
            f"background:{C['surface2']};border:1px solid {C['border']};"
            f"border-radius:6px;padding:8px 14px;color:{C['text_dim']};font-size:11px;")
        lay.addWidget(self.summary)

        # Buttons
        gen_row = QHBoxLayout()
        self.gen_btn = QPushButton("⚿  Generate License Key")
        self.gen_btn.setObjectName("cta")
        self.gen_btn.setMinimumHeight(38)
        self.gen_btn.clicked.connect(self._generate)
        pub_btn = QPushButton("Show Public Key")
        pub_btn.setObjectName("gold")
        pub_btn.clicked.connect(lambda: PublicKeyDialog(self._pub, self).exec())
        gen_row.addWidget(self.gen_btn)
        gen_row.addWidget(pub_btn)
        gen_row.addStretch()
        lay.addLayout(gen_row)

        # Output
        out_grp = QGroupBox("GENERATED KEY")
        ol = QVBoxLayout(out_grp)
        self.key_out = KeyOutputWidget()
        ol.addWidget(self.key_out)
        lay.addWidget(out_grp)

        # Validator
        val_grp = QGroupBox("VALIDATE ANY KEY")
        vl = QVBoxLayout(val_grp)
        vl.addWidget(ValidatorWidget(self._pub))
        lay.addWidget(val_grp)

        lay.addStretch()
        self._update_summary()

    def _update_summary(self):
        tier_key = self.tier_combo.currentData()
        caps  = LICENSE_TIERS.get(tier_key, {})
        days  = self.days_spin.value()
        expiry = (_utcnow() + timedelta(days=days)).strftime("%Y-%m-%d")
        max_f  = caps.get("max_files", 0)
        parts  = [
            f"<b style='color:{C['accent']}'>{caps.get('label','?').upper()}</b>",
            f"expires <b>{expiry}</b>",
            f"files: <b>{'∞' if max_f == -1 else max_f}</b>",
            f"shred: <b>{'✓' if caps.get('shred') else '✗'}</b>",
            f"batch: <b>{'✓' if caps.get('batch') else '✗'}</b>",
            f"<span style='color:{C['gold']}'>Ed25519 signed ✓</span>",
        ]
        self.summary.setTextFormat(Qt.TextFormat.RichText)
        self.summary.setText("  ·  ".join(parts))

    def _generate(self):
        tier_key = self.tier_combo.currentData()
        days = self.days_spin.value()
        mid  = "ANY"
        if self.machine_check.isChecked():
            mid = self.machine_edit.text().strip()
            if not mid:
                QMessageBox.warning(self, "Missing Machine ID",
                    "Enter the customer's machine ID or uncheck 'Lock to machine ID'.")
                return
        try:
            key = generate_license_key(tier_key, days, self._priv, mid=mid)
        except Exception as e:
            QMessageBox.critical(self, "Signing Failed", str(e))
            return
        self.key_out.set_key(key)
        expiry = (_utcnow() + timedelta(days=days)).strftime("%Y-%m-%d")
        record = {
            "issued_at": _utcnow().strftime("%Y-%m-%d %H:%M"),
            "customer":  self.name_edit.text().strip()  or "—",
            "email":     self.email_edit.text().strip()  or "—",
            "ref":       self.ref_edit.text().strip()    or "—",
            "tier":      tier_key,
            "expiry":    expiry,
            "machine":   mid,
            "key":       key,
        }
        self.key_generated.emit(record)


# ── Issued keys panel ─────────────────────────────────────────────────────────

class IssuedKeysPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 16, 20, 16)
        lay.setSpacing(10)

        hdr = QHBoxLayout()
        title = QLabel("Issued Keys")
        title.setStyleSheet(
            f"font-size:15px;font-weight:700;color:{C['text']};background:transparent;")
        hdr.addWidget(title); hdr.addStretch()
        exp_btn = QPushButton("↓  Export CSV"); exp_btn.clicked.connect(self._export_csv)
        clr_btn = QPushButton("✕  Clear Log");  clr_btn.setObjectName("danger")
        clr_btn.clicked.connect(self._clear_log)
        hdr.addWidget(exp_btn); hdr.addWidget(clr_btn)
        lay.addLayout(hdr)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search by name, email, tier…")
        self.search.textChanged.connect(self._filter)
        lay.addWidget(self.search)

        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(
            ["ISSUED", "CUSTOMER", "EMAIL", "TIER", "EXPIRES", "MACHINE", "KEY"])
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(False)
        self.table.verticalHeader().setVisible(False)
        lay.addWidget(self.table)

        self.count_lbl = QLabel("0 licenses issued")
        self.count_lbl.setStyleSheet(
            f"color:{C['text_dim']};font-size:11px;background:transparent;")
        lay.addWidget(self.count_lbl)

        self._records: list = _load_log()
        self._render()

    def add_record(self, record: dict):
        self._records.append(record)
        _save_log(self._records)
        self._render()

    def _render(self, filter_str: str = ""):
        self.table.setRowCount(0)
        fs = filter_str.lower()
        shown = 0
        tier_colours = {
            "commercial": C['gold'], "personal": C['accent'], "free": C['text_dim'],
        }
        for rec in reversed(self._records):
            if fs and not any(fs in str(v).lower() for v in rec.values()):
                continue
            row = self.table.rowCount()
            self.table.insertRow(row)
            cells = [
                rec.get("issued_at", ""), rec.get("customer", ""),
                rec.get("email", ""),     rec.get("tier", "").upper(),
                rec.get("expiry", ""),    rec.get("machine", "ANY"),
                rec.get("key", ""),
            ]
            for col, val in enumerate(cells):
                item = QTableWidgetItem(val)
                if col == 3:
                    item.setForeground(
                        QColor(tier_colours.get(rec.get("tier", ""), C['text_dim'])))
                self.table.setItem(row, col, item)
            shown += 1
        self.count_lbl.setText(
            f"{shown} license{'s' if shown != 1 else ''} shown  "
            f"({len(self._records)} total)")

    def _filter(self, text: str):
        self._render(text)

    def _export_csv(self):
        if not self._records:
            QMessageBox.information(self, "Nothing to Export", "No records yet.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV",
            str(Path.home() / "cryptkey_licenses.csv"), "CSV files (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=self._records[0].keys())
                writer.writeheader()
                writer.writerows(self._records)
            QMessageBox.information(self, "Exported", f"Saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))

    def _clear_log(self):
        reply = QMessageBox.question(
            self, "Clear All Records",
            "Permanently delete all local license records?\n"
            "Issued keys remain valid — only the log is cleared.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self._records = []
            _save_log([])
            self._render()


# ── Main window ───────────────────────────────────────────────────────────────

class LicenseGeneratorWindow(QMainWindow):
    def __init__(self, priv_key_b64: str, pub_key_b64: str):
        super().__init__()
        self._priv = priv_key_b64
        self._pub  = pub_key_b64
        self.setWindowTitle("CryptKey – License Generator  [Ed25519]")
        self.setMinimumSize(1080, 680)
        self.resize(1200, 760)
        self._build()

    def _build(self):
        root = QWidget()
        self.setCentralWidget(root)
        root_lay = QVBoxLayout(root)
        root_lay.setContentsMargins(0, 0, 0, 0)
        root_lay.setSpacing(0)

        root_lay.addWidget(HeaderBar(self._pub))

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(1)

        left_scroll = QScrollArea()
        left_scroll.setWidgetResizable(True)
        left_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.gen_panel = GeneratorPanel(self._priv, self._pub)
        self.gen_panel.key_generated.connect(self._on_key_generated)
        left_scroll.setWidget(self.gen_panel)
        splitter.addWidget(left_scroll)

        self.log_panel = IssuedKeysPanel()
        splitter.addWidget(self.log_panel)

        splitter.setSizes([520, 680])
        root_lay.addWidget(splitter)

        self.status = QLabel(
            "  🔐 Ed25519 signing active – keys are cryptographically unforgeable")
        self.status.setFixedHeight(24)
        self.status.setStyleSheet(
            f"background:{C['surface']};color:{C['text_dim']};"
            f"font-size:10px;border-top:1px solid {C['border']};padding-left:12px;")
        root_lay.addWidget(self.status)

    def _on_key_generated(self, record: dict):
        self.log_panel.add_record(record)
        tier = record["tier"]
        self.status.setText(
            f"  ✓  {LICENSE_TIERS[tier]['label']} key issued for "
            f"{record['customer']}  –  expires {record['expiry']}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(SS)
    app.setStyle("Fusion")

    is_new = not _KEY_PATH.exists()
    dlg = MasterPasswordDialog(is_new_keypair=is_new)
    if dlg.exec() != QDialog.DialogCode.Accepted:
        sys.exit(0)

    priv, pub = dlg.credentials()

    if is_new:
        QMessageBox.information(
            None, "Keypair Created",
            f"Your Ed25519 signing keypair has been created and saved to:\n\n"
            f"  {_KEY_PATH}\n\n"
            f"Click 'Show Public Key' in the generator, copy the constant,\n"
            f"and paste it into file_encryptor_enhanced.py as LICENSE_PUBLIC_KEY.")

    win = LicenseGeneratorWindow(priv, pub)
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
