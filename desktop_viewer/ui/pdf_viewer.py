"""
PDF viewer widget: renders pages from an in-memory PDF document,
draws a watermark overlay, and handles page/zoom controls.

This widget does NOT do networking or crypto. It takes decrypted PDF
bytes and the watermark text, renders pages, and provides navigation.
"""
from __future__ import annotations

from typing import Optional

import pymupdf
from PySide6.QtCore import Qt
from PySide6.QtGui import QImage, QPixmap, QPainter, QColor, QFont, QPen
from PySide6.QtWidgets import (
    QLabel, QVBoxLayout, QHBoxLayout, QWidget, QPushButton, QScrollArea, QFrame
)


class PDFViewerWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._doc: Optional[pymupdf.Document] = None
        self._pdf_bytes = b""
        self._current_page = 0
        self._zoom = 1.0
        self._watermark = ""

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # --- Toolbar ---
        toolbar = QHBoxLayout()
        
        self._btn_prev = QPushButton("◀ Prev")
        self._btn_prev.clicked.connect(self._prev_page)
        self._btn_prev.setEnabled(False)
        toolbar.addWidget(self._btn_prev)

        self._page_label = QLabel("Page - / -")
        toolbar.addWidget(self._page_label)

        self._btn_next = QPushButton("Next ▶")
        self._btn_next.clicked.connect(self._next_page)
        self._btn_next.setEnabled(False)
        toolbar.addWidget(self._btn_next)

        toolbar.addStretch(1)

        self._btn_zoom_out = QPushButton("Zoom -")
        self._btn_zoom_out.clicked.connect(self._zoom_out)
        toolbar.addWidget(self._btn_zoom_out)

        self._btn_zoom_in = QPushButton("Zoom +")
        self._btn_zoom_in.clicked.connect(self._zoom_in)
        toolbar.addWidget(self._btn_zoom_in)

        layout.addLayout(toolbar)

        # --- Render area ---
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setAlignment(Qt.AlignCenter)
        
        self._image_label = QLabel()
        self._image_label.setAlignment(Qt.AlignCenter)
        self._scroll.setWidget(self._image_label)
        
        layout.addWidget(self._scroll)

    def load(self, pdf_bytes: bytes, watermark: str):
        """Load PDF bytes into memory and render page 0."""
        self.close_document()  # wipe any existing doc first
        
        self._pdf_bytes = bytearray(pdf_bytes)  # mutable so we can zero it
        self._doc = pymupdf.open(stream=self._pdf_bytes, filetype="pdf")
        self._watermark = watermark
        self._current_page = 0
        self._zoom = 1.0
        
        self._btn_prev.setEnabled(True)
        self._btn_next.setEnabled(True)
        self._render_page()

    def close_document(self):
        """Close the document and wipe the plaintext from memory."""
        if self._doc:
            self._doc.close()
            self._doc = None
        
        # Best-effort zero of the bytearray
        if isinstance(self._pdf_bytes, bytearray):
            for i in range(len(self._pdf_bytes)):
                self._pdf_bytes[i] = 0
        self._pdf_bytes = b""
        self._watermark = ""
        
        self._image_label.clear()
        self._image_label.setText("No document loaded.")
        self._page_label.setText("Page - / -")
        self._btn_prev.setEnabled(False)
        self._btn_next.setEnabled(False)

    # --- Rendering ---

    def _render_page(self):
        if not self._doc or not self._doc.page_count:
            return
            
        page = self._doc[self._current_page]
        
        # Render at the current zoom factor (72 dpi base)
        mat = pymupdf.Matrix(self._zoom, self._zoom)
        pix = page.get_pixmap(matrix=mat, alpha=False)
        
        # Convert pymupdf pixmap to QImage
        fmt = QImage.Format_RGB888 if pix.n == 3 else QImage.Format_RGBA8888
        img = QImage(pix.samples, pix.width, pix.height, pix.stride, fmt)
        
        # Draw watermark onto a copy
        pixmap = QPixmap.fromImage(img)
        if self._watermark:
            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.Antialiasing)
            
            # Configure watermark style: red, semi-transparent, large
            painter.setPen(QPen(QColor(255, 0, 0, 60)))
            font = QFont("Arial", 16, QFont.Bold)
            painter.setFont(font)
            
            # Draw a repeated grid of the watermark text
            text = self._watermark
            step_x = 250
            step_y = 200
            painter.translate(pixmap.width() / 2, pixmap.height() / 2)
            painter.rotate(-30)
            painter.translate(-pixmap.width(), -pixmap.height())
            
            for x in range(0, pixmap.width() * 2, step_x):
                for y in range(0, pixmap.height() * 2, step_y):
                    painter.drawText(x, y, text)
            
            painter.end()
        
        self._image_label.setPixmap(pixmap)
        self._page_label.setText(f"Page {self._current_page + 1} / {self._doc.page_count}")

    # --- Controls ---

    def _prev_page(self):
        if self._doc and self._current_page > 0:
            self._current_page -= 1
            self._render_page()

    def _next_page(self):
        if self._doc and self._current_page < self._doc.page_count - 1:
            self._current_page += 1
            self._render_page()

    def _zoom_in(self):
        if self._zoom < 3.0:
            self._zoom += 0.2
            self._render_page()

    def _zoom_out(self):
        if self._zoom > 0.4:
            self._zoom -= 0.2
            self._render_page()
