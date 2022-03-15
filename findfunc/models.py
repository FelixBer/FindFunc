from PyQt5 import QtCore, QtGui
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QMessageBox

from findfunc.backbone import *
from typing import List


class ResultModel(QtCore.QAbstractTableModel):
    """
    Model that holds the matched functions after a search was performed.
    """
    col_va = 0
    col_size = 1
    col_chunks = 2
    col_label = 3

    class Result:
        """
        Helper class to efficiently hold the information about a matched function
        shown in result table.
        """
        def __init__(self, va, size, chunks, name):
            self.va = va
            self.size = size
            self.chunks = chunks
            self.name = name

    def __init__(self):
        QtCore.QAbstractTableModel.__init__(self)
        self.mydata = []
        self.headerdata = ["VA", "Size", "Chunks", "Name"]

    def columnCount(self, index=QtCore.QModelIndex()):
        return len(self.headerdata)

    def rowCount(self, index=QtCore.QModelIndex()):
        return len(self.mydata)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = ...):
        if role == Qt.DisplayRole:
            if orientation == Qt.Horizontal:
                return self.headerdata[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        col = index.column()
        if role == Qt.DisplayRole:
            d = self.mydata[index.row()]
            if col == self.col_va:
                return hex(d.va)
            if col == self.col_size:
                return d.size
            if col == self.col_chunks:
                return d.chunks
            if col == self.col_label:
                return d.name

    def sort(self, col, order=Qt.AscendingOrder):
        if col == self.col_va:
            self.mydata = sorted(self.mydata, key=lambda x: x.va)
        if col == self.col_size:
            self.mydata = sorted(self.mydata, key=lambda x: x.size)
        if col == self.col_chunks:
            self.mydata = sorted(self.mydata, key=lambda x: x.chunks)
        if col == self.col_label:
            self.mydata = sorted(self.mydata, key=lambda x: x.name)
        if order == Qt.DescendingOrder:
            self.mydata.reverse()
        self.layoutChanged.emit()

    def add_item(self, item: Result):
        self.mydata.append(item)
        self.layoutChanged.emit()

    def set_items(self, items: List[Result]):
        self.mydata = items
        self.layoutChanged.emit()

    def clear(self):
        self.mydata = []
        self.layoutChanged.emit()

    def del_item(self, row: int):
        if row < len(self.mydata):
            self.mydata.remove(self.mydata[row])
            self.layoutChanged.emit()


class RuleModel(QtCore.QAbstractTableModel):
    """
    Model to hold all Rules in a tab/findfunc widget.
    """
    col_enabled = 0
    col_typ = 1
    col_inverted = 2
    col_data = 3

    def __init__(self):
        QtCore.QAbstractTableModel.__init__(self)
        self.mydata = []
        self.headerdata = ["Enabled", "Type", "Invert Match", "Data"]

    def columnCount(self, index=QtCore.QModelIndex()):
        return len(self.headerdata)

    def rowCount(self, index=QtCore.QModelIndex()):
        return len(self.mydata)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = ...):
        if role == Qt.DisplayRole:
            if orientation == Qt.Horizontal:
                return self.headerdata[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        col = index.column()
        if role in (Qt.DisplayRole, Qt.EditRole):
            d = self.mydata[index.row()]
            if col == self.col_enabled:
                return d.enabled
            if col == self.col_inverted:
                return d.inverted
            if col == self.col_typ:
                return d.typ.value
            if col == self.col_data:
                # special handling for editing function size rules
                if role == Qt.EditRole and isinstance(d, RuleFuncSize):
                    return str(d.min) + "," + str(d.max)
                return d.get_data()
            return None
        if role == Qt.ForegroundRole:
            d = self.mydata[index.row()]
            if not d.enabled:
                return QtGui.QBrush(Qt.gray)
            return None
        if role == Qt.BackgroundRole:
            d = self.mydata[index.row()]
            if d.enabled and d.inverted:
                return QtGui.QBrush(QColor(Qt.cyan).lighter())
            return None
        if role == Qt.ToolTipRole:
            if col == self.col_data:
                d = self.mydata[index.row()]
                if isinstance(d, RuleImmediate):
                    return int(d.get_data(), 16)
            return None
        if role == Qt.TextAlignmentRole:
            return Qt.AlignCenter
        if role == Qt.CheckStateRole:
            return None
        return None

    def setData(self, index, value, role=Qt.EditRole):
        if not index.isValid():
            return False
        if role == Qt.EditRole:
            col = index.column()
            if col == self.col_enabled:
                self.mydata[index.row()].enabled = value
                self.layoutChanged.emit()
                return True
            if col == self.col_inverted:
                self.mydata[index.row()].inverted = value
                self.layoutChanged.emit()
                return True
            if col == self.col_data:
                try:
                    self.mydata[index.row()].set_data(value)
                    self.dataChanged.emit(index, index)
                    return True
                except Exception as ex:
                    QMessageBox.warning(None, "Error changing value", str(ex))
                    return False
        return False

    def flags(self, index):
        flags = super().flags(index)
        if index.row() >= len(self.mydata) or index.row() < 0:
            return flags
        d = self.mydata[index.row()]
        if index.column() == self.col_data and d.is_editable():
            flags |= Qt.ItemIsEditable
        return flags

    def sort(self, col, order=Qt.AscendingOrder):
        if col == self.col_enabled:
            self.mydata = sorted(self.mydata, key=lambda x: x.enabled)
        if col == self.col_typ:
            self.mydata = sorted(self.mydata, key=lambda x: str(x.typ))
        if col == self.col_inverted:
            self.mydata = sorted(self.mydata, key=lambda x: x.inverted)
        if col == self.col_data:
            self.mydata = sorted(self.mydata, key=lambda x: x.get_data())
        if order == Qt.DescendingOrder:
            self.mydata.reverse()
        self.layoutChanged.emit()

    def add_item(self, item: Rule):
        self.mydata.append(item)
        self.layoutChanged.emit()

    def del_item(self, row: int):
        if row < len(self.mydata):
            self.mydata.remove(self.mydata[row])
            self.layoutChanged.emit()
