import datetime
import pstats
import time
import pickle
import cProfile
import io

from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QWidget, QMessageBox, QLineEdit, QApplication, QTabBar, QMenu, QFileDialog
from PyQt5.QtCore import Qt, QEvent
from PyQt5.QtGui import QCursor, QKeySequence

from findfunc.findfuncdialog import Ui_FindFunc
from findfunc.fftabs import Ui_fftabs
from findfunc.backbone import *
from findfunc.models import RuleModel, ResultModel
import findfunc.matcher_ida

### config
# use pickle format for saving rules rater than text
use_pickle_ff = False

inida = True
try:
    import idaapi
except:
    inida = False


class FindFuncTab(QWidget):
    """
    FindFunc widget, which represents one Tab.
    Features the rule table, result table and the buttons.
    """
    def __init__(self):
        super().__init__()
        self.ui = Ui_FindFunc()
        self.ui.setupUi(self)
        # self.ui.splitter.setSizes([])
        # self.ui.splitter.setStretchFactor(0, 1)
        # self.ui.splitter.setStretchFactor(1, 1)
        # self.ui.tableresults.setBaseSize(150,150)
        self.matcher = findfunc.matcher_ida.MatcherIda()
        self.model = RuleModel()
        self.resultmodel = ResultModel()
        # self.resultmodel.mydata = [ResultModel.Result(0x00000001810FD8CC, 3, "sub_3948394"), ResultModel.Result(0x00000001810FD8CC, 2, ""), ResultModel.Result(1, 2, "")]
        self.ui.tableview.setModel(self.model)
        self.ui.tableresults.setModel(self.resultmodel)
        self.ui.tableview.setSelectionBehavior(QtWidgets.QTableView.SelectRows)
        self.ui.tableresults.setSelectionBehavior(QtWidgets.QTableView.SelectRows)
        self.ui.tableresults.resizeColumnsToContents()
        self.ui.tableresults.horizontalHeader().setStretchLastSection(True)
        self.ui.tableresults.setAlternatingRowColors(True)
        # signals
        self.ui.tableview.doubleClicked.connect(self.tableRulesDoubleClick)
        self.ui.tableresults.doubleClicked.connect(self.resultDoubleClick)
        self.ui.tableresults.pressed.connect(self.tableMidClickCopy)
        self.ui.btnaddimm.clicked.connect(self.addimmrule)
        self.ui.btnaddstr.clicked.connect(self.addstrrule)
        self.ui.btnaddname.clicked.connect(self.addnamerule)
        self.ui.btnaddpattern.clicked.connect(self.addbytepatternrule)
        self.ui.btnaddcode.clicked.connect(self.addcoderule)
        self.ui.btnfuncsize.clicked.connect(self.addfsizerule)
        self.ui.btnsearch.clicked.connect(self.dosearchclicked)
        self.ui.btnrefine.clicked.connect(self.dorefineclicked)
        # enable sorting
        self.ui.tableview.setSortingEnabled(True)
        self.ui.tableresults.setSortingEnabled(True)
        # menu init
        self.ui.tableview.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.tableview.customContextMenuRequested.connect(self.reqrulemenu)
        self.ui.tableresults.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.tableresults.customContextMenuRequested.connect(self.reqresultmenu)
        # main menu
        self.menu = QMenu('mainmenu', self.ui.tableview)
        self.menu.addAction("add imm", self.addimmrule)
        self.menu.addAction("add function size", self.addfsizerule)
        self.menu.addAction("add name ref", self.addnamerule)
        self.menu.addAction("add string ref", self.addstrrule)
        self.menu.addAction("add byte pattern", self.addbytepatternrule)
        self.menu.addAction("add code pattern", self.addcoderule)
        self.menu.addSeparator()
        act = self.menu.addAction("delete selection", self.delselrules, "del")
        self.ui.tableview.addAction(act)
        act = self.menu.addAction("copy", self.copyselrules, "ctrl+c")
        self.ui.tableview.addAction(act)
        act = self.menu.addAction("paste", self.pasteselrules, "ctrl+v")
        self.ui.tableview.addAction(act)
        self.menu.addSeparator()
        act = self.menu.addAction("save selected rules to file", self.saveselrules, "ctrl+s")
        self.ui.tableview.addAction(act)
        act = self.menu.addAction("add rules from file", self.loadselrules, "ctrl+l")
        self.ui.tableview.addAction(act)
        # result menu
        self.resmenu = QMenu('resmenu', self.ui.tableresults)
        act = self.resmenu.addAction("copy addresses", self.copyresults, "ctrl+c")
        self.ui.tableresults.addAction(act)
        self.resmenu.addAction("clear", self.clearresults)
        # menu end
        # add shortcut for search and refine
        act = QtWidgets.QAction("find", self)
        act.setShortcut("ctrl+f")
        act.triggered.connect(self.dosearchclicked)
        self.ui.tableview.addAction(act)
        act = QtWidgets.QAction("refine", self)
        act.setShortcut("ctrl+r")
        act.triggered.connect(self.dorefineclicked)
        self.ui.tableview.addAction(act)
        # event filters, see self.eventFilter()
        self.ui.tableview.installEventFilter(self)
        self.ui.tableresults.installEventFilter(self)
        self.show()

    def eventFilter(self, o, e):
        """
        IDA is doing funky stuff with event interception themselves,
        so we have to help out a little to make our shortcuts work.
        """
        if e.type() == QEvent.ShortcutOverride:
            if o is self.ui.tableview:
                # print(e.modifiers(), e.key(), e.text(), str(e.type()), e.matches(QKeySequence.Copy))
                e.accept()
                for a in self.ui.tableview.actions():
                    if a.shortcut() == QKeySequence(e.key() | int(e.modifiers())):
                        a.trigger()
                return True
            if o is self.ui.tableresults:
                e.accept()
                for a in self.ui.tableresults.actions():
                    if a.shortcut() == QKeySequence(e.key() | int(e.modifiers())):
                        a.trigger()
                return True
        if e.type() == QEvent.KeyPress:
            if o is self.ui.tableview:
                for a in self.ui.tableview.actions():
                    if a.shortcut() == QKeySequence(e.key() | int(e.modifiers())):
                        e.accept()
                        return True
            if o is self.ui.tableresults:
                e.accept()
                for a in self.ui.tableresults.actions():
                    if a.shortcut() == QKeySequence(e.key() | int(e.modifiers())):
                        e.accept()
                        return True
        return False

    def reqrulemenu(self):
        """
        show rule popup menu
        """
        self.menu.popup(QCursor.pos())

    def reqresultmenu(self):
        """
        show result popup menu
        """
        self.resmenu.popup(QCursor.pos())

    def clearresults(self):
        """
        clear result table
        """
        self.resultmodel.clear()

    def copyresults(self):
        """
        copy result VA as hex to clipboard
        """
        if self.ui.tableresults.selectionModel().hasSelection():
            rows = [index.row() for index in self.ui.tableresults.selectionModel().selectedRows()]
            data = [hex(self.resultmodel.mydata[x].va) for x in rows]
            string = "\n".join(data)
            if string:
                QApplication.instance().clipboard().setText(string)

    def addimmrule(self):
        data, succ = QtWidgets.QInputDialog.getText(self, 'Get Immediate',
                                                    'Function must reference immediate (in hex):', QLineEdit.Normal,
                                                    '0x100')
        if not succ:
            return False
        return self.__adddata(RuleImmediate(0), data)

    def addfsizerule(self):
        data, succ = QtWidgets.QInputDialog.getText(self, 'Get Function Size',
                                                    'Function size constraint in format "min,max" e.g. "10,20":',
                                                    QLineEdit.Normal, '10,0x20')
        if not succ:
            return False
        return self.__adddata(RuleFuncSize(), data)

    def addstrrule(self):
        data, succ = QtWidgets.QInputDialog.getText(self, 'Get String',
                                                    'Function must reference string (wildcard supported):',
                                                    QLineEdit.Normal, 'SomeClass::*')
        if not succ:
            return False
        return self.__adddata(RuleStrRef(""), data)

    def addnamerule(self):
        data, succ = QtWidgets.QInputDialog.getText(self, 'Get Name',
                                                    'Function must reference Name/Label (wildcard supported):',
                                                    QLineEdit.Normal, '_SomeNameLabel_*')
        if not succ:
            return False
        return self.__adddata(RuleNameRef(""), data)

    def addbytepatternrule(self):
        data, succ = QtWidgets.QInputDialog.getMultiLineText(self, 'Get Byte Pattern',
                                                             'Function must contain Byte Pattern (supports 11 ?? 22):',
                                                             '11 ?? 22')
        if not succ:
            return False
        return self.__adddata(RuleBytePattern(""), data)

    def addcoderule(self):
        example = "mov eax,imm\nmov r32, 0x100\npass\nmov r, r32\nmov* r64, any\nany eax,eax"
        data, succ = QtWidgets.QInputDialog.getMultiLineText(self, 'Get Code Pattern',
                                                        'Function must contain Code Pattern (See help for details):',
                                                         example)
        if not succ:
            return False
        return self.__adddata(RuleCode(""), data.split('\n'))

    def __adddata(self, rule: Rule, data):
        """
        helper
        """
        try:
            rule.set_data(data)
            self.model.add_item(rule)
        except Exception as ex:
            QMessageBox.warning(None, "Error setting value", str(ex))
            return False
        return True

    def resultDoubleClick(self, index):
        """
        result row doublelicked -> goto va
        """
        if not index.isValid():
            return None
        col = index.column()
        row = index.row()
        mydata = index.model().mydata
        if row >= len(mydata):
            return
        # jump to function start if function-name column clicked, else to last match
        va = mydata[row].va if ResultModel.col_label == col else mydata[row].lastmatch
        if not va:
            va = mydata[row].va
        findfunc.matcher_ida.gui_jump_to_va(va)

    def tableMidClickCopy(self, index):
        """
        table wheel-clicked: copy cell to clipboard
        """
        try:
            if QApplication.mouseButtons() & Qt.MidButton:
                data = index.model().data(index)
                QApplication.instance().clipboard().setText(str(data))
        except Exception:
            pass
        return None

    def tableRulesDoubleClick(self, index):
        """
        Rule table double-clicked: enabled/disabled, invert match or edit data
        """
        if not index.isValid():
            return None
        try:
            col = index.column()
            row = index.row()
            mydata = index.model().mydata
            if col == RuleModel.col_enabled:
                index.model().setData(index, not mydata[row].enabled)
            if col == RuleModel.col_inverted:
                index.model().setData(index, not mydata[row].inverted)
            if col == RuleModel.col_data and isinstance(mydata[row], RuleCode):
                disp = '\n'.join(mydata[row].instr_string)
                data, succ = QtWidgets.QInputDialog.getMultiLineText(self, 'Get Code Pattern',
                                                        'Function must contain Code Pattern (See help for details):',
                                                         disp)
                if succ:
                    mydata[row].set_data(data.split('\n'))
        except Exception as ex:
            QMessageBox.warning(None, "Error setting value", str(ex))
            return self.tableRulesDoubleClick(index)
        return None

    def delselrules(self):
        if self.ui.tableview.selectionModel().hasSelection():
            rows = [index.row() for index in self.ui.tableview.selectionModel().selectedRows()]
            rows.sort(reverse=True)
            for row in rows:
                self.model.del_item(row)

    def copyselrules(self):
        if self.ui.tableview.selectionModel().hasSelection():
            rows = [index.row() for index in self.ui.tableview.selectionModel().selectedRows()]
            data = [self.model.mydata[x] for x in rows]
            string = to_clipboard_string(data)
            if string:
                QApplication.instance().clipboard().setText(string)

    def pasteselrules(self):
        string = QApplication.instance().clipboard().text()
        if string:
            try:
                data = from_clipboard_string(string)
                if data:
                    self.model.mydata += data
                    self.model.layoutChanged.emit()
            except Exception as ex:
                QMessageBox.warning(self, "Error pasting rules", str(ex))

    def loadselrules(self):
        path, x = QFileDialog.getOpenFileName(self, 'Open Rule File', "", "Rules (*.rule) ;; Any (*.*)")
        if not path:
            return
        try:
            if use_pickle_ff:
                with open(path, 'rb') as handle:
                    loaded = pickle.load(handle)
                    self.model.mydata += loaded
            else:
                with open(path, 'r') as handle:
                    rules = from_clipboard_string(handle.read())
                    self.model.mydata += rules
            self.model.layoutChanged.emit()
        except Exception as ex:
            QMessageBox.warning(self, "Error reading file", str(ex))

    def saveselrules(self):
        if not self.ui.tableview.selectionModel().hasSelection():
            QMessageBox.warning(self, "Nothing", "No rules selected")
            return
        path, x = QFileDialog.getSaveFileName(self, 'Save Rule to File', "rule.rule", "Rules (*.rule) ;; Any (*.*)")
        if not path:
            return
        try:
            rows = [index.row() for index in self.ui.tableview.selectionModel().selectedRows()]
            tosave = [self.model.mydata[x] for x in rows]
            if use_pickle_ff:
                with open(path, 'wb') as handle:
                    pickle.dump(tosave, handle, protocol=3)
            else:
                with open(path, 'w') as handle:
                    handle.write(to_clipboard_string(tosave))
            QMessageBox.information(self, "Success", "Saved successfully to " + path)
        except Exception as ex:
            QMessageBox.warning(self, "Error saving file", str(ex))

    def _dosearch(self, limitto: List[int]):
        """
        perform search or refine results given in limitto
        """
        if not inida:
            msg = "This is an IDA PRO plugin, copy findfuncmain.py and findfunc folder to IDA plugin dir!"
            QMessageBox.information(self, "Error", msg)
            return
        self.matcher.info.debug = self.ui.chkdebug.isChecked()
        self.matcher.info.profile = self.ui.chkprofile.isChecked()
        profiler = cProfile.Profile()
        if self.matcher.info.profile:
            profiler.enable()
        starttime = time.perf_counter()
        idaapi.show_wait_box("FindFunc: Finding Functions... ")  # todo: maybe use ida_kernwin.replace_wait_box
        results = self.matcher.do_match(self.model.mydata, limitto)
        idaapi.hide_wait_box()
        self.resultmodel.set_items([ResultModel.Result(fn.va, fn.size, len(fn.chunks) - 1, fn.name, fn.lastmatch) for fn in results])
        self.ui.tableresults.resizeColumnsToContents()
        timetaken = time.perf_counter() - starttime
        print("Results found: ", len(results))
        print('Execution time in seconds: ' + str(round(timetaken, 2)))
        if self.matcher.info.profile:
            profiler.disable()
            stream = io.StringIO()
            ps = pstats.Stats(profiler, stream=stream).sort_stats('tottime')
            ps.print_stats()
            print(stream.getvalue())
        if self.matcher.wascancelled:
            self.matcher.wascancelled = False
            QMessageBox.warning(None, "Canceled", "Search was canceled.")

    def dosearchclicked(self):
        """
        perform new search
        """
        self._dosearch([])

    def dorefineclicked(self):
        """
        refine existing results, or new search if no current results
        """
        limitto = [r.va for r in self.resultmodel.mydata]
        self._dosearch(limitto)


class TabWid(QWidget):
    """
    Widget that represents the Tabwidget.
    At the end of the tab bar there is a disabled tab that creates a new tab when clicked.
    """
    def __init__(self, asplugin=False, parent=None):
        super().__init__(parent)
        self.running_as_plugin = asplugin
        self.count = 0  # Tab Numbering
        self.ui = Ui_fftabs()
        self.ui.setupUi(self)
        self.ui.tabWidget.tabBar().tabBarClicked.connect(self.tabClicked)
        self.ui.tabWidget.tabBar().tabBarDoubleClicked.connect(self.tabDoubleClicked)
        self.ui.tabWidget.tabBar().tabCloseRequested.connect(self.closeTabReq)
        self.ui.tabWidget.tabBar().tabMoved.connect(self.tabmoved)
        self.ui.btnloadsess.clicked.connect(self.loadsessionclicked)
        self.ui.btnloadsess.setToolTip("load tabs from file and append to existing")
        self.ui.btnloadsess.setShortcut("ctrl+shift+l")
        self.ui.btnsavesess.clicked.connect(self.savesessionclicked)
        self.ui.btnsavesess.setToolTip("save all tabs to file")
        self.ui.btnsavesess.setShortcut("ctrl+shift+s")
        self.clearAll()
        self.addNewTab()
        for r in [RuleImmediate(9), RuleCode("xor eax,r32"), RuleNameRef("mem*")]:
            self.ui.tabWidget.widget(0).model.add_item(r)
        self.lastsessionsaved = self.session_to_text()  # last saved session data, used for checking on close
        print("init with config:" + str(self.ui.tabWidget.widget(0).matcher.info))

    def closeEvent(self, event):
        # when running as script, we need to handle it here
        # when running as plugin, this is handled in findfuncmain.py
        if not self.running_as_plugin:
            cursession = self.session_to_text()
            if cursession and cursession != self.lastsessionsaved:
                reply = QMessageBox.question(None, "Save Session",
                                             "Your FindFunc session has not been saved. Save now?",
                                             QMessageBox.Yes | QMessageBox.No)
                if reply == QMessageBox.Yes:
                    self.savesessionclicked()

    def loadsessionclicked(self):
        path, x = QFileDialog.getOpenFileName(self, 'Open Session File', "", "Session (*.ffsess) ;; Any (*.*)")
        if not path:
            return
        try:
            with open(path, 'r') as handle:
                session = handle.read()
                self.load_session_from_text(session)
                self.lastsessionsaved = session
        except Exception as ex:
            QMessageBox.warning(self, "Error loading session", str(ex))

    def savesessionclicked(self):
        session = self.session_to_text()
        if self.save_as_session(session):
            self.lastsessionsaved = session

    @staticmethod
    def save_as_session(session) -> bool:
        path, x = QFileDialog.getSaveFileName(None, 'Save Session to File',
                                              f"{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.ffsess",
                                              "Session (*.ffsess) ;; Any (*.*)")
        if not path:
            return False
        try:
            with open(path, 'w') as handle:
                handle.write(session)
            return True
        except Exception as ex:
            QMessageBox.warning(None, "Error saving session", str(ex))
            return False

    def session_to_text(self) -> str:
        """
        serialize all current tabs (including their names) to string
        """
        r = ""
        for i in range(self.ui.tabWidget.tabBar().count()):
            if not self.ui.tabWidget.tabBar().isTabEnabled(i):
                continue
            title = self.ui.tabWidget.tabBar().tabText(i)
            r += "Tab " + title + "\n"
            wid = self.ui.tabWidget.widget(i)
            r += to_clipboard_string(wid.model.mydata)
        return r

    def load_session_from_text(self, session: str):
        """
        restore tabs (including names) from string
        loaded tabs are appended to existing ones
        """
        tab = None
        for line in session.split('\n'):
            if line.startswith("Tab "):
                tab = self.ui.tabWidget.addTab(FindFuncTab(), line[len("Tab "):])
                continue
            rule = from_clipboard_string(line)
            if tab:
                wid = self.ui.tabWidget.widget(tab)
                wid.model.mydata += rule
                wid.model.layoutChanged.emit()
        self.resetNewTabButton()

    def setInfoString(self, info: str):
        self.ui.linklabel.setText(info)

    def addNewTab(self):
        self.ui.tabWidget.addTab(FindFuncTab(), f"Tab {self.genId()}")
        self.resetNewTabButton()

    def tabmoved(self):
        self.resetNewTabButton()

    def tabClicked(self, index):
        if index == -1 or self.ui.tabWidget.tabBar().count() <= 1:
            self.addNewTab()

    def tabDoubleClicked(self, index):
        title = self.ui.tabWidget.tabBar().tabText(index)
        data, succ = QtWidgets.QInputDialog.getText(self, 'Rename Tab', 'New Tab Name:', QLineEdit.Normal, title)
        if succ:
            self.ui.tabWidget.tabBar().setTabText(index, data)

    def closeTabReq(self, index):
        self.ui.tabWidget.removeTab(index)
        self.resetNewTabButton()

    def genId(self):
        self.count = self.count + 1
        return self.count

    def resetNewTabButton(self):
        """
        We want a disabled tab at the end of the tab-bar that creates a new tab when clicked.
        """
        for t in range(self.ui.tabWidget.count()):
            if not self.ui.tabWidget.isTabEnabled(t):
                self.ui.tabWidget.removeTab(t)
                break
        newtab = self.ui.tabWidget.addTab(FindFuncTab(), "new tab")
        self.ui.tabWidget.setTabEnabled(newtab, False)
        self.ui.tabWidget.tabBar().setTabButton(newtab, QTabBar.RightSide, None)

    def clearAll(self):
        for t in range(self.ui.tabWidget.count()):
            self.ui.tabWidget.removeTab(t)
