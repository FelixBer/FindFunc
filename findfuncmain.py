import sys

from PyQt5.QtWidgets import QApplication, QMessageBox, QVBoxLayout

from findfunc import findfunc_gui

inida = True
try:
    # from idaapi import PluginForm
    import idc
    import idaapi
    import idautils
    import ida_bytes
    import ida_ua
    import ida_pro
    from idaapi import PluginForm
except:
    inida = False
    print("not in ida")

if inida:
    from findfunc.advanced_copy import copy_all_bytes, copy_bytes_no_imm, copy_only_opcodes, copy_only_disasm

__AUTHOR__ = 'feber'

PLUGIN_NAME = "FindFunc (x86/x64)"
PLUGIN_HOTKEY = 'ctrl+alt+f'
VERSION = '1.0'
WINDOWTITLE = f'{PLUGIN_NAME} {VERSION}'
INFOSTR = f'For usage see: ' '<a href="https://github.com/FelixBer/FindFunc">https://github.com/FelixBer/FindFunc</a>'

# this is executed when running a script rather than plugin
if __name__ == "__main__":
    if inida and not idaapi.get_input_file_path():
        QMessageBox.information(None, "No File", "Please load a file in IDA first, then run script again.")
    else:
        app = QApplication(sys.argv) if not inida else None  # if we run outside IDA for testing
        tabwid = findfunc_gui.TabWid()
        tabwid.setInfoString(INFOSTR)
        tabwid.setWindowTitle(WINDOWTITLE)
        tabwid.show()
        if app:
            sys.exit(app.exec_())


# plugin stuff

def PLUGIN_ENTRY():
    return FindFunc()


class FindFunc(idaapi.plugin_t):
    """
    Main Plugin Class
    """
    flags = 0  # idaapi.PLUGIN_PROC  # | idaapi.PLUGIN_FIX #| idaapi.PLUGIN_HIDE
    comment = "Function Finder and Advanced copying of instruction bytes"
    help = f"Edit->Plugin->FindFunc or {PLUGIN_HOTKEY}. Also: disasm->rightclick->copy all|opcode|noimm"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    ACTION_COPY_BYTES = "feber:copy_bytes"
    ACTION_COPY_OPC = "feber:copy_opc"
    ACTION_COPY_NO_IMM = "feber:copy_no_imm"
    ACTION_COPY_DISASM = "feber:copy_disasm"

    def __init__(self):
        super().__init__()
        self.hooks = ACUiHook()
        self.maintabwidgtet = None

    def init(self):
        # see advanced_copy for details
        action_desc = idaapi.action_desc_t(
            self.ACTION_COPY_BYTES,
            "copy all bytes",
            ACActionHandler(copy_all_bytes),
            "ctrl+alt+b",  # hotkey
            "copy all selected bytes as hex",
            31
        )
        assert idaapi.register_action(action_desc), "Action registration failed"
        action_desc = idaapi.action_desc_t(
            self.ACTION_COPY_OPC,
            "copy opcodes only",
            ACActionHandler(copy_only_opcodes),
            "ctrl+alt+o",  # hotkey
            "copy selected opcodes as hex, wildcard out non-opcode bytes",
            31
        )
        assert idaapi.register_action(action_desc), "Action registration failed"
        action_desc = idaapi.action_desc_t(
            self.ACTION_COPY_NO_IMM,
            "copy bytes no immediates",
            ACActionHandler(copy_bytes_no_imm),
            "ctrl+alt+i",  # hotkey
            "copy instruction bytes, wildcard out all immediates",
            31
        )
        assert idaapi.register_action(action_desc), "Action registration failed"
        action_desc = idaapi.action_desc_t(
            self.ACTION_COPY_DISASM,
            "copy disasm",
            ACActionHandler(copy_only_disasm),
            "ctrl+alt+d",  # hotkey
            "copy disasm lines only",
            31
        )
        assert idaapi.register_action(action_desc), "Action registration failed"


        self.hooks.hook()

        idaapi.msg("%s %s by %s loaded\n" % (self.wanted_name, VERSION, __AUTHOR__))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        Edit->Plugins->... or hotkey
        """
        open_form()

    def term(self):
        self.hooks.unhook()
        idaapi.unregister_action(self.ACTION_COPY_BYTES)
        idaapi.unregister_action(self.ACTION_COPY_OPC)
        idaapi.unregister_action(self.ACTION_COPY_NO_IMM)
        global cursession
        global lastsavedsession
        if cursession != lastsavedsession:
            reply = QMessageBox.question(None, "Save Session", "Your FindFunc session has not been saved. Save now?",
                                             QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                findfunc_gui.TabWid.save_as_session(cursession)
                lastsavedsession = cursession


# plugin helper stuff

cursession = ""
lastsavedsession = ""


def open_form():
    global ffform
    try:
        ffform
    except Exception:
        print("ff constructed")
        ffform = FunctionsListForm_t()
    ffform.Show()


class FunctionsListForm_t(PluginForm):
    """
    wrapper required for docking
    """
    def OnCreate(self, form):
        print("create")
        self.parent = self.FormToPyQtWidget(form)
        self.mtw = findfunc_gui.TabWid()
        self.mtw.setInfoString(INFOSTR)
        self.mtw.setWindowTitle(WINDOWTITLE)
        global cursession
        if cursession:
            self.mtw.clearAll()
            self.mtw.load_session_from_text(cursession)
            cursession = ""
        layout = QVBoxLayout()
        layout.addWidget(self.mtw)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        self.parent.setLayout(layout)

    def OnClose(self, form):
        print("closed")
        global cursession
        global lastsavedsession
        cursession = self.mtw.session_to_text()
        lastsavedsession = self.mtw.lastsessionsaved

    def Show(self):
        return PluginForm.Show(self, WINDOWTITLE, options=PluginForm.WOPN_PERSIST)


class ACActionHandler(idaapi.action_handler_t):
    """
    Action handling helper
    """
    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        self.action_function()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class ACUiHook(idaapi.UI_Hooks):
    """
    Show context menus in disasm widgets
    """
    def finish_populating_widget_popup(self, widget, popup):
        """
        Right click menu is about to be shown
        """
        form_type = idaapi.get_widget_type(widget)

        if form_type == idaapi.BWN_DISASMS:
            idaapi.attach_action_to_popup(
                widget,
                popup,
                FindFunc.ACTION_COPY_BYTES,
                # "copy all bytes",
                # idaapi.SETMENU_APP
            )
            idaapi.attach_action_to_popup(
                widget,
                popup,
                FindFunc.ACTION_COPY_NO_IMM,
            )
            idaapi.attach_action_to_popup(
                widget,
                popup,
                FindFunc.ACTION_COPY_OPC,
            )
            idaapi.attach_action_to_popup(
                widget,
                popup,
                FindFunc.ACTION_COPY_DISASM,
            )
        return 0
