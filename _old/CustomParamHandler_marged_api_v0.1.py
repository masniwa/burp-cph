from collections import namedtuple

from SimpleHTTPServer import SimpleHTTPRequestHandler
from json             import loads
from random           import randint
from re               import search as re_search
from urllib           import unquote

from logging import (
    DEBUG       ,
    ERROR       ,
    INFO        ,
    WARNING     ,
    getLevelName,
)
from SocketServer import ThreadingMixIn, TCPServer
from collections  import OrderedDict as odict, namedtuple
from difflib      import unified_diff
from hashlib      import sha256
from itertools    import product
from json         import dump, dumps, load, loads
from re           import escape as re_escape
from socket       import error as socket_error
from thread       import start_new_thread
from threading    import Thread
from webbrowser   import open_new_tab as browser_open
from burp import ITab
from java.awt import (
    CardLayout        ,
    Color             ,
    FlowLayout        ,
    Font              ,
    GridBagConstraints,
    GridBagLayout     ,
    Insets            ,
)
from java.awt.event import (
    ActionListener,
    KeyListener   ,
    MouseAdapter  ,
)
from javax.swing import (
    AbstractAction    ,
    BorderFactory     ,
    JButton           ,
    JCheckBox         ,
    JComboBox         ,
    JFileChooser      ,
    JFrame            ,
    JLabel            ,
    JOptionPane       ,
    JPanel            ,
    JScrollPane       ,
    JSeparator        ,
    JSpinner          ,
    JSplitPane        ,
    JTabbedPane       ,
    JTable            ,
    JTextArea         ,
    JTextField        ,
    KeyStroke         ,
    SpinnerNumberModel,
)
from javax.swing.event       import ChangeListener, ListSelectionListener
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing.table       import AbstractTableModel
from javax.swing.undo        import UndoManager

from datetime import datetime as dt
from sys      import stdout
from urllib   import quote
from logging import (
    Formatter    ,
    INFO         ,
    StreamHandler,
    getLogger    ,
)
from re import (
    compile  as re_compile ,
    error    as re_error   ,
    findall  as re_findall ,
    finditer as re_finditer,
    match    as re_match   ,
    search   as re_search  ,
    split    as re_split   ,
    sub      as re_sub     ,
)
from burp        import IBurpExtender
from burp        import IContextMenuFactory
from burp        import IExtensionStateListener
from burp        import IHttpListener
from burp        import ISessionHandlingAction
from javax.swing import JMenuItem

class CPH_Help:
    quickstart = """<html>
    <strong>The quicksave and quickload functionality (see buttons above) persist through<br>
    reloading not only the extension, but Burp Suite entirely. All values of each existing<br>
    configuration tab will be saved, along with the order of all tabs.<br>
    <br>
    Use the Export/Import Config buttons to save/load your current configuration to/from a JSON file.<br></strong>
    <br>
    <h2>Adding configuration tabs</h2>
    &nbsp;&nbsp;- Click '+' to add an empty tab; or<br>
    &nbsp;&nbsp;- Select one or many requests from anywhere in Burp, right-click, and choose 'Send to CPH'.<br>
    &nbsp;&nbsp;&nbsp;&nbsp;This will create as many tabs as the number of selected requests, and populate each tab<br>
    &nbsp;&nbsp;&nbsp;&nbsp;with each selected request to be issued for parameter extraction from its response.<br>
    <br>
    <h2>Enabling/Disabling configuration tabs</h2>
    &nbsp;&nbsp;&nbsp;&nbsp;Simply click the checkbox next to the tab's name.<br>
    &nbsp;&nbsp;&nbsp;&nbsp;New tabs are enabled by default but require a valid configuration in order to have any effect.<br>
    <br>
    <h2>Tab order</h2>
    &nbsp;&nbsp;&nbsp;&nbsp;Leftmost tabs will be processed first; therefore, tab order may be important,<br>
    &nbsp;&nbsp;&nbsp;&nbsp;especially when extracting values from cached responses.<br>
    &nbsp;&nbsp;&nbsp;&nbsp;Please visit the Wiki to learn more about utilizing cached responses.<br>
    </html>"""

    HelpPopup = namedtuple('HelpPopup', 'title, message, url')

    indices = HelpPopup(
        'Targeting a subset of matches',
        """<html>
        To target a specific subset of matches,<br>
        enter comma-separated indices and/or slices, such as:<br>
        0,3,5,7 - targets the 1st, 4th, 6th and 8th matches<br>
        0:7&nbsp;&nbsp;&nbsp;&nbsp; - targets the first 7 matches but not the 8th match<br>
        0:7,9&nbsp;&nbsp; - targets the first 7 matches and the 10th match<br>
        -1,-2&nbsp;&nbsp; - targets the last and penultimate matches<br>
        0:-1&nbsp;&nbsp;&nbsp; - targets all but the last match
        </html>""",
        'https://github.com/elespike/burp-cph/wiki/04.-Targeting-matches'
    )

    named_groups = HelpPopup(
        'Inserting a dynamic value using named groups',
        """<html>
        In the expression field shown in step 4,<br>
        define named groups for values you wish to extract<br>
        from the appropriate response.<br>
        <br>
        For example, (?P&lt;mygroup&gt;[Ss]ome.[Rr]eg[Ee]x)<br>
        <br>
        Then, in the expression field shown in step 3,<br>
        ensure that the RegEx box is selected,<br>
        and use named group references to access your extracted values.<br>
        <br>
        In line with the above example, \\g&lt;mygroup&gt;
        </html>""",
        'https://github.com/elespike/burp-cph/wiki/05.-Issuing-a-separate-request-to-use-a-dynamic-value-from-its-response'
    )

    extract_single = HelpPopup(
        'Extracting a value after issuing a request',
        """<html>
        To replace your target match(es) with a value<br>
        or append a value to your target match(es) when<br>
        that value depends on another request to be issued,<br>
        set up the request on the left pane and craft a RegEx<br>
        to extract the desired value from its response.<br>
        <br>
        The <b>Issue</b> button may be used to test the request,<br>
        helping ensure a proper response.
        </html>""",
        'https://github.com/elespike/burp-cph/wiki/05.-Issuing-a-separate-request-to-use-a-dynamic-value-from-its-response'
    )

    extract_macro = HelpPopup(
        'Extracting a value after issuing sequential requests',
        """<html>
        To replace your target match(es) with a value<br>
        or append a value to your target match(es) when<br>
        that value depends on sequential requests to be issued,<br>
        set up a Burp Suite Macro and invoke the CPH handler<br>
        from the Macro's associated Session Handling Rule.<br>
        <br>
        Finally, craft a RegEx to extract the desired value<br>
        from the final Macro response.
        </html>""",
        'https://github.com/elespike/burp-cph/wiki/07.-Extracting-replace-value-from-final-macro-response'
    )

    extract_cached = HelpPopup(
        'Extracting a value from a previous tab',
        """<html>
        To replace your target match(es) with a value<br>
        or append a value to your target match(es) when<br>
        that value has been cached by a previous CPH tab,<br>
        simply select the desired tab from the dynamic drop-down.<br>
        <i>NOTE: If the desired tab is not in the drop-down, ensure<br>
        that the tab has seen its request at least once.</i><br>
        <br>
        Then, craft a RegEx to extract the desired value<br>
        from the selected tab's cached response.<br>
        Note that disabled tabs will still cache HTTP messages<br>
        and therefore can be used as a mechanism for value extraction.
        </html>""",
        'https://github.com/elespike/burp-cph/wiki/08.-Utilizing-cached-responses'
    )

    def __init__(self):
        pass

class TinyHandler(SimpleHTTPRequestHandler, object):
    the_number = randint(1, 99999)
    def __init__(self, *args, **kwargs):
        self.protocol_version = 'HTTP/1.1'
        super(TinyHandler, self).__init__(*args, **kwargs)

    @staticmethod
    def normalize(number):
        try:
            number = int(number)
        except ValueError:
            return randint(1, 99999)
        if number == 0:
            return 1
        if number < 0:
            number = abs(number)
        while number > 99999:
            number = number / 10
        return number

    def do_GET(self):
        headers = {}
        response_body = 'https://github.com/elespike/burp-cph/wiki/00.-Interactive-demos'

        if self.path == '/':
            headers['Content-Type'] = 'text/html'
            response_body = '<h2>Welcome!</h2>Please <a href="https://github.com/elespike/burp-cph/wiki/00.-Interactive-demos">visit the Wiki </a> for instructions.'

        if self.path.startswith('/number'):
            response_body = str(TinyHandler.the_number)

        if self.path.startswith('/indices'):
            response_body = '[0][ ]1st  [1][ ]2nd  [2][ ]3rd\n\n[3][ ]4th  [4][ ]5th  [5][ ]6th\n\n[6][ ]7th  [7][ ]8th  [8][ ]9th'

        # E.g., /1/12345
        s = re_search('^/[123]/?.*?(\d{1,5})$', self.path)
        if s is not None:
            number = TinyHandler.normalize(s.group(1))
            if number == TinyHandler.the_number:
                response_body = '{} was correct!'.format(number)
            else:
                response_body = 'Try again!'
            TinyHandler.the_number = randint(1, 99999)
            response_body += '\nNew number: {}'.format(TinyHandler.the_number)

        if self.path.startswith('/echo/'):
            response_body = self.path.replace('/echo/', '')
            response_body = unquote(response_body)

        if self.path.startswith('/check'):
            number = 0
            s = re_search('number=(\d{1,5})', self.headers.get('cookie', ''))
            if s is not None and s.groups():
                number = TinyHandler.normalize(s.group(1))
            if not number:
                # Search again in the path/querystring.
                s = re_search('\d{1,5}', self.path)
                if s is not None:
                    number = TinyHandler.normalize(s.group(0))
            if number == TinyHandler.the_number:
                response_body = '{} was correct!'.format(number)
            else:
                response_body = 'Try again!'

        self.respond(response_body, headers)

    def do_POST(self):
        headers = {}
        response_body = 'Try again!'

        content_length = int(self.headers.get('content-length', 0))
        body = self.rfile.read(size=content_length)

        if self.path.startswith('/cookie'):
            number = 0
            # Accept both JSON and url-encoded form data.
            try:
                number = TinyHandler.normalize(loads(body)['number'])
            except:
                s = re_search('number=(\d{1,5})', body)
                if s is not None and s.groups():
                    number = TinyHandler.normalize(s.group(1))
            if number == TinyHandler.the_number:
                headers['Set-Cookie'] = 'number={}'.format(TinyHandler.the_number)
                response_body = '"number" cookie set to {}!'.format(TinyHandler.the_number)

        if self.path.startswith('/number'):
            s = re_search('number=(\d{1,5})', self.headers.get('cookie', ''))
            number_cookie = 0
            if s is not None and s.groups():
                number_cookie = int(s.group(1))
            if number_cookie == TinyHandler.the_number:
                number = randint(1, 99999)
                # Accept both JSON and url-encoded form data.
                try:
                    number = TinyHandler.normalize(loads(body)['number'])
                except:
                    s = re_search('number=(\d{1,5})', body)
                    if s is not None and s.groups():
                        number = TinyHandler.normalize(s.group(1))
                TinyHandler.the_number = number
                response_body = 'Number set to {}!'.format(TinyHandler.the_number)

        self.respond(response_body, headers)

    def respond(self, response_body, headers=dict()):
        self.send_response(200, 'OK')
        self.send_header('Content-Length', len(response_body))
        for h, v in headers.items():
            self.send_header(h, v)
        self.end_headers()
        self.wfile.write(response_body)

class MainTab(ITab, ChangeListener):
    mainpane = JTabbedPane()

    # These are set during __init__
    _cph   = None
    logger = None

    def __init__(self, cph):
        MainTab.mainpane.addChangeListener(self)
        MainTab._cph     = cph
        MainTab.logger   = cph.logger
        self.options_tab = OptionsTab()
        MainTab.mainpane.add('Options', self.options_tab)
        self._add_sign = unichr(0x002b)  # addition sign
        MainTab.mainpane.add(self._add_sign, JPanel())

        class Action(AbstractAction):
            def __init__(self, action):
                self.action = action
            def actionPerformed(self, e):
                if self.action:
                    self.action()

        # Ctrl+N only on key released
        MainTab.mainpane.getInputMap(1).put(KeyStroke.getKeyStroke(78, 2, True), 'add_config_tab')
        MainTab.mainpane.getActionMap().put('add_config_tab', Action(lambda: ConfigTab()))

        # Ctrl+Shift+N only on key released
        MainTab.mainpane.getInputMap(1).put(KeyStroke.getKeyStroke(78, 3, True), 'clone_tab')
        MainTab.mainpane.getActionMap().put(
            'clone_tab',
            Action(
                lambda: MainTab.mainpane.getSelectedComponent().clone_tab()
                if MainTab.mainpane.getSelectedIndex() > 0
                else None
            )
        )

        # Ctrl+W only on key released
        MainTab.mainpane.getInputMap(1).put(KeyStroke.getKeyStroke(87, 2, True), 'close_tab')
        MainTab.mainpane.getActionMap().put('close_tab', Action(MainTab.close_tab))

        # Ctrl+E only on key released
        MainTab.mainpane.getInputMap(1).put(KeyStroke.getKeyStroke(69, 2, True), 'toggle_tab')
        MainTab.mainpane.getActionMap().put(
            'toggle_tab',
            Action(
                lambda: MainTab.mainpane.getSelectedComponent().tabtitle_pane.enable_chkbox.setSelected(
                    not MainTab.mainpane.getSelectedComponent().tabtitle_pane.enable_chkbox.isSelected()
                )
            )
        )

        # Ctrl+,
        MainTab.mainpane.getInputMap(1).put(KeyStroke.getKeyStroke(44, 2), 'select_previous_tab')
        MainTab.mainpane.getActionMap().put(
            'select_previous_tab',
            Action(
                lambda: MainTab.mainpane.setSelectedIndex(MainTab.mainpane.getSelectedIndex() - 1)
                if MainTab.mainpane.getSelectedIndex() > 0
                else MainTab.mainpane.setSelectedIndex(0)
            )
        )

        # Ctrl+.
        MainTab.mainpane.getInputMap(1).put(KeyStroke.getKeyStroke(46, 2), 'select_next_tab')
        MainTab.mainpane.getActionMap().put(
            'select_next_tab',
            Action(lambda: MainTab.mainpane.setSelectedIndex(MainTab.mainpane.getSelectedIndex() + 1))
        )

        # Ctrl+Shift+,
        MainTab.mainpane.getInputMap(1).put(KeyStroke.getKeyStroke(44, 3), 'move_tab_back')
        MainTab.mainpane.getActionMap().put(
            'move_tab_back',
            Action(
                lambda: MainTab.mainpane.getSelectedComponent().move_tab_back(
                    MainTab.mainpane.getSelectedComponent()
                )
            )
        )

        # Ctrl+Shift+.
        MainTab.mainpane.getInputMap(1).put(KeyStroke.getKeyStroke(46, 3), 'move_tab_fwd')
        MainTab.mainpane.getActionMap().put(
            'move_tab_fwd',
            Action(
                lambda: MainTab.mainpane.getSelectedComponent().move_tab_fwd(
                    MainTab.mainpane.getSelectedComponent()
                )
            )
        )

    @staticmethod
    def getTabCaption():
        return 'CPH Config'

    def getUiComponent(self):
        return MainTab.mainpane

    def add_config_tab(self, messages):
        for message in messages:
            ConfigTab(message)

    @staticmethod
    def get_options_tab():
        return MainTab.mainpane.getComponentAt(0)

    @staticmethod
    def get_config_tabs():
        components = MainTab.mainpane.getComponents()
        for i in range(len(components)):
            for tab in components:
                if isinstance(tab, ConfigTab) and i == MainTab.mainpane.indexOfComponent(tab):
                    yield tab

    @staticmethod
    def get_config_tab_names():
        for tab in MainTab.get_config_tabs():
            yield tab.namepane_txtfield.getText()

    @staticmethod
    def get_config_tab_cache(tab_name):
        for tab in MainTab.get_config_tabs():
            if tab.namepane_txtfield.getText() == tab_name:
                return tab.cached_request, tab.cached_response

    @staticmethod
    def check_configtab_names():
        x = 0
        configtab_names = {}
        for name in MainTab.get_config_tab_names():
            configtab_names[x] = name
            x += 1
        indices_to_rename = {}
        for tab_index_1, tab_name_1 in configtab_names.items():
            for tab_index_2, tab_name_2 in configtab_names.items():
                if tab_name_2 not in indices_to_rename:
                    indices_to_rename[tab_name_2] = []
                if tab_name_1 == tab_name_2 and tab_index_1 != tab_index_2:
                    indices_to_rename[tab_name_2].append(tab_index_2 + 1) # +1 because the first tab is the Options tab
        for k, v in indices_to_rename.items():
            indices_to_rename[k] = set(sorted(v))
        for tab_name, indices in indices_to_rename.items():
            x = 1
            for i in indices:
                MainTab.set_tab_name(MainTab.mainpane.getComponentAt(i), tab_name + ' (%s)' % x)
                x += 1

    @staticmethod
    def set_tab_name(tab, tab_name):
        tab.namepane_txtfield.tab_label.setText(tab_name)
        tab.namepane_txtfield.setText(tab_name)
        emv_tab_index = MainTab.mainpane.indexOfComponent(tab) - 1
        MainTab.get_options_tab().emv_tab_pane.setTitleAt(emv_tab_index, tab_name)

    @staticmethod
    def close_tab(tab_index=None):
        if tab_index is None:
            tab_index = MainTab.mainpane.getSelectedIndex()
        true_index = tab_index - 1 # because of the Options tab
        tab_count = MainTab.mainpane.getTabCount()
        if tab_index == 0 or tab_count == 2:
            return
        if tab_count == 3 or tab_index == tab_count - 2:
            MainTab.mainpane.setSelectedIndex(tab_count - 3)
        MainTab.mainpane.remove(tab_index)
        MainTab.get_options_tab().emv_tab_pane.remove(true_index)

        # If the closed tab was selected in subsequent tabs' combo_cached, remove selection.
        for i, subsequent_tab in enumerate(MainTab.get_config_tabs()):
            if i < true_index:
                continue
            if subsequent_tab.param_handl_combo_cached.getSelectedIndex() == true_index:
                subsequent_tab.param_handl_combo_cached.setSelectedItem(None)
                if subsequent_tab.param_handl_combo_extract.getSelectedItem() == ConfigTab.PARAM_HANDL_COMBO_EXTRACT_CACHED:
                    MainTab.logger.warning(
                        'Selected cache no longer available for tab "{}"!'.format(subsequent_tab.namepane_txtfield.getText())
                    )
            subsequent_tab.param_handl_combo_cached.removeItemAt(true_index)

    def stateChanged(self, e):
        if e.getSource() == MainTab.mainpane:
            index = MainTab.mainpane.getSelectedIndex()
            if hasattr(self, '_add_sign') and MainTab.mainpane.getTitleAt(index) == self._add_sign:
                MainTab.mainpane.setSelectedIndex(0)
                ConfigTab()


class SubTab(JScrollPane, ActionListener):
    BTN_HELP = '?'
    DOCS_URL = 'https://github.com/elespike/burp-cph/wiki'
    INSETS   = Insets(2, 4, 2, 4)
    # Expression pane component indices
    CHECKBOX_INDEX  = 0
    TXT_FIELD_INDEX = 1
    # Socket pane component index tuples
    HTTPS_INDEX = 0
    HOST_INDEX  = 1
    PORT_INDEX  = 3

    CONFIG_MECHANISM = namedtuple('CONFIG_MECHANISM' , 'name, getter, setter')

    def __init__(self):
        self._main_tab_pane = JPanel(GridBagLayout())
        self.setViewportView(self._main_tab_pane)
        self.getVerticalScrollBar().setUnitIncrement(16)

    @staticmethod
    def create_blank_space():
        return JLabel(' ')

    @staticmethod
    def create_empty_button(button):
        button.setOpaque(False)
        button.setFocusable(False)
        button.setContentAreaFilled(False)
        button.setBorderPainted(False)

    @staticmethod
    def set_title_font(component):
        font = Font(Font.SANS_SERIF, Font.BOLD, 14)
        component.setFont(font)
        return component

    def initialize_constraints(self):
        constraints = GridBagConstraints()
        constraints.weightx = 1
        constraints.insets  = self.INSETS
        constraints.fill    = GridBagConstraints.HORIZONTAL
        constraints.anchor  = GridBagConstraints.NORTHWEST
        constraints.gridx   = 0
        constraints.gridy   = 0
        return constraints

    @staticmethod
    def show_card(cardpanel, label):
        cl = cardpanel.getLayout()
        cl.show(cardpanel, label)


    class HelpButton(JButton):
        # From CPH_Help.py:
        # HelpPopup = namedtuple('HelpPopup', 'title, message, url')
        def __init__(self, help_popup=None):
            super(JButton, self).__init__()
            self.title, self.message = '', ''
            self.url = SubTab.DOCS_URL

            if help_popup is not None:
                self.title   = help_popup.title
                self.message = JLabel(help_popup.message)
                self.message.setFont(Font(Font.MONOSPACED, Font.PLAIN, 14))
                self.url = help_popup.url

            self.setText(SubTab.BTN_HELP)
            self.setFont(Font(Font.SANS_SERIF, Font.BOLD, 14))

        def show_help(self):
            result = JOptionPane.showOptionDialog(
                self,
                self.message,
                self.title,
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                None,
                ['Learn more', 'Close'],
                'Close'
            )
            if result == 0:
                browser_open(self.url)


class ThreadedHTTPServer(ThreadingMixIn, TCPServer):
    pass


class OptionsTab(SubTab, ChangeListener):
    VERBOSITY        = 'Verbosity level:'
    BTN_QUICKSAVE    = 'Quicksave'
    BTN_QUICKLOAD    = 'Quickload'
    BTN_EXPORTCONFIG = 'Export Config'
    BTN_IMPORTCONFIG = 'Import Config'
    BTN_DOCS         = 'Visit Wiki'
    BTN_EMV          = 'Show EMV'
    DEMO_INACTIVE    = 'Run the built-in httpd for interactive demos'
    DEMO_ACTIVE      = 'Running built-in httpd on {}:{}'
    CHKBOX_PANE      = 'Tool scope settings'
    QUICKSTART_PANE  = 'Quickstart guide'

    FILEFILTER = FileNameExtensionFilter('JSON', ['json'])

    s = sha256()
    s.update('quick')
    CONFIGNAME_QUICK = s.hexdigest()
    s = sha256()
    s.update('options')
    CONFIGNAME_OPTIONS = s.hexdigest()
    del s

    def __init__(self):
        SubTab.__init__(self)

        btn_docs = JButton(self.BTN_DOCS)
        btn_docs.addActionListener(self)

        btn_emv = JButton(self.BTN_EMV)
        btn_emv.addActionListener(self)

        btn_quicksave = JButton(self.BTN_QUICKSAVE)
        btn_quicksave.addActionListener(self)

        btn_quickload = JButton(self.BTN_QUICKLOAD)
        btn_quickload.addActionListener(self)

        btn_exportconfig = JButton(self.BTN_EXPORTCONFIG)
        btn_exportconfig.addActionListener(self)

        btn_importconfig = JButton(self.BTN_IMPORTCONFIG)
        btn_importconfig.addActionListener(self)

        err, warn, info, dbg = 1, 2, 3, 4
        self.verbosity_translator = {
            err : ERROR  ,
            warn: WARNING,
            info: INFO   ,
            dbg : DEBUG  ,
        }

        # Just initializing
        self.httpd = None
        self.api_httpd = None
        self.api_httpd_thread = None
        self.httpd_thread = None

        self.verbosity_level_lbl = JLabel(getLevelName(INFO))
        self.verbosity_spinner = JSpinner(SpinnerNumberModel(info, err, dbg, 1))
        self.verbosity_spinner.addChangeListener(self)

        verbosity_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        verbosity_pane.add(JLabel(self.VERBOSITY))
        verbosity_pane.add(self.verbosity_spinner)
        verbosity_pane.add(self.verbosity_level_lbl)

        self.chkbox_demo = JCheckBox(self.DEMO_INACTIVE, False)
        self.chkbox_demo.addActionListener(self)
        demo_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        demo_pane.add(self.chkbox_demo)

        self.emv = JFrame('Effective Modification Viewer')
        self.emv_tab_pane = JTabbedPane()
        self.emv.add(self.emv_tab_pane)

        btn_pane = JPanel(GridBagLayout())
        constraints = self.initialize_constraints()
        constraints.gridwidth = 2
        btn_pane.add(verbosity_pane, constraints)
        constraints.gridwidth = 1
        constraints.gridy = 1
        btn_pane.add(btn_quicksave, constraints)
        constraints.gridx = 1
        btn_pane.add(btn_exportconfig, constraints)
        constraints.gridy = 2
        constraints.gridx = 0
        btn_pane.add(btn_quickload, constraints)
        constraints.gridx = 1
        btn_pane.add(btn_importconfig, constraints)
        constraints.gridy = 3
        constraints.gridx = 0
        btn_pane.add(btn_docs, constraints)
        constraints.gridx = 1
        btn_pane.add(btn_emv, constraints)
        constraints.gridy = 4
        constraints.gridx = 0
        constraints.gridwidth = 2
        btn_pane.add(demo_pane, constraints)

        self.chkbox_proxy     = JCheckBox('Proxy'    , True )
        self.chkbox_target    = JCheckBox('Target'   , False)
        self.chkbox_spider    = JCheckBox('Spider'   , False)
        self.chkbox_repeater  = JCheckBox('Repeater' , True )
        self.chkbox_sequencer = JCheckBox('Sequencer', False)
        self.chkbox_intruder  = JCheckBox('Intruder' , False)
        self.chkbox_scanner   = JCheckBox('Scanner'  , False)
        self.chkbox_extender  = JCheckBox('Extender' , False)

        chkbox_pane = JPanel(GridBagLayout())
        chkbox_pane.setBorder(BorderFactory.createTitledBorder(self.CHKBOX_PANE))
        chkbox_pane.getBorder().setTitleFont(Font(Font.SANS_SERIF, Font.ITALIC, 16))
        constraints = self.initialize_constraints()
        chkbox_pane.add(self.chkbox_proxy, constraints)
        constraints.gridy = 1
        chkbox_pane.add(self.chkbox_target, constraints)
        constraints.gridy = 2
        chkbox_pane.add(self.chkbox_spider, constraints)
        constraints.gridy = 3
        chkbox_pane.add(self.chkbox_repeater, constraints)
        constraints.gridx = 1
        constraints.gridy = 0
        chkbox_pane.add(self.chkbox_sequencer, constraints)
        constraints.gridy = 1
        chkbox_pane.add(self.chkbox_intruder, constraints)
        constraints.gridy = 2
        chkbox_pane.add(self.chkbox_scanner, constraints)
        constraints.gridy = 3
        chkbox_pane.add(self.chkbox_extender, constraints)

        quickstart_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        quickstart_pane.setBorder(BorderFactory.createTitledBorder(self.QUICKSTART_PANE))
        quickstart_pane.getBorder().setTitleFont(Font(Font.SANS_SERIF, Font.ITALIC, 16))
        quickstart_text_lbl = JLabel(CPH_Help.quickstart)
        quickstart_text_lbl.putClientProperty("html.disable", None)
        quickstart_text_lbl.setFont(Font(Font.MONOSPACED, Font.PLAIN, 14))
        quickstart_pane.add(quickstart_text_lbl)

        constraints = self.initialize_constraints()
        constraints.gridwidth = 3
        self._main_tab_pane.add(SubTab.create_blank_space(), constraints)
        constraints.gridwidth = 1
        constraints.gridy = 1
        self._main_tab_pane.add(btn_pane, constraints)
        constraints.gridx = 1
        self._main_tab_pane.add(SubTab.create_blank_space(), constraints)
        constraints.gridx = 2
        self._main_tab_pane.add(chkbox_pane, constraints)
        constraints.gridx = 3
        self._main_tab_pane.add(SubTab.create_blank_space(), constraints)
        constraints.gridx = 0
        constraints.gridy = 2
        constraints.gridwidth = 3
        self._main_tab_pane.add(SubTab.create_blank_space(), constraints)
        constraints.gridy = 3
        constraints.weighty = 1
        self._main_tab_pane.add(quickstart_pane, constraints)

        self.config_mechanisms = [
            SubTab.CONFIG_MECHANISM(
                'verbosity',
                self.verbosity_spinner.getValue,
                lambda cv: self.verbosity_spinner.setValue(cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'chkbox_proxy',
                self.chkbox_proxy.isSelected,
                lambda cv: self.chkbox_proxy.setSelected(cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'chkbox_target',
                self.chkbox_target.isSelected,
                lambda cv: self.chkbox_target.setSelected(cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'chkbox_spider',
                self.chkbox_spider.isSelected,
                lambda cv: self.chkbox_spider.setSelected(cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'chkbox_repeater',
                self.chkbox_repeater.isSelected,
                lambda cv: self.chkbox_repeater.setSelected(cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'chkbox_sequencer',
                self.chkbox_sequencer.isSelected,
                lambda cv: self.chkbox_sequencer.setSelected(cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'chkbox_intruder',
                self.chkbox_intruder.isSelected,
                lambda cv: self.chkbox_intruder.setSelected(cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'chkbox_scanner',
                self.chkbox_scanner.isSelected,
                lambda cv: self.chkbox_scanner.setSelected(cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'chkbox_extender',
                self.chkbox_extender.isSelected,
                lambda cv: self.chkbox_extender.setSelected(cv)
            ),
        ]

    def stateChanged(self, e):
        if e.getSource() == self.verbosity_spinner:
            level = self.verbosity_translator[self.verbosity_spinner.getValue()]
            MainTab.logger.setLevel(level)
            self.verbosity_level_lbl.setText(getLevelName(level))

    def set_tab_values(self, config, tab, tab_name=''):
        warn = False
        for cm in tab.config_mechanisms:
            if cm.name in config:
                cm.setter(config[cm.name])
            else:
                warn = True
                continue
        if warn:
            MainTab.logger.warning(
                'Your configuration is corrupt or was generated by an old version of CPH. Expect the unexpected.'
            )

        if isinstance(tab, OptionsTab):
            return

        MainTab.set_tab_name(tab, tab_name)
        # A couple hacks to avoid implementing an ItemListener just for this,
        # because ActionListener doesn't get triggered on setSelected() -_-
        # Reference: https://stackoverflow.com/questions/9882845
        try:
            tab.param_handl_forwarder_socket_pane.setVisible(config['enable_forwarder'])
            tab.param_handl_dynamic_pane         .setVisible(config['dynamic_checkbox'])
        except KeyError:
            return

    def actionPerformed(self, e):
        c = e.getActionCommand()
        if c == self.BTN_QUICKLOAD or c == self.BTN_IMPORTCONFIG:
            replace_config_tabs = False
            result   = 0
            tabcount = 0
            for tab in MainTab.get_config_tabs():
                tabcount += 1
                break
            if tabcount > 0:
                result = JOptionPane.showOptionDialog(
                    self,
                    'Would you like to Purge or Keep all existing tabs?',
                    'Existing Tabs Detected!',
                    JOptionPane.YES_NO_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE,
                    None,
                    ['Purge', 'Keep', 'Cancel'],
                    'Cancel'
                )
            # If purge...
            if result == 0:
                replace_config_tabs = True
                MainTab.logger.info('Replacing configuration...')
            # If not cancel or close dialog...
            # note: result can still be 0 here; do not use 'elif'
            if result != 2 and result != -1:
                if result != 0:
                    MainTab.logger.info('Merging configuration...')

                if c == self.BTN_QUICKLOAD:
                    try:
                        config = loads(
                            MainTab._cph.callbacks.loadExtensionSetting(OptionsTab.CONFIGNAME_QUICK),
                            object_pairs_hook=odict
                        )
                        self.load_config(config, replace_config_tabs)
                        MainTab.logger.info('Configuration quickloaded.')
                    except StandardError:
                        MainTab.logger.exception('Error during quickload.')

                if c == self.BTN_IMPORTCONFIG:
                    fc = JFileChooser()
                    fc.setFileFilter(OptionsTab.FILEFILTER)
                    result = fc.showOpenDialog(self)
                    if result == JFileChooser.APPROVE_OPTION:
                        fpath = fc.getSelectedFile().getPath()
                        try:
                            with open(fpath, 'r') as f:
                                config = load(f, object_pairs_hook=odict)
                            self.load_config(config, replace_config_tabs)
                            MainTab.logger.info('Configuration imported from "{}".'.format(fpath))
                        except StandardError:
                            MainTab.logger.exception('Error importing config from "{}".'.format(fpath))
                    if result == JFileChooser.CANCEL_OPTION:
                        MainTab.logger.info('User canceled configuration import from file.')
            else:
                MainTab.logger.info('User canceled quickload/import.')

        if c == self.BTN_QUICKSAVE:
            try:
                full_config = self.prepare_to_save_all()
                MainTab._cph.callbacks.saveExtensionSetting(OptionsTab.CONFIGNAME_QUICK, dumps(full_config))
                MainTab.logger.info('Configuration quicksaved.')
            except StandardError:
                MainTab.logger.exception('Error during quicksave.')

        if c == self.BTN_DOCS:
            browser_open(self.DOCS_URL)

        if c == self.BTN_EMV:
            if not self.emv.isVisible():
                self.emv.pack()
                self.emv.setSize(800, 600)
                self.emv.show()
            # Un-minimize
            self.emv.setState(JFrame.NORMAL)
            self.emv.toFront()
            for emv_tab in self.emv_tab_pane.getComponents():
                emv_tab.viewer.setDividerLocation(0.5)

        if c == self.BTN_EXPORTCONFIG:
            tabcount = 0
            for tab in MainTab.get_config_tabs():
                tabcount += 1
                break
            if tabcount > 0:
                fc = JFileChooser()
                fc.setFileFilter(OptionsTab.FILEFILTER)
                result = fc.showSaveDialog(self)
                if result == JFileChooser.APPROVE_OPTION:
                    fpath = fc.getSelectedFile().getPath()
                    if not fpath.endswith('.json'):
                        fpath += '.json'
                    full_config = self.prepare_to_save_all()
                    try:
                        with open(fpath, 'w') as f:
                            dump(full_config, f, indent=4, separators=(',', ': '))
                        MainTab.logger.info('Configuration exported to "{}".'.format(fpath))
                    except IOError:
                        MainTab.logger.exception('Error exporting config to "{}".'.format(fpath))
                if result == JFileChooser.CANCEL_OPTION:
                    MainTab.logger.info('User canceled configuration export to file.')

        if c == self.DEMO_INACTIVE:
            # Start threaded HTTP server for interactive demos.
            try:
                self.httpd = ThreadedHTTPServer(('localhost', 9001), TinyHandler)
            except socket_error:
                # Port zero means any unused port.
                self.httpd = ThreadedHTTPServer(('localhost', 0), TinyHandler)
            self.httpd_thread = Thread(target=self.httpd.serve_forever)
            # Daemonize so that it terminates cleanly without needing to join().
            self.httpd_thread.daemon = True
            self.httpd_thread.start()
            self.chkbox_demo.setText(self.DEMO_ACTIVE.format(*self.httpd.server_address))

        if self.httpd is not None and c == self.DEMO_ACTIVE.format(*self.httpd.server_address):
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
            self.chkbox_demo.setText(self.DEMO_INACTIVE)


    def load_config(self, config, replace_config_tabs=False):
        loaded_tab_names = config.keys()

        if OptionsTab.CONFIGNAME_OPTIONS in loaded_tab_names:
            self.set_tab_values(config[OptionsTab.CONFIGNAME_OPTIONS], MainTab.get_options_tab())
            loaded_tab_names.remove(OptionsTab.CONFIGNAME_OPTIONS)

        tabs_left_to_load = list(loaded_tab_names)
        tabs_to_remove    = {}

        # Modify existing and mark for purge where applicable
        for tab_name, tab in product(loaded_tab_names, MainTab.get_config_tabs()):
            if tab_name == tab.namepane_txtfield.getText():
                self.set_tab_values(config[tab_name], tab, tab_name)
                if tab_name in tabs_left_to_load:
                    tabs_left_to_load.remove(tab_name)
                tabs_to_remove[tab] = False
            if tab not in tabs_to_remove:
                tabs_to_remove[tab] = True

        # Import and purge if applicable
        for tab, tab_marked in tabs_to_remove.items():
            if tab_marked and replace_config_tabs:
                MainTab.get_options_tab().emv_tab_pane.remove(tab.emv_tab)
                MainTab.mainpane.remove(tab)
        for tab_name in tabs_left_to_load:
            self.set_tab_values(config[tab_name], ConfigTab(), tab_name)

        # No need to proceed if there's only 1 tab.
        # This is also the case when cloning a tab.
        if len(loaded_tab_names) <= 1:
            return

        # Restore tab order
        for tab in MainTab.get_config_tabs():
            tab_name = tab.namepane_txtfield.getText()
            # Adding one because the Options tab is always the first tab.
            if tab_name in loaded_tab_names:
                ConfigTab.move_tab(tab, loaded_tab_names.index(tab_name) + 1)
            else:
                ConfigTab.move_tab(tab, len(loaded_tab_names) + 1)

    def prepare_to_save_all(self):
        MainTab.check_configtab_names()
        full_config = odict()
        for tab in MainTab.get_config_tabs():
            full_config[tab.namepane_txtfield.getText()] = self.prepare_to_save_tab(tab)
        full_config[OptionsTab.CONFIGNAME_OPTIONS] = self.prepare_to_save_tab(MainTab.get_options_tab())
        return full_config

    def prepare_to_save_tab(self, tab):
        config = {}
        for cm in tab.config_mechanisms:
            config[cm.name] = cm.getter()
        return config


class EMVTab(JSplitPane, ListSelectionListener):
    MAX_ITEMS = 32
    def __init__(self):
        self.updating = False
        self.selected_index = -1

        self.table = JTable(self.EMVTableModel())
        self.table_model = self.table.getModel()
        sm = self.table.getSelectionModel()
        sm.setSelectionMode(0) # Single selection
        sm.addListSelectionListener(self)

        table_pane = JScrollPane()
        table_pane.setViewportView(self.table)
        table_pane.getVerticalScrollBar().setUnitIncrement(16)

        self.diff_field     = MainTab._cph.callbacks.createMessageEditor(None, False)
        self.original_field = MainTab._cph.callbacks.createMessageEditor(None, False)
        self.modified_field = MainTab._cph.callbacks.createMessageEditor(None, False)

        self.viewer = JSplitPane()
        self.viewer.setLeftComponent(self.original_field.getComponent())
        self.viewer.setRightComponent(self.modified_field.getComponent())

        self.diffpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        # Top pane gets populated in value_changed(), below.
        self.diffpane.setTopComponent(JPanel())
        self.diffpane.setBottomComponent(self.viewer)
        self.diffpane.setDividerLocation(100)

        viewer_pane = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.weightx = 1
        constraints.weighty = 1
        constraints.fill    = GridBagConstraints.BOTH
        constraints.anchor  = GridBagConstraints.NORTH
        constraints.gridx   = 0
        constraints.gridy   = 0
        viewer_pane.add(self.diffpane, constraints)

        self.setOrientation(JSplitPane.VERTICAL_SPLIT)
        self.setTopComponent(table_pane)
        self.setBottomComponent(viewer_pane)
        self.setDividerLocation(100)

    def add_table_row(self, time, is_request, original_msg, modified_msg):
        if len(self.table_model.rows) == 0:
            self.viewer.setDividerLocation(0.5)

        message_type = 'Response'
        if is_request:
            message_type = 'Request'
        self.table_model.rows.insert(
            0,
            [str(time)[:-3], message_type, len(modified_msg) - len(original_msg)]
        )
        self.table_model.messages.insert(
            0,
            self.table_model.MessagePair(original_msg, modified_msg)
        )

        if len(self.table_model.rows) > self.MAX_ITEMS:
            self.table_model.rows.pop(-1)
        if len(self.table_model.messages) > self.MAX_ITEMS:
            self.table_model.messages.pop(-1)

        self.table_model.fireTableDataChanged()
        self.table.setRowSelectionInterval(0, 0)

    def valueChanged(self, e):
        # Jenky lock mechanism to prevent crash with many quickly-repeated triggers.
        if self.updating:
            return
        self.updating = True

        index = self.table.getSelectedRow()
        if self.selected_index == index:
            self.updating = False
            return
        self.selected_index = index
        original_msg = self.table_model.messages[index].original_msg
        modified_msg = self.table_model.messages[index].modified_msg

        diff = unified_diff(original_msg.splitlines(1), modified_msg.splitlines(1))
        text = ''
        for line in diff:
            if '---' in line or '+++' in line:
                continue
            text += line
            if not text.endswith('\n'):
                text += '\n'

        dl = self.diffpane.getDividerLocation()
        is_request = self.table_model.rows[index][1] == 'Request'
        self.diff_field    .setMessage(text        , is_request)
        self.original_field.setMessage(original_msg, is_request)
        self.modified_field.setMessage(modified_msg, is_request)

        self.diffpane.setTopComponent(self.diff_field.getComponent().getComponentAt(0))
        self.diffpane.setDividerLocation(dl)
        self.updating = False


    class EMVTableModel(AbstractTableModel):
        def __init__(self):
            super(EMVTab.EMVTableModel, self).__init__()
            self.MessagePair = namedtuple('MessagePair', 'original_msg, modified_msg')
            self.rows = []
            self.messages = []

        def getRowCount(self):
            return len(self.rows)

        def getColumnCount(self):
            return 3

        def getColumnName(self, columnIndex):
            if columnIndex == 0:
                return 'Time'
            if columnIndex == 1:
                return 'Type'
            if columnIndex == 2:
                return 'Length Difference'

        def getValueAt(self, rowIndex, columnIndex):
            return self.rows[rowIndex][columnIndex]

        def setValueAt(self, aValue, rowIndex, columnIndex):
            return

        def isCellEditable(self, rowIndex, columnIndex):
            return False


class ConfigTabTitle(JPanel):
    def __init__(self):
        self.setBorder(BorderFactory.createEmptyBorder(-4, -5, -5, -5))
        self.setOpaque(False)
        self.enable_chkbox = JCheckBox('', True)
        self.label = JLabel(ConfigTab.TAB_NEW_NAME)
        self.label.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 4))
        self.add(self.enable_chkbox)
        self.add(self.label)
        self.add(self.CloseButton())

    class CloseButton(JButton, ActionListener):
        def __init__(self):
            self.setText(unichr(0x00d7))  # multiplication sign
            self.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 2))
            SubTab.create_empty_button(self)
            self.addMouseListener(self.CloseButtonMouseListener())
            self.addActionListener(self)

        def actionPerformed(self, e):
            MainTab.close_tab(MainTab.mainpane.indexOfTabComponent(self.getParent()))

        class CloseButtonMouseListener(MouseAdapter):
            def mouseEntered(self, e):
                button = e.getComponent()
                button.setForeground(Color.red)

            def mouseExited(self, e):
                button = e.getComponent()
                button.setForeground(Color.black)

            def mouseReleased(self, e):
                pass

            def mousePressed(self, e):
                pass


class ConfigTabNameField(JTextField, KeyListener):
    def __init__(self, tab_label):
        self.setColumns(32)
        self.setText(ConfigTab.TAB_NEW_NAME)
        self.setFont(ConfigTab.FIELD_FONT)
        self.addKeyListener(self)
        self.tab_label = tab_label

        self.addKeyListener(UndoableKeyListener(self))

    def keyReleased(self, e):
        self_index = MainTab.mainpane.getSelectedIndex()
        true_index = self_index - 1 # because of the Options tab
        self.tab_label.setText(self.getText())
        MainTab.get_options_tab().emv_tab_pane.setTitleAt(true_index, self.getText())
        for i, subsequent_tab in enumerate(MainTab.get_config_tabs()):
            if i <= true_index:
                continue
            subsequent_tab.param_handl_combo_cached.removeItemAt(true_index)
            subsequent_tab.param_handl_combo_cached.insertItemAt(self.getText(), true_index)

    def keyPressed(self, e):
        # Doing self._tab_label.setText() here is sub-optimal. Leave it above.
        pass

    def keyTyped(self, e):
        pass


class UndoableKeyListener(KeyListener):
    REDO = 89
    UNDO = 90
    CTRL = 2
    def __init__(self, target):
        self.undomgr = UndoManager()
        target.getDocument().addUndoableEditListener(self.undomgr)

    def keyReleased(self, e):
        pass

    def keyPressed(self, e):
        if e.getModifiers() == self.CTRL:
            if e.getKeyCode() == self.UNDO and self.undomgr.canUndo():
                self.undomgr.undo()
            if e.getKeyCode() == self.REDO and self.undomgr.canRedo():
                self.undomgr.redo()

    def keyTyped(self, e):
        pass


class ConfigTab(SubTab):
    TXT_FIELD_SIZE = 64
    FIELD_FONT     = Font(Font.MONOSPACED, Font.PLAIN, 13)
    REGEX          = 'RegEx'
    TAB_NEW_NAME   = 'Unconfigured'

    BTN_BACK     = '<'
    BTN_FWD      = '>'
    BTN_CLONETAB = 'Clone'
    TAB_NAME     = 'Friendly name:'

    # Scope pane
    MSG_MOD_GROUP           = 'Scoping'
    MSG_MOD_SCOPE_BURP      = ' Provided their URLs are within Burp Suite\'s scope,'
    MSG_MOD_TYPES_TO_MODIFY = 'this tab will work'

    MSG_MOD_COMBO_SCOPE_ALL     = 'on all'
    MSG_MOD_COMBO_SCOPE_SOME    = 'only on'
    MSG_MOD_COMBO_SCOPE_CHOICES = [
        MSG_MOD_COMBO_SCOPE_ALL,
        MSG_MOD_COMBO_SCOPE_SOME,
    ]
    MSG_MOD_COMBO_TYPE_REQ     = 'requests'
    MSG_MOD_COMBO_TYPE_RESP    = 'responses'
    MSG_MOD_COMBO_TYPE_BOTH    = 'requests and responses'
    MSG_MOD_COMBO_TYPE_CHOICES = [
        MSG_MOD_COMBO_TYPE_REQ ,
        MSG_MOD_COMBO_TYPE_RESP,
        MSG_MOD_COMBO_TYPE_BOTH,
    ]
    MSG_MOD_SCOPE_SOME = ' containing this expression:'

    # Handling pane
    PARAM_HANDL_GROUP            = 'Parameter handling'
    PARAM_HANDL_AUTO_ENCODE      = 'Automatically URL-encode the first line of the request, if modified'
    PARAM_HANDL_ENABLE_FORWARDER = 'Change the destination of the request'
    PARAM_HANDL_MATCH_EXP        = ' 1) Find matches to this expression:'
    PARAM_HANDL_TARGET           = '2) Target'

    PARAM_HANDL_COMBO_INDICES_FIRST   = 'the first'
    PARAM_HANDL_COMBO_INDICES_EACH    = 'each'
    PARAM_HANDL_COMBO_INDICES_SUBSET  = 'a subset'
    PARAM_HANDL_COMBO_INDICES_CHOICES = [
        PARAM_HANDL_COMBO_INDICES_FIRST ,
        PARAM_HANDL_COMBO_INDICES_EACH  ,
        PARAM_HANDL_COMBO_INDICES_SUBSET,
    ]
    PARAM_HANDL_MATCH_RANGE  = 'of the matches'
    PARAM_HANDL_MATCH_SUBSET = 'Which subset?'
    PARAM_HANDL_ACTION       = ' 3) Replace each target with this expression:'

    PARAM_HANDL_DYNAMIC_CHECKBOX    = 'The value I need is dynamic'
    PARAM_HANDL_DYNAMIC_DESCRIPTION = '4) In the expression above, refer to the named RegEx groups you\'ll define below in order to insert:'

    PARAM_HANDL_COMBO_EXTRACT_SINGLE  = 'values returned by issuing a single request'
    PARAM_HANDL_COMBO_EXTRACT_MACRO   = 'values returned by issuing a sequence of requests'
    PARAM_HANDL_COMBO_EXTRACT_CACHED  = 'values in the cached response of a previous CPH tab'
    PARAM_HANDL_COMBO_EXTRACT_CHOICES = [
        PARAM_HANDL_COMBO_EXTRACT_SINGLE,
        PARAM_HANDL_COMBO_EXTRACT_MACRO ,
        PARAM_HANDL_COMBO_EXTRACT_CACHED,
    ]
    PARAM_HANDL_BTN_ISSUE           = 'Issue'
    PARAM_HANDL_EXTRACT_STATIC      = 'When "RegEx" is enabled here, backslash escape sequences and group references will be processed.'
    PARAM_HANDL_EXTRACT_SINGLE      = 'the request in the left pane, then extract the value from its response with this expression:'
    PARAM_HANDL_EXTRACT_MACRO       = 'When invoked from a Session Handling Rule, CPH will extract the value from the final macro response with this expression:'
    PARAM_HANDL_EXTRACT_CACHED_PRE  = 'Extract the value from'
    PARAM_HANDL_EXTRACT_CACHED_POST = '\'s cached response with this expression:'

    EXPRESSION_CONFIG = namedtuple('EXPRESSION_CONFIG', 'is_regex, expression')
    SOCKET_CONFIG     = namedtuple('SOCKET_CONFIG'    , 'https, host, port')

    def __init__(self, message=None):
        SubTab.__init__(self)

        index = MainTab.mainpane.getTabCount() - 1
        MainTab.mainpane.add(self, index)
        self.tabtitle_pane = ConfigTabTitle()
        MainTab.mainpane.setTabComponentAt(index, self.tabtitle_pane)
        MainTab.mainpane.setSelectedIndex(index)

        btn_back = SubTab.set_title_font(JButton(self.BTN_BACK))
        btn_fwd  = SubTab.set_title_font(JButton(self.BTN_FWD))
        btn_back.addActionListener(self)
        btn_fwd .addActionListener(self)

        btn_clonetab = JButton(self.BTN_CLONETAB)
        btn_clonetab.addActionListener(self)

        controlpane = JPanel(FlowLayout(FlowLayout.LEADING))
        controlpane.add(btn_back)
        controlpane.add(btn_fwd)
        controlpane.add(SubTab.create_blank_space())
        controlpane.add(btn_clonetab)

        namepane = JPanel(FlowLayout(FlowLayout.LEADING))
        namepane.add(SubTab.set_title_font(JLabel(self.TAB_NAME)))
        self.namepane_txtfield = ConfigTabNameField(self.tabtitle_pane.label)
        namepane.add(self.namepane_txtfield)

        msg_mod_layout_pane = JPanel(GridBagLayout())
        msg_mod_layout_pane.setBorder(BorderFactory.createTitledBorder(self.MSG_MOD_GROUP))
        msg_mod_layout_pane.getBorder().setTitleFont(Font(Font.SANS_SERIF, Font.ITALIC, 16))

        param_handl_layout_pane = JPanel(GridBagLayout())
        param_handl_layout_pane.setBorder(BorderFactory.createTitledBorder(self.PARAM_HANDL_GROUP))
        param_handl_layout_pane.getBorder().setTitleFont(Font(Font.SANS_SERIF, Font.ITALIC, 16))

        self.msg_mod_combo_scope = JComboBox(self.MSG_MOD_COMBO_SCOPE_CHOICES)
        self.msg_mod_combo_type  = JComboBox(self.MSG_MOD_COMBO_TYPE_CHOICES)
        self.msg_mod_combo_scope.addActionListener(self)
        self.msg_mod_combo_type .addActionListener(self)

        self.msg_mod_exp_pane_scope     = self.create_expression_pane()
        self.msg_mod_exp_pane_scope_lbl = JLabel(self.MSG_MOD_SCOPE_SOME)
        self.msg_mod_exp_pane_scope    .setVisible(False)
        self.msg_mod_exp_pane_scope_lbl.setVisible(False)

        self.param_handl_auto_encode_chkbox      = JCheckBox(self.PARAM_HANDL_AUTO_ENCODE     , False)
        self.param_handl_enable_forwarder_chkbox = JCheckBox(self.PARAM_HANDL_ENABLE_FORWARDER, False)
        self.param_handl_enable_forwarder_chkbox.addActionListener(self)

        self.param_handl_forwarder_socket_pane = self.create_socket_pane()
        self.param_handl_forwarder_socket_pane.setVisible(False)

        self.param_handl_exp_pane_target = self.create_expression_pane()
        self.param_handl_combo_indices = JComboBox(self.PARAM_HANDL_COMBO_INDICES_CHOICES)
        self.param_handl_combo_indices.addActionListener(self)

        self.param_handl_txtfield_match_indices = JTextField(12)
        self.param_handl_txtfield_match_indices.addKeyListener(
            UndoableKeyListener(self.param_handl_txtfield_match_indices)
        )
        self.param_handl_txtfield_match_indices.setText('0')
        self.param_handl_txtfield_match_indices.setEnabled(False)

        self.param_handl_button_indices_help = self.HelpButton(CPH_Help.indices)
        self.param_handl_button_indices_help.putClientProperty("html.disable", None)
        self.param_handl_button_indices_help.addActionListener(self)

        self.param_handl_subset_pane = JPanel(FlowLayout(FlowLayout.LEADING))

        self.param_handl_dynamic_chkbox = JCheckBox(self.PARAM_HANDL_DYNAMIC_CHECKBOX, False)
        self.param_handl_dynamic_chkbox.addActionListener(self)

        self.param_handl_dynamic_pane = JPanel(GridBagLayout())
        self.param_handl_dynamic_pane.setVisible(False)

        self.param_handl_exp_pane_extract_static = self.create_expression_pane(label=self.PARAM_HANDL_EXTRACT_STATIC, multiline=False)
        self.param_handl_exp_pane_extract_single = self.create_expression_pane(enabled=False)
        self.param_handl_exp_pane_extract_macro  = self.create_expression_pane(label=self.PARAM_HANDL_EXTRACT_MACRO, enabled=False)
        self.param_handl_exp_pane_extract_cached = self.create_expression_pane(enabled=False)

        self.param_handl_issuer_socket_pane = self.create_socket_pane()

        self.request       , self.response        = self.initialize_req_resp()
        self.cached_request, self.cached_response = self.initialize_req_resp()

        if message: # init argument, defaults to None, set when using 'Send to CPH'
            self.request = message.getRequest()
            resp = message.getResponse()
            if resp:
                self.response = resp
            httpsvc = message.getHttpService()
            self.get_socket_pane_component(self.param_handl_issuer_socket_pane, self.HOST_INDEX).setText(httpsvc.getHost())
            self.get_socket_pane_component(self.param_handl_issuer_socket_pane, self.PORT_INDEX).setValue(httpsvc.getPort())
            self.get_socket_pane_component(self.param_handl_issuer_socket_pane, self.HTTPS_INDEX).setSelected(httpsvc.getProtocol() == 'https')

        self.param_handl_request_editor  = MainTab._cph.callbacks.createMessageEditor(None, True)
        self.param_handl_response_editor = MainTab._cph.callbacks.createMessageEditor(None, False)
        self.param_handl_request_editor .setMessage(self.request , True)
        self.param_handl_response_editor.setMessage(self.response, False)

        self.param_handl_cached_req_viewer  = MainTab._cph.callbacks.createMessageEditor(None, False)
        self.param_handl_cached_resp_viewer = MainTab._cph.callbacks.createMessageEditor(None, False)
        self.param_handl_cached_req_viewer .setMessage(self.cached_request , True)
        self.param_handl_cached_resp_viewer.setMessage(self.cached_response, False)

        self.param_handl_cardpanel_static_or_extract = JPanel(FlexibleCardLayout())

        self.param_handl_combo_extract = JComboBox(self.PARAM_HANDL_COMBO_EXTRACT_CHOICES)
        self.param_handl_combo_extract.addActionListener(self)

        self.param_handl_button_named_groups_help = self.HelpButton(CPH_Help.named_groups)
        self.param_handl_button_named_groups_help.putClientProperty("html.disable", None)
        self.param_handl_button_named_groups_help.addActionListener(self)

        # These ones don't need ActionListeners; see actionPerformed().
        self.param_handl_button_extract_single_help = self.HelpButton(CPH_Help.extract_single)
        self.param_handl_button_extract_single_help.putClientProperty("html.disable", None)
        self.param_handl_button_extract_macro_help  = self.HelpButton(CPH_Help.extract_macro )
        self.param_handl_button_extract_macro_help.putClientProperty("html.disable", None)
        self.param_handl_button_extract_cached_help = self.HelpButton(CPH_Help.extract_cached)
        self.param_handl_button_extract_cached_help.putClientProperty("html.disable", None)

        self.param_handl_combo_cached = JComboBox()
        self.param_handl_combo_cached.addActionListener(self)

        self.build_msg_mod_pane(msg_mod_layout_pane)
        self.build_param_handl_pane(param_handl_layout_pane)

        if self.request:
            self.param_handl_combo_extract.setSelectedItem(self.PARAM_HANDL_COMBO_EXTRACT_SINGLE)
            # Using doClick() since it's initially unchecked, which means it'll get checked *and* the ActionListener will trigger.
            self.param_handl_dynamic_chkbox.doClick()

        for previous_tab in MainTab.get_config_tabs():
            if previous_tab == self:
                break
            self.param_handl_combo_cached.addItem(previous_tab.namepane_txtfield.getText())

        constraints = self.initialize_constraints()
        constraints.weighty = 0.05
        self._main_tab_pane.add(controlpane, constraints)
        constraints.gridy = 1
        self._main_tab_pane.add(namepane, constraints)
        constraints.gridy = 2
        self._main_tab_pane.add(msg_mod_layout_pane, constraints)
        constraints.gridy = 3
        constraints.weighty = 1
        self._main_tab_pane.add(param_handl_layout_pane, constraints)

        self.emv_tab = EMVTab()
        MainTab.get_options_tab().emv_tab_pane.add(self.namepane_txtfield.getText(), self.emv_tab)

        self.config_mechanisms = [
            SubTab.CONFIG_MECHANISM(
                'enabled',
                self.tabtitle_pane.enable_chkbox.isSelected,
                lambda cv: self.tabtitle_pane.enable_chkbox.setSelected(cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'modify_scope_choice_index',
                self.msg_mod_combo_scope.getSelectedIndex,
                lambda cv: self.msg_mod_combo_scope.setSelectedIndex(cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'modify_type_choice_index',
                self.msg_mod_combo_type.getSelectedIndex,
                lambda cv: self.msg_mod_combo_type.setSelectedIndex(cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'modify_expression',
                lambda   : self.get_exp_pane_config(self.msg_mod_exp_pane_scope    ),
                lambda cv: self.set_exp_pane_config(self.msg_mod_exp_pane_scope, cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'auto_encode',
                self.param_handl_auto_encode_chkbox.isSelected,
                lambda cv: self.param_handl_auto_encode_chkbox.setSelected(cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'enable_forwarder',
                self.param_handl_enable_forwarder_chkbox.isSelected,
                lambda cv: self.param_handl_enable_forwarder_chkbox.setSelected(cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'forwarder',
                lambda   : self.get_socket_pane_config(self.param_handl_forwarder_socket_pane    ),
                lambda cv: self.set_socket_pane_config(self.param_handl_forwarder_socket_pane, cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'match_expression',
                lambda   : self.get_exp_pane_config(self.param_handl_exp_pane_target    ),
                lambda cv: self.set_exp_pane_config(self.param_handl_exp_pane_target, cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'indices_choice_index',
                self.param_handl_combo_indices.getSelectedIndex,
                lambda cv: self.param_handl_combo_indices.setSelectedIndex(cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'extract_choice_index',
                self.param_handl_combo_extract.getSelectedIndex,
                lambda cv: self.param_handl_combo_extract.setSelectedIndex(cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'match_indices',
                self.param_handl_txtfield_match_indices.getText,
                lambda cv: self.param_handl_txtfield_match_indices.setText(cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'static_expression',
                lambda   : self.get_exp_pane_config(self.param_handl_exp_pane_extract_static    ),
                lambda cv: self.set_exp_pane_config(self.param_handl_exp_pane_extract_static, cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'dynamic_checkbox',
                self.param_handl_dynamic_chkbox.isSelected,
                lambda cv: self.param_handl_dynamic_chkbox.setSelected(cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'single_expression',
                lambda   : self.get_exp_pane_config(self.param_handl_exp_pane_extract_single    ),
                lambda cv: self.set_exp_pane_config(self.param_handl_exp_pane_extract_single, cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'issuer',
                lambda   : self.get_socket_pane_config(self.param_handl_issuer_socket_pane    ),
                lambda cv: self.set_socket_pane_config(self.param_handl_issuer_socket_pane, cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'single_request',
                lambda   : MainTab._cph.helpers.bytesToString(self.param_handl_request_editor.getMessage()),
                lambda cv: self.param_handl_request_editor.setMessage(MainTab._cph.helpers.stringToBytes(cv), True)
            ),
            SubTab.CONFIG_MECHANISM(
                'single_response',
                lambda   : MainTab._cph.helpers.bytesToString(self.param_handl_response_editor.getMessage()),
                lambda cv: self.param_handl_response_editor.setMessage(MainTab._cph.helpers.stringToBytes(cv), False)
            ),
            SubTab.CONFIG_MECHANISM(
                'macro_expression',
                lambda   : self.get_exp_pane_config(self.param_handl_exp_pane_extract_macro    ),
                lambda cv: self.set_exp_pane_config(self.param_handl_exp_pane_extract_macro, cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'cached_expression',
                lambda   : self.get_exp_pane_config(self.param_handl_exp_pane_extract_cached    ),
                lambda cv: self.set_exp_pane_config(self.param_handl_exp_pane_extract_cached, cv)
            ),
            SubTab.CONFIG_MECHANISM(
                'cached_selection',
                self.param_handl_combo_cached.getSelectedItem,
                lambda cv: self.param_handl_combo_cached.setSelectedItem(cv)
            ),
        ]

    def initialize_req_resp(self):
        return [], MainTab._cph.helpers.stringToBytes(''.join([' \r\n' for i in range(6)]))

    def create_expression_pane(self, label=None, multiline=True, checked=True, enabled=True):
        field = JTextArea()
        if not multiline:
            field = JTextField()
        field.setColumns(self.TXT_FIELD_SIZE)
        field.setFont(self.FIELD_FONT)
        field.addKeyListener(UndoableKeyListener(field))

        box = JCheckBox(self.REGEX, checked)
        if not enabled:
            box.setEnabled(False)

        child_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        child_pane.add(box)
        child_pane.add(field)

        parent_pane = JPanel(GridBagLayout())
        constraints = self.initialize_constraints()
        if label:
            parent_pane.add(JLabel(label), constraints)
            constraints.gridy += 1
        parent_pane.add(child_pane, constraints)

        return parent_pane

    def create_socket_pane(self):
        host_field = JTextField()
        host_field.setColumns(self.TXT_FIELD_SIZE)
        host_field.setText('host')
        host_field.setFont(self.FIELD_FONT)
        host_field.addKeyListener(UndoableKeyListener(host_field))

        port_spinner = JSpinner(SpinnerNumberModel(80, 1, 65535, 1))
        port_spinner.setFont(self.FIELD_FONT)
        port_spinner.setEditor(JSpinner.NumberEditor(port_spinner, '#'))

        socket_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        https_box = JCheckBox('HTTPS')
        https_box.setSelected(False)
        socket_pane.add(https_box   )
        socket_pane.add(host_field  )
        socket_pane.add(JLabel(':') )
        socket_pane.add(port_spinner)

        return socket_pane

    def get_exp_pane_component(self, pane, component_index):
        """
        component_index values:
        0: regex checkbox
        1: expression field
        See create_expression_pane() for further details
        """
        comp_count = pane.getComponentCount()
        if comp_count == 1:
            # then there's no label and child_pane is the only component
            child_pane = pane.getComponent(0)
        elif comp_count == 2:
            # then there is a label and child_pane is the second component
            child_pane = pane.getComponent(1)
        return child_pane.getComponent(component_index)

    def get_exp_pane_expression(self, pane):
        expression = self.get_exp_pane_component(pane, ConfigTab.TXT_FIELD_INDEX).getText()
        # If the RegEx checkbox is unchecked, run re.escape()
        # in order to treat it like a literal string.
        if not self.get_exp_pane_component(pane, ConfigTab.CHECKBOX_INDEX).isSelected():
            expression = re_escape(expression)
        return expression

    def get_exp_pane_config(self, pane):
        config = self.EXPRESSION_CONFIG(
            self.get_exp_pane_component(pane, ConfigTab.CHECKBOX_INDEX).isSelected(),
            self.get_exp_pane_component(pane, ConfigTab.TXT_FIELD_INDEX).getText()
        )
        return config

    def set_exp_pane_config(self, pane, config):
        config = self.EXPRESSION_CONFIG(*config)
        self.get_exp_pane_component(pane, ConfigTab.CHECKBOX_INDEX ).setSelected(config.is_regex  )
        self.get_exp_pane_component(pane, ConfigTab.TXT_FIELD_INDEX).setText    (config.expression)

    def get_socket_pane_component(self, pane, component_index):
        """
        indices_tuple values:
        0: https checkbox
        1: host field
        3: port spinner (2 is the ':' JLabel)
        See create_socket_pane() for further details
        """
        return pane.getComponent(component_index)

    def get_socket_pane_config(self, pane):
        config = self.SOCKET_CONFIG(
            self.get_socket_pane_component(pane, ConfigTab.HTTPS_INDEX).isSelected(),
            self.get_socket_pane_component(pane, ConfigTab.HOST_INDEX ).getText   (),
            self.get_socket_pane_component(pane, ConfigTab.PORT_INDEX ).getValue  ()
        )
        return config

    def set_socket_pane_config(self, pane, config):
        config = self.SOCKET_CONFIG(*config)
        self.get_socket_pane_component(pane, ConfigTab.HTTPS_INDEX).setSelected(config.https)
        self.get_socket_pane_component(pane, ConfigTab.HOST_INDEX ).setText    (config.host )
        self.get_socket_pane_component(pane, ConfigTab.PORT_INDEX ).setValue   (config.port )

    def build_msg_mod_pane(self, msg_mod_pane):
        msg_mod_req_or_resp_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        msg_mod_req_or_resp_pane.add(JLabel(self.MSG_MOD_TYPES_TO_MODIFY))
        msg_mod_req_or_resp_pane.add(self.msg_mod_combo_scope)
        msg_mod_req_or_resp_pane.add(self.msg_mod_combo_type)
        msg_mod_req_or_resp_pane.add(self.msg_mod_exp_pane_scope_lbl)

        constraints = self.initialize_constraints()
        msg_mod_pane.add(SubTab.set_title_font(JLabel(self.MSG_MOD_SCOPE_BURP)), constraints)
        constraints.gridy = 1
        msg_mod_pane.add(msg_mod_req_or_resp_pane, constraints)
        constraints.gridy = 2
        msg_mod_pane.add(self.msg_mod_exp_pane_scope, constraints)

    def build_param_handl_pane(self, param_derivation_pane):
        target_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        target_pane.add(SubTab.set_title_font(JLabel(self.PARAM_HANDL_TARGET)))
        target_pane.add(self.param_handl_combo_indices)
        target_pane.add(SubTab.set_title_font(JLabel(self.PARAM_HANDL_MATCH_RANGE)))

        self.param_handl_subset_pane.add(JLabel(self.PARAM_HANDL_MATCH_SUBSET))
        self.param_handl_subset_pane.add(self.param_handl_txtfield_match_indices)
        self.param_handl_subset_pane.add(self.param_handl_button_indices_help)
        self.param_handl_subset_pane.setVisible(False)

        derive_param_single_card = JPanel(GridBagLayout())
        constraints = self.initialize_constraints()
        derive_param_single_card.add(self.param_handl_issuer_socket_pane, constraints)
        constraints.gridy = 1
        issue_request_pane   = JPanel(FlowLayout(FlowLayout.LEADING))
        issue_request_button = JButton(self.PARAM_HANDL_BTN_ISSUE)
        issue_request_button.addActionListener(self)
        issue_request_pane.add(issue_request_button)
        issue_request_pane.add(JLabel(self.PARAM_HANDL_EXTRACT_SINGLE))
        derive_param_single_card.add(issue_request_pane, constraints)
        constraints.gridy = 2
        derive_param_single_card.add(self.param_handl_exp_pane_extract_single, constraints)
        constraints.gridy = 3
        constraints.gridwidth = 2
        splitpane = JSplitPane()
        splitpane.setLeftComponent (self.param_handl_request_editor .getComponent())
        splitpane.setRightComponent(self.param_handl_response_editor.getComponent())
        derive_param_single_card.add(splitpane, constraints)
        splitpane.setDividerLocation(0.5)

        derive_param_macro_card = JPanel(GridBagLayout())
        constraints = self.initialize_constraints()
        derive_param_macro_card.add(self.param_handl_exp_pane_extract_macro, constraints)

        cached_param_card = JPanel(GridBagLayout())
        constraints = self.initialize_constraints()
        tab_choice_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        tab_choice_pane.add(JLabel(self.PARAM_HANDL_EXTRACT_CACHED_PRE))
        tab_choice_pane.add(self.param_handl_combo_cached)
        tab_choice_pane.add(JLabel(self.PARAM_HANDL_EXTRACT_CACHED_POST))
        cached_param_card.add(tab_choice_pane, constraints)
        constraints.gridy = 1
        cached_param_card.add(self.param_handl_exp_pane_extract_cached, constraints)
        constraints.gridy = 2
        constraints.gridwidth = 2
        splitpane = JSplitPane()
        splitpane.setLeftComponent (self.param_handl_cached_req_viewer .getComponent())
        splitpane.setRightComponent(self.param_handl_cached_resp_viewer.getComponent())
        cached_param_card.add(splitpane, constraints)
        splitpane.setDividerLocation(0.5)

        self.param_handl_cardpanel_static_or_extract.add(derive_param_single_card, self.PARAM_HANDL_COMBO_EXTRACT_SINGLE)
        self.param_handl_cardpanel_static_or_extract.add(derive_param_macro_card , self.PARAM_HANDL_COMBO_EXTRACT_MACRO )
        self.param_handl_cardpanel_static_or_extract.add(cached_param_card       , self.PARAM_HANDL_COMBO_EXTRACT_CACHED)

        # Making a FlowLayout panel here so the combo box doesn't stretch.
        combo_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        combo_pane.add(self.param_handl_combo_extract)
        placeholder_btn = self.HelpButton()
        placeholder_btn.addActionListener(self)
        combo_pane.add(placeholder_btn)
        combo_pane.add(SubTab.create_blank_space())
        constraints = self.initialize_constraints()
        dyn_desc_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        dyn_desc_pane.add(SubTab.set_title_font(JLabel(self.PARAM_HANDL_DYNAMIC_DESCRIPTION)))
        dyn_desc_pane.add(self.param_handl_button_named_groups_help)
        self.param_handl_dynamic_pane.add(dyn_desc_pane, constraints)
        constraints.gridy = 1
        self.param_handl_dynamic_pane.add(combo_pane, constraints)
        constraints.gridy = 2
        constraints.gridwidth = GridBagConstraints.REMAINDER - 1
        self.param_handl_dynamic_pane.add(self.param_handl_cardpanel_static_or_extract, constraints)

        constraints = self.initialize_constraints()
        param_derivation_pane.add(self.param_handl_auto_encode_chkbox, constraints)
        constraints.gridy = 1
        param_derivation_pane.add(self.param_handl_enable_forwarder_chkbox, constraints)
        constraints.gridy = 2
        param_derivation_pane.add(self.param_handl_forwarder_socket_pane, constraints)
        constraints.gridy = 3
        param_derivation_pane.add(SubTab.set_title_font(JLabel(self.PARAM_HANDL_MATCH_EXP)), constraints)
        constraints.gridy = 4
        param_derivation_pane.add(self.param_handl_exp_pane_target, constraints)
        constraints.gridy = 5
        param_derivation_pane.add(target_pane, constraints)
        constraints.gridy = 6
        param_derivation_pane.add(self.param_handl_subset_pane, constraints)
        constraints.gridy = 7
        param_derivation_pane.add(SubTab.set_title_font(JLabel(self.PARAM_HANDL_ACTION)), constraints)
        constraints.gridy = 8
        param_derivation_pane.add(self.param_handl_exp_pane_extract_static, constraints)
        constraints.gridy = 9
        param_derivation_pane.add(self.param_handl_dynamic_chkbox, constraints)
        constraints.gridy = 10
        param_derivation_pane.add(self.param_handl_dynamic_pane, constraints)

    @staticmethod
    def restore_combo_cached_selection(tab, selected_item):
        tab.param_handl_combo_cached.setSelectedItem(selected_item)
        # If the item has been removed, remove selection.
        if tab.param_handl_combo_cached.getSelectedItem() != selected_item:
            tab.param_handl_combo_cached.setSelectedItem(None)
            if tab.param_handl_combo_extract.getSelectedItem() == ConfigTab.PARAM_HANDL_COMBO_EXTRACT_CACHED:
                MainTab.logger.warning(
                    'Selected cache no longer available for tab "{}"!'.format(tab.namepane_txtfield.getText())
                )

    @staticmethod
    def move_tab(tab, desired_index):
        # The Options tab is index 0, hence subtracting 1 in a number of lines below.
        if desired_index <= 0 or desired_index >= MainTab.mainpane.getTabCount() - 1:
            return

        MainTab.mainpane.setSelectedIndex(0)
        emv_sel_tab = MainTab.get_options_tab().emv_tab_pane.getSelectedComponent()
        current_index = MainTab.mainpane.indexOfComponent(tab)
        combo_cached_item = tab.param_handl_combo_cached.getSelectedItem()

        if current_index > desired_index:
            MainTab.mainpane.add(tab, desired_index)
            MainTab.get_options_tab().emv_tab_pane.add(tab.emv_tab, desired_index - 1)
            # Rearrange combo_cached appropriately.
            for i, other_tab in enumerate(MainTab.get_config_tabs()):
                if i < desired_index - 1:
                    continue
                selected_item = other_tab.param_handl_combo_cached.getSelectedItem()
                if i > desired_index - 1 and i <= current_index - 1:
                    tab.param_handl_combo_cached.removeItemAt(tab.param_handl_combo_cached.getItemCount() - 1)
                    other_tab.param_handl_combo_cached.insertItemAt(tab.namepane_txtfield.getText(), desired_index - 1)
                if i > current_index - 1:
                    other_tab.param_handl_combo_cached.removeItemAt(current_index - 1)
                    other_tab.param_handl_combo_cached.insertItemAt(tab.namepane_txtfield.getText(), desired_index - 1)
                ConfigTab.restore_combo_cached_selection(other_tab, selected_item)

        else:
            # I've no idea why +1 is needed here. =)
            MainTab.mainpane.add(tab, desired_index + 1)
            MainTab.get_options_tab().emv_tab_pane.add(tab.emv_tab, desired_index)
            # Rearrange combo_cached appropriately.
            for i, other_tab in enumerate(MainTab.get_config_tabs()):
                if i < current_index - 1:
                    continue
                selected_item = other_tab.param_handl_combo_cached.getSelectedItem()
                if i < desired_index - 1:
                    tab.param_handl_combo_cached.insertItemAt(other_tab.namepane_txtfield.getText(), i)
                    other_tab.param_handl_combo_cached.removeItemAt(current_index - 1)
                if i > desired_index - 1:
                    other_tab.param_handl_combo_cached.removeItemAt(current_index - 1)
                    other_tab.param_handl_combo_cached.insertItemAt(tab.namepane_txtfield.getText(), desired_index - 1)
                ConfigTab.restore_combo_cached_selection(other_tab, selected_item)

        MainTab.mainpane.setTabComponentAt(desired_index, tab.tabtitle_pane)
        MainTab.mainpane.setSelectedIndex (desired_index)
        MainTab.get_options_tab().emv_tab_pane.setTitleAt(
            desired_index - 1,
            tab.namepane_txtfield.getText()
        )
        MainTab.get_options_tab().emv_tab_pane.setSelectedComponent(emv_sel_tab)
        ConfigTab.restore_combo_cached_selection(tab, combo_cached_item)

    @staticmethod
    def move_tab_back(tab):
        desired_index = MainTab.mainpane.getSelectedIndex() - 1
        ConfigTab.move_tab(tab, desired_index)

    @staticmethod
    def move_tab_fwd(tab):
        desired_index = MainTab.mainpane.getSelectedIndex() + 1
        ConfigTab.move_tab(tab, desired_index)

    def clone_tab(self):
        desired_index = MainTab.mainpane.getSelectedIndex() + 1

        newtab = ConfigTab()
        MainTab.set_tab_name(newtab, self.namepane_txtfield.getText())
        config = MainTab.get_options_tab().prepare_to_save_tab(self)
        MainTab.get_options_tab().load_config({self.namepane_txtfield.getText(): config})

        ConfigTab.move_tab(newtab, desired_index)

    # def disable_cache_viewers(self):
        # self.cached_request, self.cached_response = self.initialize_req_resp()
        # self.param_handl_cached_req_viewer .setMessage(self.cached_request , False)
        # self.param_handl_cached_resp_viewer.setMessage(self.cached_response, False)

    # @staticmethod
    # def disable_all_cache_viewers():
        # for tab in MainTab.mainpane.getComponents():
            # if isinstance(tab, ConfigTab):
                # tab.disable_cache_viewers()

    def actionPerformed(self, e):
        c = e.getActionCommand()

        if c == self.BTN_HELP:
            source = e.getSource()
            if hasattr(source, 'title') and source.title:
                source.show_help()
            else:
                # The dynamic help button (placeholder_btn) has no title,
                # so use the selected combobox item to show the appropriate help message.
                extract_combo_selection = self.param_handl_combo_extract.getSelectedItem()
                if extract_combo_selection == self.PARAM_HANDL_COMBO_EXTRACT_SINGLE:
                    self.param_handl_button_extract_single_help.show_help()
                if extract_combo_selection == self.PARAM_HANDL_COMBO_EXTRACT_MACRO:
                    self.param_handl_button_extract_macro_help.show_help()
                if extract_combo_selection == self.PARAM_HANDL_COMBO_EXTRACT_CACHED:
                    self.param_handl_button_extract_cached_help.show_help()

        if c == 'comboBoxChanged':
            c = e.getSource().getSelectedItem()

        if c == self.MSG_MOD_COMBO_TYPE_RESP:
            self.param_handl_auto_encode_chkbox     .setVisible(False)
            self.param_handl_enable_forwarder_chkbox.setVisible(False)
            self.param_handl_forwarder_socket_pane  .setVisible(False)
        elif c == self.MSG_MOD_COMBO_TYPE_REQ or c == self.MSG_MOD_COMBO_TYPE_BOTH:
            self.param_handl_auto_encode_chkbox     .setVisible(True)
            self.param_handl_enable_forwarder_chkbox.setVisible(True)
            self.param_handl_forwarder_socket_pane  .setVisible(self.param_handl_enable_forwarder_chkbox.isSelected())

        if c == self.MSG_MOD_COMBO_SCOPE_ALL:
            self.msg_mod_exp_pane_scope_lbl.setVisible(False)
            self.msg_mod_exp_pane_scope.setVisible(False)
        if c == self.MSG_MOD_COMBO_SCOPE_SOME:
            self.msg_mod_exp_pane_scope_lbl.setVisible(True)
            self.msg_mod_exp_pane_scope.setVisible(True)

        if c == self.PARAM_HANDL_ENABLE_FORWARDER:
            self.param_handl_forwarder_socket_pane.setVisible(self.param_handl_enable_forwarder_chkbox.isSelected())

        if c == self.PARAM_HANDL_COMBO_INDICES_FIRST:
            self.param_handl_txtfield_match_indices.setEnabled(False)
            self.param_handl_txtfield_match_indices.setText('0')
            self.param_handl_subset_pane.setVisible(False)
        if c == self.PARAM_HANDL_COMBO_INDICES_EACH:
            self.param_handl_txtfield_match_indices.setEnabled(False)
            self.param_handl_txtfield_match_indices.setText('0:-1,-1')
            self.param_handl_subset_pane.setVisible(False)
        if c == self.PARAM_HANDL_COMBO_INDICES_SUBSET:
            self.param_handl_txtfield_match_indices.setEnabled(True)
            self.param_handl_subset_pane.setVisible(True)

        if c == self.PARAM_HANDL_DYNAMIC_CHECKBOX:
            is_selected = self.param_handl_dynamic_chkbox.isSelected()
            self.param_handl_dynamic_pane.setVisible(is_selected)

        if c in self.PARAM_HANDL_COMBO_EXTRACT_CHOICES:
            SubTab.show_card(self.param_handl_cardpanel_static_or_extract, c)

        # Set the cached request/response viewers to the selected tab's cache
        if e.getSource() == self.param_handl_combo_cached:
            if c is None:
                req, resp = self.initialize_req_resp()
            if c in MainTab.get_config_tab_names():
                req, resp = MainTab.get_config_tab_cache(c)
            self.param_handl_cached_req_viewer .setMessage(req , True)
            self.param_handl_cached_resp_viewer.setMessage(resp, False)

        if c == self.PARAM_HANDL_BTN_ISSUE:
            start_new_thread(MainTab._cph.issue_request, (self,))

        if c == self.BTN_BACK:
            ConfigTab.move_tab_back(self)
        if c == self.BTN_FWD:
            ConfigTab.move_tab_fwd(self)
        if c == self.BTN_CLONETAB:
            self.clone_tab()


class FlexibleCardLayout(CardLayout):
    def __init__(self):
        super(FlexibleCardLayout, self).__init__()

    def preferredLayoutSize(self, parent):
        current = FlexibleCardLayout.find_current_component(parent)
        if current:
            insets = parent.getInsets()
            pref = current.getPreferredSize()
            pref.width += insets.left + insets.right
            pref.height += insets.top + insets.bottom
            return pref
        return super.preferredLayoutSize(parent)

    @staticmethod
    def find_current_component(parent):
        for comp in parent.getComponents():
            if comp.isVisible():
                return comp
        return None

class BurpExtender(IBurpExtender, IContextMenuFactory, IExtensionStateListener, IHttpListener, ISessionHandlingAction):
    def __init__(self):
        self.messages_to_send = []
        self.final_macro_resp = ''

        self.logger = getLogger(__name__)
        self.initialize_logger()

        self.maintab = MainTab(self)

    def initialize_logger(self):
        fmt = '\n%(asctime)s:%(msecs)03d [%(levelname)s] %(message)s'
        datefmt = '%H:%M:%S'
        formatter = Formatter(fmt=fmt, datefmt=datefmt)

        handler = StreamHandler(stream=stdout)
        handler.setFormatter(formatter)

        self.logger.addHandler(handler)
        self.logger.setLevel(INFO)

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers   = callbacks.getHelpers()
        callbacks.setExtensionName('Custom Parameter Handler')
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.registerHttpListener(self)
        callbacks.registerSessionHandlingAction(self)
        callbacks.addSuiteTab(self.maintab)

    def getActionName(self):
        return 'CPH: extract replace value from the final macro response'

    def performAction(self, currentRequest, macroItems):
        if not macroItems:
            self.logger.error('No macro found, or macro is empty!')
            return
        self.final_macro_resp = self.helpers.bytesToString(macroItems[-1].getResponse())

    def createMenuItems(self, invocation):
        context = invocation.getInvocationContext()
        if context == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST \
        or context == invocation.CONTEXT_MESSAGE_VIEWER_REQUEST \
        or context == invocation.CONTEXT_PROXY_HISTORY          \
        or context == invocation.CONTEXT_TARGET_SITE_MAP_TABLE  \
        or context == invocation.CONTEXT_SEARCH_RESULTS:
            self.messages_to_send = invocation.getSelectedMessages()
            if len(self.messages_to_send):
                return [JMenuItem('Send to CPH', actionPerformed=self.send_to_cph)]
        else:
            return None

    def send_to_cph(self, e):
        self.maintab.add_config_tab(self.messages_to_send)

    def extensionUnloaded(self):
        if self.maintab.options_tab.httpd is not None:
            self.maintab.options_tab.httpd.shutdown()
            self.maintab.options_tab.httpd.server_close()
        try:
            while self.maintab.options_tab.emv_tab_pane.getTabCount():
                self.maintab.options_tab.emv_tab_pane.remove(
                    self.maintab.options_tab.emv_tab_pane.getTabCount() - 1
                )
            self.maintab.options_tab.emv.dispose()
        except AttributeError:
            self.logger.warning(
                'Effective Modification Viewer not found! You may be using an outdated version of CPH!'
            )

        while self.maintab.mainpane.getTabCount():
            # For some reason, the last tab isn't removed until the next loop,
            # hence the try/except block with just a continue. Thx, Java.
            try:
                self.maintab.mainpane.remove(
                    self.maintab.mainpane.getTabCount() - 1
                )
            except:
                continue

    def issue_request(self, tab):
        tab.request = tab.param_handl_request_editor.getMessage()

        issuer_config = tab.get_socket_pane_config(tab.param_handl_issuer_socket_pane)
        host  = issuer_config.host
        port  = issuer_config.port
        https = issuer_config.https

        tab.request = self.update_content_length(tab.request, True)
        tab.param_handl_request_editor.setMessage(tab.request, True)

        try:
            httpsvc = self.helpers.buildHttpService(host, port, https)
            response_bytes = self.callbacks.makeHttpRequest(httpsvc, tab.request).getResponse()
            self.logger.debug('Issued configured request from tab "{}" to host "{}:{}"'.format(
                tab.namepane_txtfield.getText(),
                httpsvc.getHost(),
                httpsvc.getPort()
            ))
            if response_bytes:
                tab.param_handl_response_editor.setMessage(response_bytes, False)
                tab.response = response_bytes
                self.logger.debug('Got response!')
        # Generic except because misc. Java exceptions might occur.
        except:
            self.logger.exception('Error issuing configured request from tab "{}" to host "{}:{}"'.format(
                tab.namepane_txtfield.getText(),
                host,
                port
            ))
            tab.response = self.helpers.stringToBytes('Error! See extension output for details.')
            tab.param_handl_response_editor.setMessage(tab.response, False)

    def update_content_length(self, message_bytes, is_request):
        if is_request:
            message_info = self.helpers.analyzeRequest(message_bytes)
        else:
            message_info = self.helpers.analyzeResponse(message_bytes)

        content_length = len(message_bytes) - message_info.getBodyOffset()
        msg_as_string = self.helpers.bytesToString(message_bytes)
        msg_as_string = re_sub(
            'Content-Length: \d+\r\n',
            'Content-Length: {}\r\n'.format(content_length),
            msg_as_string,
            1
        )
        return self.helpers.stringToBytes(msg_as_string)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        dbg_skip_tool = 'Skipping message received from {} on account of global tool scope options.'
        if toolFlag == self.callbacks.TOOL_PROXY:
            if not self.maintab.options_tab.chkbox_proxy.isSelected():
                self.logger.debug(dbg_skip_tool.format('Proxy'))
                return
        elif toolFlag == self.callbacks.TOOL_TARGET:
            if not self.maintab.options_tab.chkbox_target.isSelected():
                self.logger.debug(dbg_skip_tool.format('Target'))
                return
        elif toolFlag == self.callbacks.TOOL_SPIDER:
            if not self.maintab.options_tab.chkbox_spider.isSelected():
                self.logger.debug(dbg_skip_tool.format('Spider'))
                return
        elif toolFlag == self.callbacks.TOOL_REPEATER:
            if not self.maintab.options_tab.chkbox_repeater.isSelected():
                self.logger.debug(dbg_skip_tool.format('Repeater'))
                return
        elif toolFlag == self.callbacks.TOOL_SEQUENCER:
            if not self.maintab.options_tab.chkbox_sequencer.isSelected():
                self.logger.debug(dbg_skip_tool.format('Sequencer'))
                return
        elif toolFlag == self.callbacks.TOOL_INTRUDER:
            if not self.maintab.options_tab.chkbox_intruder.isSelected():
                self.logger.debug(dbg_skip_tool.format('Intruder'))
                return
        elif toolFlag == self.callbacks.TOOL_SCANNER:
            if not self.maintab.options_tab.chkbox_scanner.isSelected():
                self.logger.debug(dbg_skip_tool.format('Scanner'))
                return
        elif toolFlag == self.callbacks.TOOL_EXTENDER:
            if not self.maintab.options_tab.chkbox_extender.isSelected():
                self.logger.debug(dbg_skip_tool.format('Extender'))
                return
        else:
            self.logger.debug('Skipping message received from unsupported Burp tool.')
            return

        requestinfo = self.helpers.analyzeRequest(messageInfo)
        requesturl  = requestinfo.getUrl()

        if not self.callbacks.isInScope(requesturl):
            return

        # Leave these out of the 'if' statement; the 'else' needs req_as_string.
        request_bytes = messageInfo.getRequest()
        req_as_string = self.helpers.bytesToString(request_bytes)
        if messageIsRequest:
            original_req  = req_as_string
            for tab in self.maintab.get_config_tabs():
                if request_bytes == tab.request:
                    continue

                if tab.tabtitle_pane.enable_chkbox.isSelected() \
                and self.is_in_cph_scope(req_as_string, messageIsRequest, tab):

                    self.logger.info('Sending request to tab "{}" for modification'.format(
                        tab.namepane_txtfield.getText()
                    ))

                    req_as_string = self.modify_message(tab, req_as_string)
                    if req_as_string != original_req:
                        if tab.param_handl_auto_encode_chkbox.isSelected():
                            # URL-encode the first line of the request, since it was modified
                            first_req_line_old = req_as_string.split('\r\n')[0]
                            self.logger.debug('first_req_line_old:\n{}'.format(first_req_line_old))
                            first_req_line_old = first_req_line_old.split(' ')
                            first_req_line_new = '{} {} {}'.format(
                                first_req_line_old[0],
                                ''.join([quote(char, safe='/%+=?&') for char in '%20'.join(first_req_line_old[1:-1])]),
                                first_req_line_old[-1]
                            )
                            self.logger.debug('first_req_line_new:\n{}'.format(first_req_line_new))
                            req_as_string = req_as_string.replace(
                                ' '.join(first_req_line_old),
                                first_req_line_new
                            )
                            self.logger.debug('Resulting first line of request:\n{}'.format(
                                req_as_string.split('\r\n')[0]
                            ))

                        request_bytes = self.helpers.stringToBytes(req_as_string)

                    forwarder_config = tab.get_socket_pane_config(tab.param_handl_forwarder_socket_pane)
                    host  = forwarder_config.host
                    port  = forwarder_config.port
                    https = forwarder_config.https

                    # Need to update content-length.
                    request_bytes = self.update_content_length(request_bytes, messageIsRequest)
                    req_as_string = self.helpers.bytesToString(request_bytes)

                    if req_as_string != original_req:
                        tab.emv_tab.add_table_row(dt.now().time(), True, original_req, req_as_string)

                    if tab.param_handl_enable_forwarder_chkbox.isSelected():
                        try:
                            messageInfo.setHttpService(self.helpers.buildHttpService(host, int(port), https))
                            httpsvc = messageInfo.getHttpService()
                            self.logger.info('Tab "{}" is re-routing its request to "{}:{}"'.format(
                                tab.namepane_txtfield.getText(),
                                httpsvc.getHost(),
                                httpsvc.getPort()
                            ))
                        # Generic except because misc. Java exceptions might occur.
                        except:
                            self.logger.exception('Error re-routing request:')

            messageInfo.setRequest(request_bytes)

        if not messageIsRequest:
            response_bytes = messageInfo.getResponse()
            resp_as_string = self.helpers.bytesToString(response_bytes)
            original_resp  = resp_as_string

            for tab in self.maintab.get_config_tabs():
                if tab.tabtitle_pane.enable_chkbox.isSelected() \
                and self.is_in_cph_scope(resp_as_string, messageIsRequest, tab):

                    self.logger.info('Sending response to tab "{}" for modification'.format(
                        tab.namepane_txtfield.getText()
                    ))

                    resp_as_string = self.modify_message(tab, resp_as_string)
                    response_bytes = self.helpers.stringToBytes(resp_as_string)
                    response_bytes = self.update_content_length(response_bytes, messageIsRequest)
                    resp_as_string = self.helpers.bytesToString(response_bytes)

                    if resp_as_string != original_resp:
                        tab.emv_tab.add_table_row(dt.now().time(), False, original_resp, resp_as_string)

            messageInfo.setResponse(response_bytes)

            for working_tab in self.maintab.get_config_tabs():
                selected_item = working_tab.param_handl_combo_cached.getSelectedItem()
                if self.is_in_cph_scope(req_as_string , True , working_tab)\
                or self.is_in_cph_scope(resp_as_string, False, working_tab):
                    working_tab.cached_request  = request_bytes
                    working_tab.cached_response = response_bytes
                    self.logger.debug('Messages cached for tab {}!'.format(
                        working_tab.namepane_txtfield.getText()
                    ))
                # If this tab is set to extract a value from one of the previous tabs,
                # update its cached message panes with that tab's cached messages.
                for previous_tab in self.maintab.get_config_tabs():
                    if previous_tab == working_tab:
                        break
                    item = previous_tab.namepane_txtfield.getText()
                    if item == selected_item:
                        working_tab.param_handl_cached_req_viewer .setMessage(previous_tab.cached_request , True)
                        working_tab.param_handl_cached_resp_viewer.setMessage(previous_tab.cached_response, False)

    def is_in_cph_scope(self, msg_as_string, is_request, tab):
        rms_scope_all  = tab.msg_mod_combo_scope.getSelectedItem() == tab.MSG_MOD_COMBO_SCOPE_ALL
        rms_scope_some = tab.msg_mod_combo_scope.getSelectedItem() == tab.MSG_MOD_COMBO_SCOPE_SOME

        rms_type_requests  = tab.msg_mod_combo_type.getSelectedItem() == tab.MSG_MOD_COMBO_TYPE_REQ
        rms_type_responses = tab.msg_mod_combo_type.getSelectedItem() == tab.MSG_MOD_COMBO_TYPE_RESP
        rms_type_both      = tab.msg_mod_combo_type.getSelectedItem() == tab.MSG_MOD_COMBO_TYPE_BOTH

        rms_scope_exp = tab.get_exp_pane_expression(tab.msg_mod_exp_pane_scope)

        if is_request and (rms_type_requests or rms_type_both):
            pass
        elif not is_request and (rms_type_responses or rms_type_both):
            pass
        else:
            self.logger.debug('Preliminary scope check negative!')
            return False

        if rms_scope_all:
            return True
        elif rms_scope_some and rms_scope_exp:
            regexp = re_compile(rms_scope_exp)
            if regexp.search(msg_as_string):
                return True
        else:
            self.logger.warning('Scope restriction is active but no expression was specified. Skipping tab "{}".'.format(
                tab.namepane_txtfield.getText()
            ))
        return False

    def modify_message(self, tab, msg_as_string):
        ph_matchnum_txt = tab.param_handl_txtfield_match_indices.getText()

        ph_target_exp         = tab.get_exp_pane_expression(tab.param_handl_exp_pane_target        )
        ph_extract_static_exp = tab.get_exp_pane_expression(tab.param_handl_exp_pane_extract_static)
        ph_extract_single_exp = tab.get_exp_pane_expression(tab.param_handl_exp_pane_extract_single)
        ph_extract_macro_exp  = tab.get_exp_pane_expression(tab.param_handl_exp_pane_extract_macro )
        ph_extract_cached_exp = tab.get_exp_pane_expression(tab.param_handl_exp_pane_extract_cached)

        if not ph_target_exp:
            self.logger.warning(
                'No match expression specified! Skipping tab "{}".'.format(
                    tab.namepane_txtfield.getText()
                )
            )
            return msg_as_string

        exc_invalid_regex = 'Skipping tab "{}" due to error in expression {{}}: {{}}'.format(
            tab.namepane_txtfield.getText()
        )

        try:
            match_exp = re_compile(ph_target_exp)
        except re_error as e:
            self.logger.error(exc_invalid_regex.format(ph_target_exp, e))
            return msg_as_string

        # The following code does not remove support for groups,
        # as the original expression will be used for actual replacements.
        # We simply need an expression without capturing groups to feed into re.findall(),
        # which enables the logic for granular control over which match indices to target.

        # Removing named groups to normalize capturing groups.
        findall_exp = re_sub('\?P<.+?>', '', ph_target_exp)
        # Removing capturing groups to search for full matches only.
        findall_exp = re_sub(r'(?<!\\)\(([^?]*?)(?<!\\)\)', '\g<1>', findall_exp)
        findall_exp = re_compile(findall_exp)
        self.logger.debug('findall_exp: {}'.format(findall_exp.pattern))

        all_matches = re_findall(findall_exp, msg_as_string)
        self.logger.debug('all_matches: {}'.format(all_matches))

        match_count = len(all_matches)
        if not match_count:
            self.logger.warning(
                'Skipping tab "{}" because this expression found no matches: {}'.format(
                    tab.namepane_txtfield.getText(),
                    ph_target_exp
                )
            )
            return msg_as_string

        matches     = list()
        dyn_values  = ''
        replace_exp = ph_extract_static_exp

        if tab.param_handl_dynamic_chkbox.isSelected():
            find_exp, target_txt = '', ''
            selected_item = tab.param_handl_combo_extract.getSelectedItem()

            if selected_item == tab.PARAM_HANDL_COMBO_EXTRACT_CACHED:
                find_exp, target_txt = ph_extract_cached_exp, tab.param_handl_cached_resp_viewer.getMessage()
                target_txt = self.helpers.bytesToString(target_txt)

            elif selected_item == tab.PARAM_HANDL_COMBO_EXTRACT_SINGLE:
                self.issue_request(tab)
                find_exp, target_txt = ph_extract_single_exp, self.helpers.bytesToString(tab.response)

            elif selected_item == tab.PARAM_HANDL_COMBO_EXTRACT_MACRO:
                find_exp, target_txt = ph_extract_macro_exp, self.final_macro_resp

            if not find_exp:
                self.logger.warning(
                    'No dynamic value extraction expression specified! Skipping tab "{}".'.format(
                        tab.namepane_txtfield.getText()
                    )
                )
                return msg_as_string

            try:
                # Making a list to enable multiple iterations.
                matches = list(re_finditer(find_exp, target_txt))
                # 2025-11-20 start add by ZoranJi
                self.logger.warning("matches with index = %s",
                    [(i, m.group()) for i, m in enumerate(matches)]
                )
                #get last 
                #matches = matches[-1:]
                #get first
                matches = matches[:1]
                # 2025-11-20 end add by ZoranJi
            except re_error as e:
                self.logger.error(exc_invalid_regex.format(ph_extract_macro_exp, e))
                return msg_as_string

            if not matches:
                self.logger.warning('Skipping tab "{}" because this expression found no matches: {}'.format(
                    tab.namepane_txtfield.getText(),
                    find_exp
                ))
                return msg_as_string

            groups = {}
            groups_keys = groups.viewkeys()
            for match in matches:
                gd = match.groupdict()
                # The given expression should have unique group matches.
                for k in gd.keys():
                    if k in groups_keys:
                        self.logger.warning('Skipping tab "{}" because this expression found ambiguous matches: {}'.format(
                            tab.namepane_txtfield.getText(),
                            find_exp
                        ))
                        return msg_as_string
                groups.update(gd)

            # Remove '$' not preceded by '\'
            exp = re_sub(r'(?<!\\)\$', '', ph_target_exp)
            flags = re_match('\(\?[Limuxs]{1,6}\)', ph_target_exp)
            if flags is not None and 'x' in flags.group(0):
                exp += '\n'

            groups_exp = ''.join(['(?P<{}>{})'.format(group_name, group_match) for group_name, group_match in groups.items()])
            dyn_values = ''.join(groups.values())

            # No need for another try/except around this re.compile(),
            # as ph_target_exp was already checked when compiling match_exp earlier.
            # match_exp = re_compile(exp + groups_exp + end)
            match_exp = re_compile(exp + groups_exp)
            self.logger.debug('match_exp adjusted to:\n{}'.format(match_exp.pattern))

        subsets = ph_matchnum_txt.replace(' ', '').split(',')
        match_indices = []
        for subset in subsets:
            try:
                if ':' in subset:
                    sliceindex = subset.index(':')
                    start = int(subset[:sliceindex   ])
                    end   = int(subset[ sliceindex+1:])
                    if start < 0:
                        start = match_count + start
                    if end < 0:
                        end = match_count + end
                    for match_index in range(start, end):
                        match_indices.append(match_index)
                else:
                    match_index = int(subset)
                    if match_index < 0:
                        match_index = match_count + match_index
                    match_indices.append(match_index)
            except ValueError as e:
                self.logger.error(
                    'Ignoring invalid match index or slice on tab "{}" due to {}'.format(
                        tab.namepane_txtfield.getText(),
                        e
                    )
                )
                continue

        match_indices = set(sorted([m for m in match_indices if m < match_count]))
        self.logger.debug('match_indices: {}'.format(match_indices))

        # Using findall_exp to avoid including capture groups in the result.
        message_parts = re_split(findall_exp, msg_as_string)
        self.logger.debug('message_parts: {}'.format(message_parts))

        # The above strategy to use re.split() in order to enable the usage of match_indices
        # ends up breaking non-capturing groups. At this point, however, we can safely remove
        # all non-capturing groups and everything will be peachy.
        ncg_exp = re_compile('\(\?[^P].+?\)')
        if re_search(ncg_exp, match_exp.pattern) is not None:
            match_exp = re_compile(ncg_exp.sub('', match_exp.pattern))
            if flags is not None:
                match_exp = re_compile(flags.group(0) + match_exp.pattern)
            self.logger.debug('match_exp adjusted to:\n{}'.format(match_exp.pattern))

        modified_message  = ''
        remaining_indices = list(match_indices)
        for part_index, message_part in enumerate(message_parts):
            if remaining_indices and part_index == remaining_indices[0]:
                try:
                    final_value = match_exp.sub(replace_exp, all_matches[part_index] + dyn_values)
                except (re_error, IndexError) as e:
                    self.logger.error(exc_invalid_regex.format(match_exp.pattern + ' or expression ' + replace_exp, e))
                    return msg_as_string
                self.logger.debug('Found:\n{}\nreplaced using:\n{}\nin string:\n{}'.format(
                    match_exp.pattern,
                    replace_exp,
                    all_matches[part_index] + dyn_values
                ))
                final_value = message_part + final_value
                modified_message += final_value
                remaining_indices.pop(0)
            elif part_index < match_count:
                modified_message += message_part + all_matches[part_index]
            else:
                modified_message += message_part

        return modified_message

