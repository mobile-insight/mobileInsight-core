#!/usr/bin/python3

"""
Python GUI for MobileInsight
Author: Moustafa Alzantot
Date : Feb 26, 2016
"""

import sys
import wx
import wx.grid
import wx.adv
from threading import Thread
from random import random
from datetime import datetime, timedelta

import matplotlib
from matplotlib.backends.backend_wxagg import FigureCanvasWxAgg as FigureCanvas
# from matplotlib.backends.backend_wx import NavigationToolbar2Wx, wxc
from matplotlib.backends.backend_wx import NavigationToolbar2Wx
from matplotlib.figure import Figure

import xml.dom.minidom
import xml.etree.ElementTree as ET

from mobile_insight.analyzer import LogAnalyzer
from mobile_insight.monitor.dm_collector.dm_endec.dm_log_packet import DMLogPacket

ID_FILE_OPEN = wx.NewId()
ID_FILE_EXIT = wx.NewId()
ID_TB_OPEN = wx.NewId()
ID_TB_FILTER = wx.NewId()
ID_TB_SEARCH = wx.NewId()
ID_TB_TIME = wx.NewId()
ID_TB_RESET = wx.NewId()
ID_TB_GRAPH = wx.NewId()
EVT_RESULT_ID = wx.NewId()


def EVT_RESULT(win, func):
    win.Connect(-1, -1, EVT_RESULT_ID, func)


class ResultEvent(wx.PyEvent):
    def __init__(self, data):
        wx.PyEvent.__init__(self)
        self.SetEventType(EVT_RESULT_ID)
        self.data = data


class ProgressDialog(wx.Dialog):
    def __init__(self, parent):
        wx.Dialog.__init__(self, parent, -1, style=wx.NO_BORDER)
        mainSizer = wx.BoxSizer(wx.VERTICAL)
        anim = wx.adv.Animation("icons/loading.gif")
        gif = wx.adv.AnimationCtrl(self, -1, anim, size=(-1, -1))
        # gif = wx.adv.AnimationCtrl(self, pos=(0, 0), size=(-1, -1))
        gif.Play()

        mainSizer.Add(gif, wx.EXPAND | wx.ALL)
        self.SetSizer(mainSizer)
        self.Fit()


class TimeWindowDialog(wx.Dialog):
    def __init__(self, parent, start_time, end_time):
        wx.Dialog.__init__(self, parent, -1)
        sizer = wx.BoxSizer(wx.VERTICAL)
        self.SetTitle("Time Window")
        self.start_label = wx.StaticText(self, -1, label="...", style=wx.BOLD)
        self.end_label = wx.StaticText(self, -1, label="...", style=wx.BOLD)
        self.window_label = wx.StaticText(self, -1, "\t to \t")
        # self.start_label.SetFont(wx.Font(11, wx.DEFAULT, wx.BOLD, wx.NORMAL))
        # self.window_label.SetFont(wx.Font(11, wx.DEFAULT, wx.ITALIC, wx.NORMAL))
        # self.end_label.SetFont(wx.Font(11, wx.DEFAULT, wx.BOLD, wx.NORMAL))

        self.start_label.SetFont(wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_SLANT, wx.FONTWEIGHT_NORMAL))
        self.window_label.SetFont(wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_ITALIC, wx.FONTWEIGHT_NORMAL))
        self.end_label.SetFont(wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_SLANT, wx.FONTWEIGHT_NORMAL))

        labelSizer = wx.BoxSizer(wx.HORIZONTAL)
        labelSizer.Add(self.start_label, 0, wx.ALL | wx.EXPAND, 3)
        labelSizer.Add(self.window_label, wx.ALL, 1)
        labelSizer.Add(self.end_label, 0, wx.ALL | wx.EXPAND, 3)

        self.btns = self.CreateSeparatedButtonSizer(wx.OK | wx.CANCEL)
        start_sizer = wx.BoxSizer(wx.HORIZONTAL)
        start_sizer.Add(wx.StaticText(self, -1, "Start: "), 0, wx.ALL, 1)
        self.start_slider = wx.Slider(
            self, -1, 0, 0, 100, wx.DefaultPosition, (250, -1), wx.SL_HORIZONTAL)
        start_sizer.Add(self.start_slider, 0, wx.ALL | wx.EXPAND, 5)
        self.Bind(wx.EVT_SLIDER, self.start_slider_update, self.start_slider)

        end_sizer = wx.BoxSizer(wx.HORIZONTAL)
        end_sizer.Add(wx.StaticText(self, -1, "End: "), 0, wx.ALL, 1)
        self.end_slider = wx.Slider(
            self, -1, 100, 0, 100, wx.DefaultPosition, (250, -1), wx.SL_HORIZONTAL)
        end_sizer.Add(self.end_slider, 0, wx.ALL | wx.EXPAND, 5)
        self.Bind(wx.EVT_SLIDER, self.end_slider_udpate, self.end_slider)

        self.start_time = start_time
        self.cur_end = end_time
        self.cur_start = self.start_time
        self.unit_seconds = (end_time - start_time).total_seconds() / 100.0

        self.updateUI()
        sizer.Add(labelSizer, 0, wx.ALL | wx.EXPAND, 5)
        sizer.Add(start_sizer, 0, wx.ALL | wx.EXPAND, 5)
        sizer.Add(end_sizer, 0, wx.ALL | wx.EXPAND, 5)
        sizer.Add(self.btns, 0, wx.ALL | wx.EXPAND, 5)
        self.SetSizer(sizer)
        self.Fit()

    def start_slider_update(self, event):
        delta_seconds = self.start_slider.GetValue() * self.unit_seconds
        self.cur_start = self.start_time + \
                         timedelta(seconds=int(delta_seconds))
        self.updateUI()

    def end_slider_udpate(self, event):
        delta_seconds = self.end_slider.GetValue() * self.unit_seconds
        self.cur_end = self.start_time + timedelta(seconds=int(delta_seconds))
        self.updateUI()

    def updateUI(self):
        self.start_label.SetLabel(format("%s" % (self.cur_start)))
        self.end_label.SetLabel(format("%s" % (self.cur_end)))


class MyMCD(wx.Dialog):
    def __init__(self, parent, message, caption, choices=[]):
        wx.Dialog.__init__(self, parent, -1)
        self.SetTitle(caption)
        sizer = wx.BoxSizer(wx.VERTICAL)
        self.message = wx.StaticText(self, -1, message)
        self.clb = wx.CheckListBox(self, -1, choices=choices)
        self.chbox = wx.CheckBox(self, -1, 'Select all')
        self.btns = self.CreateSeparatedButtonSizer(wx.OK | wx.CANCEL)
        self.Bind(wx.EVT_CHECKBOX, self.EvtChBox, self.chbox)

        sizer.Add(self.message, 0, wx.ALL | wx.EXPAND, 5)
        sizer.Add(self.clb, 1, wx.ALL | wx.EXPAND, 5)
        sizer.Add(self.chbox, 0, wx.ALL | wx.EXPAND, 5)
        sizer.Add(self.btns, 0, wx.ALL | wx.EXPAND, 5)
        self.SetSizer(sizer)
        # self.Fit()

    def GetSelections(self):
        return self.clb.GetChecked()

    def EvtChBox(self, event):
        state = self.chbox.IsChecked()
        for i in range(self.clb.GetCount()):
            self.clb.Check(i, state)


class WindowClass(wx.Frame):

    def __init__(self, *args, **kwargs):
        super(WindowClass, self).__init__(*args, **kwargs)

        self.min_time = datetime.strptime("3000 Jan 1", '%Y %b %d')
        self.max_time = datetime.strptime("1900 Jan 1", '%Y %b %d')
        self.selectedTypes = None  # Message Filters
        self.basicGUI()

    def basicGUI(self):

        self._log_analyzer = LogAnalyzer(self.OnReadComplete)
        menuBar = wx.MenuBar()
        fileButton = wx.Menu()
        editButton = wx.Menu()

        openItem = fileButton.Append(ID_FILE_OPEN, "Open", "Open log file")
        exitItem = fileButton.Append(ID_FILE_EXIT, "Exit", "Exit application")

        menuBar.Append(fileButton, 'File')
        menuBar.Append(editButton, "Edit")
        self.SetMenuBar(menuBar)

        self.Bind(wx.EVT_MENU, self.Quit, exitItem)
        self.Bind(wx.EVT_MENU, self.Open, openItem)

        # Toolbar
        self.toolbar = self.CreateToolBar(
            wx.TB_FLAT | wx.TB_TEXT | wx.TB_HORIZONTAL | wx.NO_BORDER)

        toolbar_open = self.toolbar.AddLabelTool(
            ID_TB_OPEN, "Open", wx.Bitmap("/usr/local/share/mobileinsight/icons/open.png"))
        self.toolbar.AddSeparator()
        toolbar_filter = self.toolbar.AddLabelTool(
            ID_TB_FILTER, "Filter", wx.Bitmap("/usr/local/share/mobileinsight/icons/filter.png"))
        self.toolbar.AddSeparator()
        toolbar_search = self.toolbar.AddLabelTool(
            ID_TB_SEARCH, "Search", wx.Bitmap("/usr/local/share/mobileinsight/icons/search.png"))
        self.toolbar.AddSeparator()
        toolbar_time = self.toolbar.AddLabelTool(
            ID_TB_TIME, "Time Window", wx.Bitmap("/usr/local/share/mobileinsight/icons/time.png"))
        self.toolbar.AddSeparator()
        toolbar_reset = self.toolbar.AddLabelTool(
            ID_TB_RESET, "Reset", wx.Bitmap("/usr/local/share/mobileinsight/icons/reset.png"))
        # self.toolbar.AddSeparator()
        # toolbar_graph = self.toolbar.AddLabelTool(ID_TB_GRAPH, "Graph", wx.Bitmap("/usr/local/share/mobileinsight/icons/graph.png"))
        self.toolbar.AddSeparator()
        toolbar_about = self.toolbar.AddLabelTool(
            ID_TB_GRAPH, "About", wx.Bitmap("/usr/local/share/mobileinsight/icons/about.png"))

        self.Bind(wx.EVT_TOOL, self.Open, toolbar_open)
        self.Bind(wx.EVT_TOOL, self.OnFilter, toolbar_filter)
        self.Bind(wx.EVT_TOOL, self.OnSearch, toolbar_search)
        self.Bind(wx.EVT_TOOL, self.OnTime, toolbar_time)
        self.Bind(wx.EVT_TOOL, self.OnReset, toolbar_reset)
        # self.Bind(wx.EVT_TOOL, self.OnGraph, toolbar_graph)
        self.Bind(wx.EVT_TOOL, self.OnAbout, toolbar_about)
        self.toolbar.Realize()

        # Main Panel
        panel = wx.Panel(self, -1, size=(-1, -1), style=wx.BORDER_RAISED)
        mainSizer = wx.BoxSizer(wx.HORIZONTAL)

        hbox = wx.BoxSizer(wx.HORIZONTAL)
        self.grid = wx.grid.Grid(panel)
        self.grid.CreateGrid(50, 2)
        self.grid.SetSelectionMode(1)  # 1 is Select Row

        self.grid.Bind(wx.grid.EVT_GRID_SELECT_CELL, self.OnGridSelect)
        self.grid.SetColLabelValue(0, "Timestamp")
        self.grid.SetColLabelValue(1, "Type ID")

        hbox.Add(self.grid, 5, wx.EXPAND | wx.ALL, 10)

        leftPanel = wx.Panel(panel, -1, size=(-1, -1), style=wx.BORDER_RAISED)

        leftbox = wx.BoxSizer(wx.VERTICAL)
        self.status_text = wx.StaticText(
            leftPanel,
            label="Welcome to MobileInsight 6.0 beta!\n\nMobileInsight is a Python 3 package for mobile network monitoring and analysis on the end device.",
            style=wx.ALIGN_LEFT)
        #self.details_text = wx.TextCtrl(leftPanel, style=wx.ALIGN_LEFT | wx.TE_MULTILINE)
        self.details_text = wx.TreeCtrl(leftPanel, style=wx.TR_DEFAULT_STYLE | wx.TR_LINES_AT_ROOT)

        leftbox.Add(self.status_text, 1, wx.EXPAND | wx.HORIZONTAL)
        leftbox.Add(self.details_text, 3, wx.EXPAND)

        leftPanel.SetSizer(leftbox)
        hbox.Add(leftPanel, 4, wx.EXPAND | wx.ALL, 10)
        self.grid.SetColSize(0, 200)
        self.grid.SetColSize(1, 300)
        self.grid.ForceRefresh()

        panel.SetSizer(hbox)

        mainSizer.Add(panel, 1, wx.EXPAND, 0)
        self.SetSizer(mainSizer)
        self.statusbar = self.CreateStatusBar()
        self.Bind(wx.EVT_CLOSE, self.Quit)
        self.SetTitle("MobileInsight")
        self.SetSize((1200, 800))
        self.Centre()
        self.Show(True)

        self.data = None

        EVT_RESULT(self, self.OnResult)

    def OnResult(self, event):
        if self.progressDialog:
            self.progressDialog.EndModal(wx.ID_CANCEL)
            self.progressDialog.Destroy()

        data = event.data
        if data:
            self.statusbar.SetStatusText("Read %d logs" % len(data))
            self.data = data
            self.data_view = self.data
            self.SetupGrid()

    def Open(self, e):
        openFileDialog = wx.FileDialog(
            self,
            "Open Log file",
            "",
            "",
            "log files (*.mi2log) |*.mi2log| All files |*.*",
            wx.FD_OPEN | wx.FD_FILE_MUST_EXIST | wx.FD_MULTIPLE)
        if (openFileDialog.ShowModal() == wx.ID_OK):
            # print 'Selected %s' %openFileDialog.GetPath()
            print(('Selected %s' % openFileDialog.Paths))
            try:
                self.grid.ClearGrid()

                # thread.start_new_thread(openFile,(openFileDialog.GetPath(),))
                # t = Thread(target = self.openFile, args=(openFileDialog.GetPath(),self.selectedTypes))
                t = Thread(
                    target=self.openFile,
                    args=(
                        openFileDialog.Paths,
                        self.selectedTypes))
                self.progressDialog = ProgressDialog(self)
                t.start()
                self.progressDialog.ShowModal()

                if len(openFileDialog.Paths) == 1:
                    self.SetTitle(openFileDialog.GetPath())
                else:
                    self.SetTitle(
                        "Multiple files in " +
                        openFileDialog.Directory)

            except e:
                print(("Error while opening file.", e))
            # if (random() > 0.5):
            #    self.SetupGrid(self.data1)
            # else:
            #    self.SetupGrid(self.data2)

    def OnFilter(self, e):
        types = list(self._log_analyzer.supported_types)
        checkboxDialog = MyMCD(self, "Filter", "", types)
        if (checkboxDialog.ShowModal() == wx.ID_OK):
            self.selectedTypes = [types[x]
                                  for x in checkboxDialog.GetSelections()]
            if self.data:
                self.data_view = [
                    x for x in self.data if x["TypeID"] in self.selectedTypes]
                self.SetupGrid()

    def OnTime(self, e):
        timewindowDialog = TimeWindowDialog(self, self.min_time, self.max_time)
        if (timewindowDialog.ShowModal() == wx.ID_OK):
            select_start = timewindowDialog.cur_start
            select_end = timewindowDialog.cur_end
            self.data_view = [
                x for x in self.data_view if datetime.strptime(
                    x["Timestamp"],
                    '%Y-%m-%d  %H:%M:%S.%f') >= select_start and datetime.strptime(
                    x["Timestamp"],
                    '%Y-%m-%d  %H:%M:%S.%f') <= select_end]
            self.SetupGrid()

    def OnReset(self, e):
        if self.data:
            self.data_view = self.data
            self.SetupGrid()

    # def openFile(self, filePath,selectedTypes):
    #     self._log_analyzer.AnalyzeFile(filePath,selectedTypes)

    def openFile(self, Paths, selectedTypes):
        self._log_analyzer.AnalyzeFile(Paths, selectedTypes)

    def OnSearch(self, e):
        search_dlg = wx.TextEntryDialog(
            self, "Search for", "", "", style=wx.OK | wx.CANCEL)
        if (search_dlg.ShowModal() == wx.ID_OK):
            keyword = search_dlg.GetValue()
            self.data_view = [
                x for x in self.data_view if keyword in x["Payload"]]
            self.SetupGrid()
        search_dlg.Destroy()

    def OnAbout(self, e):
        about_text = (
                'MobileInsight GUI\n\n\n' +
                'Copyright (c) 2014-2016 MobileInsight Team\n\n' +
                'Developers:\n    Moustafa Alzantot,\n' +
                '    Priyanka Avinash Kachare,\n' +
                '    Michael Ivan,\n' +
                '    Yuanjie Li')
        search_dlg = wx.MessageDialog(
            self, about_text, "About MobileInsight GUI", wx.OK)
        search_dlg.ShowModal()

    def OnGridSelect(self, e):
        # self.statusbar.SetStatusText("Selected %d" %e.GetRow())
        row = e.GetRow()
        if (row < len(self.data_view)):
            self.status_text.SetLabel(
                "Time Stamp : %s    Type : %s" %
                (str(
                    self.data_view[row]["Timestamp"]), str(
                    self.data_view[row]["TypeID"])))
            #self.details_text.SetValue(str(self.data_view[row]["Payload"]))
            
            #val = xml.dom.minidom.parseString(
             #   str(self.data_view[row]["Payload"]))
            #pretty_xml_as_string = val.toprettyxml(indent="  ", newl="\n", encoding="utf8")  # maybe will trigger bug
            #self.details_text.SetValue(pretty_xml_as_string)
            
            self.content = {}
            r = ET.fromstring(str(self.data_view[row]["Payload"]))
            print(r.tag)
            for child in r:
                k = child.get("key")
                if child.get("type")=="list" and len(child)==0:
                    self.content[k]={}
                elif child.get("type") == "list" and child[0].tag == "list":
                    list_content = self.parse_list(child, k)
                    self.content[k] = list_content
                elif child.get("type") == "list" and child[0].tag == "msg":  # xml from wireshark
                    list_content = self.parse_msg(child)
                    self.content[k] = list_content
                    # print(str(list_content))
                elif child.get("type")=="dict":
                    self.content[k]=self.parse_dict(child)
                else:
                    self.content[k] = child.text
            self.details_text.DeleteAllItems()
            root = self.details_text.AddRoot('payload')
            self.creat_tree(self.content,root)
            self.details_text.ExpandAll()
            
        e.Skip()

    def parse_list(self, listroot, attrib_key):
        '''
        convert list from .xml to standard dict
        :param listroot:
        :param attrib_key:
        :return: dict
        '''
        list_content = {}
        if(len(listroot)==0):
            return None
        listroot = listroot[0];  # <pair key="CA Combos" type="list">   <list>
        i = 0
        for xml_list in listroot:
            if xml_list.tag == "item" and xml_list.get("type") == "dict":  # The only subclass of list is dict
                dist_content = self.parse_dict(xml_list)
                if(xml_list.get("key")==None):
                    list_content[attrib_key + "[" + str(i) + "]"] = dist_content 
                    i += 1
                else:
                    list_content[xml_list.get("key")]=dist_content 
        return list_content

    def parse_dict(self, dictroot):
        '''
        convert dict from .xml to standard dict
        :param dictroot:
        :return:
        '''
        dictroot = dictroot[0]  # <item type="dict">  <dict>
        dict_content = {}
        for d in dictroot:
            k = d.get("key")
            if (d.get("type") == "list"):  # list in dist
                list_content = self.parse_list(d, k)
                dict_content[k] = list_content
            elif (d.get("type")=="dict"):
                list_content = self.parse_dict(d)
                dict_content[k] = list_content
            else:
                dict_content[k] = d.text;  # key-value
        return dict_content

    def split_key_value(self,str):
        '''
        e.g. "a:b"->"a","b"
        :param str:
        :return:
        '''
        start=str.find(":")
        if(start!=-1):
            key=str[0:start]
            val=str[start+1:]
            return key ,val
        else:
            return str,"none"
    def parse_msg(self, msgroot):
        '''
        parse xml file which is conveyed by wireshark
        :param msgroot:
        :return:
        '''
        proto = msgroot.findall(".//proto")
        dict_msg = {}
        skip_context=["geninfo","frame","user_dlt"]#proto which is useless
        for p in proto:
            if (p.get("hide") != "yes" and p.get("name") not in skip_context):
                dict_msg.update(self.parse_msg_field(p))
            else:
                continue
        return dict_msg

    def parse_msg_field(self, msgroot):
        msg_dict={}
        #skip_context=["geninfo","frame","user_dlt"]
        for field in msgroot:
            if (field.get("hide") == "yes"):
                continue
            elif len(field) != 0 and field.get("showname")!=None:
                k=field.get("showname")
                k,_=self.split_key_value(k)
                val_dict = self.parse_msg_field(field)
                if len(val_dict)==0:
                    msg_dict[k]="skip"
                else:
                    msg_dict[k]=val_dict
            elif len(field)!=0:
                msg_dict.update(self.parse_msg_field(field))
            else:
                dict_msg = field.get("showname")
                if dict_msg !=None:
                    k, v = self.split_key_value(dict_msg)
                    msg_dict[k] = v
        return msg_dict

    def creat_tree(self,payload_dict,root):
        for k,v in payload_dict.items():
            if(isinstance(v,dict)):
                subroot=self.details_text.AppendItem(root,str(k))
                self.creat_tree(v,subroot)
            else:
                if(v!="skip"):
                    self. details_text.AppendItem(root,str(k)+":"+str(v))
                else:
                    self.details_text.AppendItem(root,str(k))
                    

    def Quit(self, e):
        self.Destroy()

    def OnReadComplete(self):
        evt = ResultEvent(self._log_analyzer.msg_logs)
        wx.PostEvent(wx.GetApp().frame, evt)

    def SetupGrid(self):
        self.min_time = datetime.strptime("3000 Jan 1", '%Y %b %d')
        self.max_time = datetime.strptime("1900 Jan 1", '%Y %b %d')

        n = len(self.data_view)
        # self.grid.CreateGrid(max(25, n), 2)
        if n > self.grid.GetNumberRows():
            self.grid.InsertRows(0, n - self.grid.GetNumberRows())
        else:
            self.grid.DeleteRows(0, self.grid.GetNumberRows() - n)

        self.grid.ClearGrid()
        self.grid.SetColLabelValue(0, "Timestamp")
        self.grid.SetColLabelValue(1, "Type ID")
        for i in range(n):
            try:
                cur_time = datetime.strptime(
                    self.data_view[i]["Timestamp"],
                    '%Y-%m-%d  %H:%M:%S.%f')
            except Exception as e:
                cur_time = datetime.strptime(
                    self.data_view[i]["Timestamp"], '%Y-%m-%d  %H:%M:%S')
            self.min_time = min(self.min_time, cur_time)
            self.max_time = max(self.max_time, cur_time)
            self.grid.SetCellValue(i, 0, str(self.data_view[i]["Timestamp"]))
            self.grid.SetCellValue(i, 1, str(self.data_view[i]["TypeID"]))
            self.grid.SetReadOnly(i, 0)
            self.grid.SetReadOnly(i, 1)
        # self.grid.Bind(wx.grid.EVT_GRID_CELL_LEFT_CLICK, self.onRowClick)


def main():
    wx.Log.SetLogLevel(0)
    app = wx.App()
    app.frame = WindowClass(None)
    app.MainLoop()


main()
