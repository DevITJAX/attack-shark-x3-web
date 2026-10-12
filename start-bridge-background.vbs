Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "c:\Users\XEON\Desktop\attacksharkx3-web"
WshShell.Run """C:\Users\XEON\AppData\Local\Python\pythoncore-3.14-64\pythonw.exe"" ""c:\Users\XEON\Desktop\attacksharkx3-web\server.py""", 0, False
Set WshShell = Nothing
