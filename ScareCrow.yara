// Copyright 2021 Optiv Security, Inc.
import "pe"

rule HackTool_ScareCrow
{
   meta:
      description = "Basic detection for ScareCrow" 
      rev = 2
      author = "Optiv"
   strings:
      $go1 = "go.buildid" ascii wide
      $go2 = "Go build ID:" ascii wide
      $str1 = "kernelbase.dll"
      $str2 = "kernel32.dll"
      $str3 = "ntdll.dll"
   condition:
      uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10MB and all of ($go*) and all of ($str*) and
         pe.version_info["CompanyName"] contains "Microsoft Corporation" and
         (
         pe.version_info["FileDescription"] contains "Microsoft Excel" or
         pe.version_info["FileDescription"] contains "Microsoft Word" or
         pe.version_info["FileDescription"] contains "Microsoft PowerPoint" or
         pe.version_info["FileDescription"] contains "Microsoft Outlook" or
         pe.version_info["FileDescription"] contains "Skype for Business" or
         pe.version_info["FileDescription"] contains "Windows Command Processor" or
         pe.version_info["FileDescription"] contains "Microsoft OneDrive" or
         pe.version_info["FileDescription"] contains "Application Compatibility Client Library" or
         pe.version_info["FileDescription"] contains "Windows Cryptographic Primitives Library" or
         pe.version_info["FileDescription"] contains "Configuration Manager DLL" or
         pe.version_info["FileDescription"] contains "Microsoft COM for Windows" or
         pe.version_info["FileDescription"] contains "Cryptographic Service Provider API" or
         pe.version_info["FileDescription"] contains "DNS Client API DLL" or
         pe.version_info["FileDescription"] contains "Data Protection API" or
         pe.version_info["FileDescription"] contains "Host for SCM/SDDL/LSA Lookup APIs" or
         pe.version_info["FileDescription"] contains "TLS / SSL Security Provider" or
         pe.version_info["FileDescription"] contains "OLE32 Extensions for Win32" or
         pe.version_info["FileDescription"] contains "Win32u" or
         pe.version_info["FileDescription"] contains "Shell Application Manager" or
         pe.version_info["FileDescription"] contains "Bluetooth Control Panel Applet" or
         pe.version_info["FileDescription"] contains "Desktop Settings Control Panel" or
         pe.version_info["FileDescription"] contains "Windows Defender Firewall Control Panel DLL Launching Stub" or
         pe.version_info["FileDescription"] contains " Adobe Flash Player Control Panel Applet" or
         pe.version_info["FileDescription"] contains "Add Hardware Control Panel Applet" or
         pe.version_info["FileDescription"] contains "Internet Control Panel" or
         pe.version_info["FileDescription"] contains "Control Panel DLL" or
         pe.version_info["FileDescription"] contains "Infrared Control Panel Applet" or
         pe.version_info["FileDescription"] contains "Game Controllers Control Panel Applet" or
         pe.version_info["FileDescription"] contains "Mouse and Keyboard Control Panel Applets" or
         pe.version_info["FileDescription"] contains "Audio Control Panel" or
         pe.version_info["FileDescription"] contains "Network Connections Control-Panel Stub" or
         pe.version_info["FileDescription"] contains "Power Management Configuration Control Panel Applet" or
         pe.version_info["FileDescription"] contains "Speech UX Control Panel" or
         pe.version_info["FileDescription"] contains "System Applet for the Control Panel" or
         pe.version_info["FileDescription"] contains "Tablet PC Control Panel" or
         pe.version_info["FileDescription"] contains "Telephony Control Panel" or
         pe.version_info["FileDescription"] contains "Time Date Control Panel Applet" or
         pe.version_info["FileDescription"] contains "Security and Maintenance" or
         pe.version_info["FileDescription"] contains "Timesheet ToolPak" or
         pe.version_info["FileDescription"] contains "Report ToolPak" or
         pe.version_info["FileDescription"] contains "Zoom Addon ToolPak" or
         pe.version_info["FileDescription"] contains "Microsoft Update ToolPak" or
         pe.version_info["FileDescription"] contains "Calendar ToolPak" or
         pe.version_info["FileDescription"] contains "Memo ToolPak" or
         pe.version_info["FileDescription"] contains "Office Desktop ToolPak" or
         pe.version_info["FileDescription"] contains "Application Installer ToolPak"
         )
}
