Hi all,

here you can find a resource collection of MS Outlook plugins.
The plugins and scripts are intented to be used for the assp emailinterface report functions.

NOTICE: not a single one of these scripts and plugins is tested by the assp development. Be carefull!



For the following macros you have to first install redemption which can be found here  http://www.dimastr.com/redemption/
As of Dec-05-2016 the original resource is available at https://www.hmailserver.com/forum/viewtopic.php?t=3812

Notice: the target is to send the complete MIME-source of the original mail as an attachment to assp
  ASSP also accepts compressed attachment formats (eg. ZIP) with multiple .eml files in it - this seems not to be used in these macros.

spam reporting macro:----------------------------------------------- 
####################################################################

Sub ForwardToSpam() 

Dim objOL As Outlook.Application 
Dim objSelection As Outlook.Selection 
Dim objMsg As Object 
Dim objNewMsg As Object 

On Error Resume Next 

' Instantiate an Outlook Application object 
Set objOL = CreateObject("Outlook.Application") 
' Get the collection of selected objects 
Set objSelection = objOL.ActiveExplorer.Selection 
' This code sends the all of the selected mail items 
' one at a time. 
For Each objMsg In objSelection 
' This code sends one selected mail item at a time 
If objMsg.Class = olMail Then 
' Create a new mail item 
Set objNewMsg = Application.CreateItem(olMailItem) 
' send the new mail item to the spam reporting email address 
objNewMsg.To = "assp-spam@yourdomain.com" 
objNewMsg.Subject = objMsg.Subject 
'save the new mail before adding attachments 
objNewMsg.Save 
' add selected mail item as attachment to new mail item 
objNewMsg.Attachments.Add objMsg 
' send the new mail item 
Set objSafeMail = CreateObject("Redemption.SafeMailItem") 
objSafeMail.Item = objNewMsg 
objSafeMail.Send 


' Clear the New Mail Item object 
Set objNewMsg = Nothing 
' Delete the spam mail item 
objMsg.Delete 

End If 
Next 


Set objMsg = Nothing 
Set objSelection = Nothing 
Set objOL = Nothing 

Dim oBtn As CommandBarButton 
Set oBtn = Application.ActiveExplorer.CommandBars.FindControl(1, 5488) 
oBtn.Execute 
Set oBtn = Nothing 


MsgBox "Thank you for reporting spam!" 


End Sub 




Here is the macro to report misidentified ham or good email---------------------- 
#################################################################################

Sub ForwardToNotSpam() 

Dim objOL As Outlook.Application 
Dim objSelection As Outlook.Selection 
Dim objMsg As Object 
Dim objNewMsg As Object 

On Error Resume Next 

' Instantiate an Outlook Application object 
Set objOL = CreateObject("Outlook.Application") 
' Get the collection of selected objects 
Set objSelection = objOL.ActiveExplorer.Selection 

' This code sends the all of the selected mail items 
' one at a time. 
For Each objMsg In objSelection 
' This code sends one selected mail item at a time 
If objMsg.Class = olMail Then 
' Create a new mail item 
Set objNewMsg = Application.CreateItem(olMailItem) 
' send the new mail item to the spam reporting email address 
objNewMsg.To = "assp-notspam@yourdomain.com" 
objNewMsg.Subject = objMsg.Subject 
'save the new mail before adding attachments 
objNewMsg.Save 
' add selected mail item as attachment to new mail item 
objNewMsg.Attachments.Add objMsg 
' send the new mail item 
Set objSafeMail = CreateObject("Redemption.SafeMailItem") 
objSafeMail.Item = objNewMsg 
objSafeMail.Send 


' Clear the New Mail Item object 
Set objNewMsg = Nothing 


End If 
Next 


Set objMsg = Nothing 
Set objSelection = Nothing 
Set objOL = Nothing 

'send and receive 
Dim oBtn As CommandBarButton 
Set oBtn = Application.ActiveExplorer.CommandBars.FindControl(1, 5488) 
oBtn.Execute 
Set oBtn = Nothing 


MsgBox "Thank you for reporting misidentified spam. " 


End Sub 

------------------
The (https://www.hmailserver.com/forum) macros ends here


ASSP Outlook Ribbon Shortcuts 2013.pdf:
############################################################

This PDF document also contains some script examples for outlook.



olspamcop_3.0.4.exe:
############################################################

This application was developed by olspamcop.org (no longer available) as a SpamCop plugin for outlook.
It can be free configured and used. An FAQ and HOWTO should be implemented!

As of Dec-05-2016 an older webpage copy of olspamcop.org seems to be available at http://archive.is/olspamcop.org and/or http://archive.is/IJ0rG
