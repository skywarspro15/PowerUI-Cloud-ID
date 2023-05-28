Attribute VB_Name = "CloudID"
Function CreateAccount(username As String, password As String) As String
    Dim req As New ServerXMLHTTP60
    Dim url As String
    Dim payload As String
    Dim payloadObject As New Scripting.Dictionary
    Dim parsed As Scripting.Dictionary
    
    
    url = "https://powerui-cloud-id.skywarspro15.repl.co/signup"
    payloadObject.Add "username", username
    payloadObject.Add "password", password
    
    payload = JsonConverter.ConvertToJson(payloadObject)
    req.Open "POST", url, True
    req.setRequestHeader "Content-Type", "application/json"
    req.send payload
    
    Do Until req.readyState = 4
        DoEvents
    Loop
    
    CreateAccount = req.responseText
End Function

Function GetUserToken(username As String, password As String, Optional twoFA As String = "000000") As String
    Dim req As New ServerXMLHTTP60
    Dim url As String
    Dim payload As String
    Dim payloadObject As New Scripting.Dictionary
    Dim parsed As Scripting.Dictionary
    
    url = "https://powerui-cloud-id.skywarspro15.repl.co/login"
    payloadObject.Add "username", username
    payloadObject.Add "password", password
    payloadObject.Add "code", twoFA
    
    payload = JsonConverter.ConvertToJson(payloadObject)
    
    req.Open "POST", url, True
    req.setRequestHeader "Content-Type", "application/json"
    req.send payload
    
    Do Until req.readyState = 4
        DoEvents
    Loop
    
    If req.status = 200 Then
        Set parsed = JsonConverter.ParseJson(req.responseText)
        GetUserToken = parsed("token")
    Else
        GetUserToken = req.responseText
    End If
End Function

Function SetUserStatus(token As String, status As String) As String
    Dim req As New ServerXMLHTTP60
    Dim url As String
    Dim payload As String
    Dim payloadObject As New Scripting.Dictionary
    
    url = "https://powerui-cloud-id.skywarspro15.repl.co/status"
    
    payloadObject.Add "status", status
    
    payload = JsonConverter.ConvertToJson(payloadObject)
    
    req.Open "POST", url, True
    req.setRequestHeader "Content-Type", "application/json"
    req.setRequestHeader "Authorization", "Bearer " & token
    req.send payload
    
    Do Until req.readyState = 4
        DoEvents
    Loop
    
    SetUserStatus = req.responseText
End Function

Function Get2faQR(token As String, imgShp As Shape) As String
    Dim req As New ServerXMLHTTP60
    Dim reqStream As Object
    Dim url As String
    
    url = "https://powerui-cloud-id.skywarspro15.repl.co/getQR"
    
    req.Open "GET", url, True
    req.setRequestHeader "Content-Type", "application/json"
    req.setRequestHeader "Authorization", "Bearer " & token
    req.send
    
    Do Until req.readyState = 4
        DoEvents
    Loop
    
    If Dir("C:\PowerUIDesktop\", vbDirectory) = "" Then
        MkDir ("C:\PowerUIDesktop")
    End If
    
    If Dir("C:\PowerUIDesktop\CloudID\", vbDirectory) = "" Then
        MkDir ("C:\PowerUIDesktop\CloudID")
    End If
    
    If req.status = 200 Then
        Set reqStream = CreateObject("ADODB.Stream")
        reqStream.Open
        reqStream.Type = 1
        reqStream.Write req.responseBody
        reqStream.SaveToFile "C:\PowerUIDesktop\CloudID\qr.png", 2
        reqStream.Close
    End If
    
    imgShp.Fill.UserPicture "C:\PowerUIDesktop\CloudID\qr.png"
    Kill "C:\PowerUIDesktop\CloudID\qr.png"
    
    Exit Function
End Function

Function Change2faStatus(token As String, code As String, enabled As Boolean) As String
    Dim req As New ServerXMLHTTP60
    Dim url As String
    Dim payload As String
    Dim payloadObject As New Scripting.Dictionary
    
    url = "https://powerui-cloud-id.skywarspro15.repl.co/change2fa"
    
    payloadObject.Add "enabled", enabled
    payloadObject.Add "code", code
    
    payload = JsonConverter.ConvertToJson(payloadObject)
    
    req.Open "POST", url, True
    req.setRequestHeader "Content-Type", "application/json"
    req.setRequestHeader "Authorization", "Bearer " & token
    req.send payload
    
    Do Until req.readyState = 4
        DoEvents
    Loop
    
    Change2faStatus = req.responseText
    
End Function

Function GetUserInfo(token As String) As String
    Dim req As New ServerXMLHTTP60
    Dim url As String
    
    url = "https://powerui-cloud-id.skywarspro15.repl.co/getUser"
    
    req.Open "GET", url, True
    req.setRequestHeader "Authorization", "Bearer " & token
    req.send status
    
    Do Until req.readyState = 4
        DoEvents
    Loop
    
    GetUserInfo = req.responseText
End Function


