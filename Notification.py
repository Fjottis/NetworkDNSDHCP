# For the notification notifications
import os  # Pour Mac
from plyer import notification  # Pour Windows
# For the emails
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from sys import platform


def notify(title, text):
    path = '/home/theman/Documents/NetworkDNSDHCP'
    if platform == 'darwin':
        os.system("""
              osascript -e 'display notification "{}" with title "{}"'
              """.format(text, title))
    elif platform == 'win32':
        notification.notify(
            title=title,
            message=text,
            timeout=10,
            app_icon=path + "/icons/warning-icon.ico"
        )
    elif platform == 'linux':
        notification.notify(
            title=title,
            message=text,
            timeout=10,
            app_icon=path + "/icons/warning-icon.png"
        )
    else:
        print("OS Platform not recognized")


def mail(receiver, sujet, content):
    sender = ''
    password = ''
    server = 'smtp.gmail.com'
    port = 465
    server = smtplib.SMTP_SSL(server, port)
    server.login(sender, password)
    message = MIMEMultipart()

    message['From'] = sender
    message['To'] = receiver
    message['Subject'] = sujet

    message.attach(MIMEText(content, 'plain'))
    server.send_message(message)
    server.quit()


if __name__ == '__main__':
    mail('dnsdhcp@gmail.com', 'TestPython', 'This is the test :')
