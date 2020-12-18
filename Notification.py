# For the notification notifications
import os  # Pour Mac
from plyer import notification  # Pour Windows
# For the emails
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def notify(title, text, ostype="Mac"):
    if ostype == "Mac":
        os.system("""
              osascript -e 'display notification "{}" with title "{}"'
              """.format(text, title))
    elif ostype == "Windows":
        notification.notify(
            title=title,
            message=text,
            timeout=10,
            app_icon="./icons/warning-icon.ico"
        )
    elif ostype == "Unix":
        notification.notify(
            title=title,
            message=text,
            timeout=10,
            app_icon="./icons/warning-icon.png"
        )


def mail(receiver, sujet, content):

    server = 'smtp.gmail.com'
    port = 465
    server = smtplib.SMTP_SSL(server, port)
    server.login(sender, mdp)
    message = MIMEMultipart()

    message['From'] = sender
    message['To'] = receiver
    message['Subject'] = sujet

    message.attach(MIMEText(content, 'plain'))
    server.send_message(message)
    server.quit()


if __name__ == '__main__':
    mail('dnsdhcp@gmail.com', 'TestPython', 'This is the test :')
