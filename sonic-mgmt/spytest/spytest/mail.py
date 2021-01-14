import os
import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders

def send(server, to, subject, body, filenames=[], html=False, preamble="Report", cc=[], bcc=[]):

    # ensure we have some address to send
    if not to:
        if not cc:
            if not bcc:
                return
            to = bcc
        else:
            to = cc

    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = server["sendor"]
    msg['To'] = ",".join(to)
    msg['CC'] = ",".join(cc)
    msg['BCC'] = ",".join(bcc)
    msg.preamble = preamble

    if html:
        msg.attach(MIMEText(body, 'html'))
    else:
        msg.attach(MIMEText(body, 'plain'))

    for filename in filenames:
      fp = open(filename, 'rb')
      img = MIMEBase("application", "octet-stream")
      img.set_payload(fp.read())
      fp.close()
      encoders.encode_base64(img)
      basename = os.path.basename(filename)
      img.add_header('Content-Disposition', 'attachment', filename=basename)
      msg.attach(img)

    s = smtplib.SMTP(host=server["host"])
    s.sendmail(msg["From"], msg['To'].split(","), msg.as_string())
    s.quit()

