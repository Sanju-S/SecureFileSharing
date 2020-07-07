import smtplib
from string import Template
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

MY_ADDRESS = "securefilesharingteam@gmail.com"
PASSWORD = "secure@123"


def read_template():
    content = """Dear ${PERSON_NAME},

Thank you for using Secure File Sharing.
Please share the following link with the intended recipient only : 
http://127.0.0.1:8000/get/${FILE_ID}/${LINK}/

If you don't want to send it on your own then you can send it directly via SFS anytime, it is as secure as always.

Thank You.

Team SFS."""
    return Template(content)


def read_temp():
    content = """Dear User,

You just received a file '${FILE_NAME}' from ${PERSON_NAME}.
You can download it by clicking on the following link:-
http://127.0.0.1:8000/get/${FILE_ID}/${LINK}/

Please do not share this link with anyone else.

Thank You.

Team SFS."""

    return Template(content)


def send_mail(user, file_id, key):
    name = str(user.username)
    email = str(user.email)
    msg_temp = read_template()

    s = smtplib.SMTP(host='smtp.gmail.com', port=587)
    s.starttls()
    s.login(MY_ADDRESS, PASSWORD)

    msg = MIMEMultipart()
    mesg = msg_temp.substitute(PERSON_NAME=name.title(), FILE_ID=file_id, LINK=key)

    msg['From'] = MY_ADDRESS
    msg['To'] = email
    msg['Subject'] = "Secure Link for the File"

    msg.attach(MIMEText(mesg, 'plain'))

    s.send_message(msg)
    del msg

    s.quit()


def send_mail_other(username, email, file_name, file_id, key):
    msg_temp = read_temp()

    s = smtplib.SMTP(host='smtp.gmail.com', port=587)
    s.starttls()
    s.login(MY_ADDRESS, PASSWORD)

    msg = MIMEMultipart()
    mesg = msg_temp.substitute(FILE_NAME=file_name, PERSON_NAME=username, FILE_ID=file_id, LINK=key)

    msg['From'] = MY_ADDRESS
    msg['To'] = email
    msg['Subject'] = "You received a file from Secure File Sharing"

    msg.attach(MIMEText(mesg, 'plain'))

    s.send_message(msg)
    del msg

    s.quit()
