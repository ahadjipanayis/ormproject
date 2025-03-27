import random
import string

def generate_temporary_password(length=8):
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for i in range(length))

import smtplib
import base64
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from .models import SMTPSetting  # Ensure this model is imported correctly

def send_email(subject, message, recipient_list, bcc=None):
    smtp_settings = SMTPSetting.objects.first()

    if not smtp_settings:
        logging.error("SMTP settings are not configured.")
        return

    msg = MIMEMultipart()
    msg['From'] = smtp_settings.sender_email
    msg['To'] = ', '.join(recipient_list)
    msg['Subject'] = subject

    # Add BCC recipients
    if bcc:
        msg['Bcc'] = ', '.join(bcc)
        recipient_list += bcc  # Ensure BCC recipients receive the email

    # Attach the HTML message
    msg.attach(MIMEText(message, 'html'))

    # SMTP server configuration
    smtp_host = smtp_settings.smtp_server
    smtp_port = smtp_settings.smtp_port
    smtp_user = smtp_settings.smtp_username
    smtp_password = smtp_settings.smtp_password

    # Encode username and password in Base64
    encoded_user = base64.b64encode(smtp_user.encode()).decode()
    encoded_password = base64.b64encode(smtp_password.encode()).decode()

    try:
        # Connect to the SMTP server
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.set_debuglevel(1)  # Enable debug output
        server.ehlo()
        server.starttls()  # Secure the connection
        server.ehlo()

        # Perform AUTH LOGIN manually
        server.docmd("AUTH LOGIN", encoded_user)
        server.docmd(encoded_password)

        # Send the email
        server.sendmail(msg['From'], recipient_list, msg.as_string())
        server.quit()
        logging.info(f"Email sent successfully to {', '.join(recipient_list)}")
    except smtplib.SMTPException as e:
        logging.error(f"Failed to send email: {e}")