import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import base64
from .models import SMTPSetting  # Assuming your SMTP settings are stored in this model

class EmailSender:
    def send_email(self, subject, message, recipient_list):
        # Fetch the first SMTP settings object from the database
        smtp_settings = SMTPSetting.objects.first()

        # Compose the email
        msg = MIMEMultipart()
        msg['From'] = smtp_settings.sender_email
        msg['To'] = ", ".join(recipient_list)  # Convert recipient list to string
        msg['Subject'] = subject
        msg.attach(MIMEText(message, 'html'))

        # SMTP server configuration
        smtp_host = smtp_settings.smtp_server
        smtp_port = smtp_settings.smtp_port
        smtp_user = smtp_settings.smtp_username
        smtp_password = smtp_settings.smtp_password

        # Encode username and password for AUTH LOGIN
        encoded_user = base64.b64encode(smtp_user.encode()).decode()
        encoded_password = base64.b64encode(smtp_password.encode()).decode()

        try:
            # Establish connection to the SMTP server
            server = smtplib.SMTP(smtp_host, smtp_port)
            server.set_debuglevel(1)  # Debugging enabled for connection details
            server.ehlo()
            server.starttls()  # Secure connection
            server.ehlo()

            # Authenticate with the SMTP server
            server.docmd("AUTH LOGIN", encoded_user)
            server.docmd(encoded_password)

            # Send the email
            server.sendmail(msg['From'], recipient_list, msg.as_string())
            server.quit()

            # Log success
            logging.info("Email sent successfully")

        except smtplib.SMTPException as e:
            # Log any errors that occur
            logging.error(f"Failed to send email: {e}")
