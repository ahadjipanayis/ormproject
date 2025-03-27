import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import base64
from orm.models import SMTPSetting

# Set up logging
logging.basicConfig(level=logging.DEBUG)

def send_email(subject, message, recipient_list, bcc=None):
    # Fetch SMTP settings from the database (or settings)
    smtp_settings = SMTPSetting.objects.first()
    
    if not smtp_settings:
        logging.error("SMTP settings are not configured.")
        return
    
    msg = MIMEMultipart()
    msg['From'] = smtp_settings.sender_email
    msg['To'] = ', '.join(recipient_list)
    msg['Subject'] = subject
    
    # Add BCC recipients, if provided
    if bcc:
        msg['Bcc'] = ', '.join(bcc)
        recipient_list += bcc  # Ensure BCC recipients receive the email

    # Attach the HTML message body
    msg.attach(MIMEText(message, 'html'))

    # Extract SMTP server configuration
    smtp_host = smtp_settings.smtp_server
    smtp_port = smtp_settings.smtp_port
    smtp_user = smtp_settings.smtp_username
    smtp_password = smtp_settings.smtp_password

    # Encode SMTP credentials in Base64 for AUTH LOGIN
    encoded_user = base64.b64encode(smtp_user.encode()).decode()
    encoded_password = base64.b64encode(smtp_password.encode()).decode()

    try:
        # Connect to the SMTP server
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.set_debuglevel(1)  # Enable debug output for troubleshooting
        server.ehlo()
        server.starttls()  # Secure the connection
        server.ehlo()

        # Perform AUTH LOGIN
        server.docmd("AUTH LOGIN", encoded_user)
        server.docmd(encoded_password)

        # Send the email
        server.sendmail(msg['From'], recipient_list, msg.as_string())
        server.quit()
        
        logging.info(f"Email sent successfully to {', '.join(recipient_list)}")
    except smtplib.SMTPException as e:
        logging.error(f"SMTP Exception: Failed to send email: {e}")
    except Exception as e:
        logging.error(f"General Exception: Failed to send email: {e}")