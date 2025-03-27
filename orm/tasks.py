import random
import string
from orm.models import Action


def generate_temporary_password(length=8):
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for i in range(length))

import calendar
from django.utils import timezone
from django.template.loader import render_to_string
from orm.models import Action, ApprovalRequest, SMTPSetting
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import base64
from datetime import datetime
from django.utils import timezone
from django.template.loader import render_to_string
from orm.models import Action, ApprovalRequest, SMTPSetting
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import logging
import base64
from datetime import datetime

def get_greek_month_year():
    greek_months = [
        "Ιανουάριος", "Φεβρουάριος", "Μάρτιος", "Απρίλιος", "Μάιος", "Ιούνιος",
        "Ιούλιος", "Αύγουστος", "Σεπτέμβριος", "Οκτώβριος", "Νοέμβριος", "Δεκέμβριος"
    ]
    current_date = timezone.now()
    return f"{greek_months[current_date.month - 1]} {current_date.year}"

def send_email(subject, message, recipient_list, bcc=None):
    smtp_settings = SMTPSetting.objects.first()
    if not smtp_settings:
        logging.error("SMTP settings not configured.")
        return

    msg = MIMEMultipart()
    msg['From'] = smtp_settings.sender_email
    msg['To'] = ', '.join(recipient_list)
    msg['Subject'] = subject
    msg['Date'] = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S +0000")

    if bcc:
        msg['Bcc'] = ', '.join(bcc)
        recipient_list += bcc

    msg.attach(MIMEText(message, 'html'))

    try:
        server = smtplib.SMTP(smtp_settings.smtp_server, smtp_settings.smtp_port)
        server.ehlo()
        server.starttls()
        server.ehlo()

        encoded_user = base64.b64encode(smtp_settings.smtp_username.encode()).decode()
        encoded_password = base64.b64encode(smtp_settings.smtp_password.encode()).decode()

        server.docmd("AUTH LOGIN", encoded_user)
        server.docmd(encoded_password)

        server.sendmail(msg['From'], recipient_list, msg.as_string())
        server.quit()
        logging.info(f"Email sent to {', '.join(recipient_list)}")
    except smtplib.SMTPException as e:
        logging.error(f"Failed to send email: {e}")

def send_pending_approvals_and_actions():
    smtp_settings = SMTPSetting.objects.first()
    admin_email = smtp_settings.admin_email if smtp_settings else None

    today = timezone.now().date()
    pending_approvals = ApprovalRequest.objects.filter(status='pending')
    pending_actions = Action.objects.filter(status='pending')

    approvals_by_user = {}

    for approval in pending_approvals:
        user = approval.user
        approvals_by_user.setdefault(user, {'approvals': [], 'actions_performer': [], 'actions_owner': []})
        approvals_by_user[user]['approvals'].append(approval)

    for action in pending_actions:
        if action.performer:
            approvals_by_user.setdefault(action.performer, {'approvals': [], 'actions_performer': [], 'actions_owner': []})
            approvals_by_user[action.performer]['actions_performer'].append(action)

        if action.owner:
            approvals_by_user.setdefault(action.owner, {'approvals': [], 'actions_performer': [], 'actions_owner': []})
            approvals_by_user[action.owner]['actions_owner'].append(action)

    email_count = 0

    for user, items in approvals_by_user.items():
        approval_links = [
            {
                'url': f"http://ermapp.avax.gr/risk/{a.risk.id}/",
                'risk_title': a.risk.title,
                'due_date': a.due_date,
                'days_until_due': (a.due_date - today).days if a.due_date else None
            }
            for a in items['approvals']
        ]
        action_performer_links = [
            {
                'title': a.title,
                'url': f"http://ermapp.avax.gr/action_detail/{a.id}/",
                'deadline': a.deadline,
                'days_until_deadline': (a.deadline - today).days if a.deadline else None
            }
            for a in items['actions_performer']
        ]
        action_owner_links = [
            {
                'title': a.title,
                'url': f"http://ermapp.avax.gr/action_detail/{a.id}/",
                'deadline': a.deadline,
                'days_until_deadline': (a.deadline - today).days if a.deadline else None
            }
            for a in items['actions_owner']
        ]

        totals = {
            "approvals": {
                "total": len(approval_links),
                "overdue": sum(1 for a in approval_links if a['days_until_due'] is not None and a['days_until_due'] < 0),
                "future": sum(1 for a in approval_links if a['days_until_due'] is not None and a['days_until_due'] >= 0),
            },
            "performer": {
                "total": len(action_performer_links),
                "overdue": sum(1 for a in action_performer_links if a['days_until_deadline'] is not None and a['days_until_deadline'] < 0),
                "future": sum(1 for a in action_performer_links if a['days_until_deadline'] is not None and a['days_until_deadline'] >= 0),
            },
            "owner": {
                "total": len(action_owner_links),
                "overdue": sum(1 for a in action_owner_links if a['days_until_deadline'] is not None and a['days_until_deadline'] < 0),
                "future": sum(1 for a in action_owner_links if a['days_until_deadline'] is not None and a['days_until_deadline'] >= 0),
            },
        }

        context = {
            'user': user.user.email,
            'approval_links': approval_links,
            'action_performer_links': action_performer_links,
            'action_owner_links': action_owner_links,
            'totals': totals,
        }

        email_body = render_to_string('emails/pending_approvals_and_actions.html', context)
        subject = f'Ενημέρωση Κατάστασης ermapp.avax.gr - {get_greek_month_year()}'
        send_email(subject, email_body, [user.user.email], bcc=[admin_email] if admin_email else [])
        email_count += 1

    print(f"{email_count} emails sent.")
