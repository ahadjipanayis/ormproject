from django.utils.timezone import now
from orm.models import ApprovalRequest, Action, SMTPSetting
from django.template.loader import render_to_string
from django.core.mail import send_mail
from datetime import date

def send_pending_approvals_and_actions():
    today = now().date()

    # Group pending approvals and actions
    approvals = ApprovalRequest.objects.filter(status='pending').select_related('risk', 'user')
    actions = Action.objects.filter(status='pending').select_related('owner', 'performer')

    # Group by user
    user_data = {}

    for approval in approvals:
        user = approval.user
        if user not in user_data:
            user_data[user] = {"approvals": [], "performer_actions": [], "owner_actions": []}
        days_until = (approval.due_date - today).days if approval.due_date else None
        user_data[user]["approvals"].append({
            "risk_title": approval.risk.title,
            "due_date": approval.due_date,
            "days_until_due": days_until,
            "url": f"http://ermapp.avax.gr/risk/{approval.risk.id}/"
        })

    for action in actions:
        if action.performer:
            user = action.performer
            if user not in user_data:
                user_data[user] = {"approvals": [], "performer_actions": [], "owner_actions": []}
            days_until = (action.deadline - today).days if action.deadline else None
            user_data[user]["performer_actions"].append({
                "title": action.title,
                "deadline": action.deadline,
                "days_until_deadline": days_until,
                "url": f"http://ermapp.avax.gr/action/{action.id}/"
            })

        if action.owner:
            user = action.owner
            if user not in user_data:
                user_data[user] = {"approvals": [], "performer_actions": [], "owner_actions": []}
            days_until = (action.deadline - today).days if action.deadline else None
            user_data[user]["owner_actions"].append({
                "title": action.title,
                "deadline": action.deadline,
                "days_until_deadline": days_until,
                "url": f"http://ermapp.avax.gr/action/{action.id}/"
            })

    # Get SMTP admin for BCC
    smtp_settings = SMTPSetting.objects.first()
    admin_email = smtp_settings.admin_email if smtp_settings else None

    for user, data in user_data.items():
        approval_links = data["approvals"]
        performer_links = data["performer_actions"]
        owner_links = data["owner_actions"]

        # Accurate per-user totals
        totals = {
            "approvals": {
                "total": len(approval_links),
                "overdue": sum(1 for a in approval_links if a["days_until_due"] is not None and a["days_until_due"] < 0),
                "future": sum(1 for a in approval_links if a["days_until_due"] is not None and a["days_until_due"] >= 0),
            },
            "performer": {
                "total": len(performer_links),
                "overdue": sum(1 for a in performer_links if a["days_until_deadline"] is not None and a["days_until_deadline"] < 0),
                "future": sum(1 for a in performer_links if a["days_until_deadline"] is not None and a["days_until_deadline"] >= 0),
            },
            "owner": {
                "total": len(owner_links),
                "overdue": sum(1 for a in owner_links if a["days_until_deadline"] is not None and a["days_until_deadline"] < 0),
                "future": sum(1 for a in owner_links if a["days_until_deadline"] is not None and a["days_until_deadline"] >= 0),
            },
        }

        context = {
            "user": user.user.email,
            "approval_links": approval_links,
            "action_performer_links": performer_links,
            "action_owner_links": owner_links,
            "totals": totals,
        }

        # DEBUG OUTPUT
        print(f"\n📧 Email to {user.user.email}")
        print(f"✅ Approvals: {totals['approvals']}")
        print(f"✅ Performer Actions: {totals['performer']}")
        print(f"✅ Owner Actions: {totals['owner']}")

        # Render email
        html_message = render_to_string('emails/pending_approvals_and_actions.html', context)

        # Save for inspection
        with open(f"debug_email_{user.username}.html", "w", encoding="utf-8") as f:
            f.write(html_message)

        # Send the email
        send_mail(
            subject="Pending Approvals and Actions",
            message="Please view this email in HTML format.",
            from_email="from@example.com",
            recipient_list=[user.user.email],
            html_message=html_message,
            bcc=[admin_email] if admin_email else None
        )


import logging
from django.core.management.base import BaseCommand
from orm.tasks import send_pending_approvals_and_actions

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Send emails for pending approval requests and actions'

    def handle(self, *args, **kwargs):
        try:
            send_pending_approvals_and_actions()
            self.stdout.write(self.style.SUCCESS('Pending approvals and actions emails sent successfully.'))
            logger.info("Pending approvals and actions emails sent successfully.")
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error: {e}'))
            logger.error(f"Error executing command: {e}")