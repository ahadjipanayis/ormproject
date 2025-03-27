from django.core.management.base import BaseCommand
from django.utils import timezone
from orm.models import Risk, ApprovalRequest, UserProfile
import logging

class Command(BaseCommand):
    help = 'Manage approval requests: create missing requests for current owners and delete requests for removed owners.'

    def handle(self, *args, **kwargs):
        # Counters to keep track of created and deleted approval requests
        created_count = 0
        deleted_count = 0

        # Get all risks
        risks = Risk.objects.all()

        for risk in risks:
            # Step 1: Ensure all current owners have an approval request for this risk
            for owner in risk.owners.all():
                try:
                    # Check if at least one approval request exists for this risk and this owner
                    existing_approval_request = ApprovalRequest.objects.filter(risk=risk, user=owner).exists()

                    if not existing_approval_request:
                        # No approval request exists for this owner and this risk, so create one
                        approval_request = ApprovalRequest.objects.create(
                            risk=risk,
                            user=owner,  # The owner is a UserProfile instance
                            status='pending',
                            due_date=timezone.now().date()  # Set the due date to today
                        )

                        # Output the details to the terminal
                        self.stdout.write(
                            self.style.SUCCESS(f"Created approval request for risk '{risk.title}' for owner '{owner.user.email}' with due date today.")
                        )
                        created_count += 1  # Increment the counter
                    else:
                        # Output if an approval request already exists
                        self.stdout.write(
                            self.style.WARNING(f"Approval request already exists for risk '{risk.title}' and owner '{owner.user.email}'")
                        )

                except UserProfile.DoesNotExist:
                    # Output error in case owner doesn't exist
                    self.stdout.write(
                        self.style.ERROR(f"No UserProfile found for owner with email '{owner.user.email}'")
                    )

            # Step 2: Remove approval requests for users who are no longer owners of this risk
            approval_requests = ApprovalRequest.objects.filter(risk=risk)
            for approval_request in approval_requests:
                if approval_request.user not in risk.owners.all():
                    approval_request.delete()
                    deleted_count += 1  # Increment the counter

                    # Output the details to the terminal
                    self.stdout.write(
                        self.style.SUCCESS(f"Deleted approval request for risk '{risk.title}' for removed owner '{approval_request.user.user.email}'.")
                    )

        # Final message once all risks are processed
        self.stdout.write(self.style.SUCCESS(
            f"Finished managing approval requests. Total created: {created_count}, Total deleted: {deleted_count}"))
