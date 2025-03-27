
from django.core.management.base import BaseCommand
from orm.services import fetch_sanction_list_data, validate_counterparties_against_sanctions

class Command(BaseCommand):
    help = "Check counterparties against the sanctions list"

    def handle(self, *args, **kwargs):
        api_url = "https://api.opensanctions.org/match/default"
        api_key = "YOUR_API_KEY"  # Replace with your actual API key
        try:
            self.stdout.write("Fetching sanctions data...")
            sanctions_data = fetch_sanction_list_data(api_url, api_key)
            self.stdout.write("Validating counterparties...")
            validate_counterparties_against_sanctions(sanctions_data)
            self.stdout.write("Sanction check completed successfully.")
        except Exception as e:
            self.stderr.write(f"Error during sanction check: {e}")
