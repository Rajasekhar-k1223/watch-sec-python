import stripe
import logging
import os
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger("MeteringService")

class MeteringService:
    """[v2.5.0] Usage-Based Metered Billing Service (Stripe)."""
    
    def __init__(self):
        self.api_key = os.getenv("STRIPE_SECRET_KEY", "sk_test_PLACEHOLDER")
        stripe.api_key = self.api_key

    async def report_usage(self, stripe_subscription_item_id: str, quantity: int):
        """Reports resource usage to Stripe Usage Records API."""
        if not stripe_subscription_item_id or stripe_subscription_item_id == "placeholder":
            return

        try:
            # Report usage for the current timestamp
            stripe.SubscriptionItem.create_usage_record(
                stripe_subscription_item_id,
                quantity=quantity,
                timestamp=int(datetime.utcnow().timestamp()),
                action='increment'
            )
            logger.info(f"Reported usage of {quantity} to Stripe for item {stripe_subscription_item_id}")
        except Exception as e:
            logger.error(f"Stripe Usage Reporting Failed: {e}")

    @staticmethod
    def calculate_cost(feature: str, count: int) -> float:
        """Helper to estimate cost for UI display."""
        rates = {
            "ocr_page": 0.05,
            "ai_summary": 0.10,
            "gb_storage": 0.50
        }
        return round(rates.get(feature, 0.0) * count, 2)

    @staticmethod
    async def check_quota(tenant_id: int, feature: str, current_count: int) -> bool:
        """[v2.6.0] Quota Enforcement: Verifies if a tenant has remaining capacity."""
        # This would typically query a 'Quotas' table or the Tenant plan
        # Simplified logic for demonstration
        quotas = {
            "max_agents": {"Starter": 10, "Professional": 500, "Enterprise": 10000},
            "max_storage_gb": {"Starter": 5, "Professional": 100, "Enterprise": 5000}
        }
        
        # In a real app, fetch plan from DB
        plan = "Enterprise" # Placeholder
        limit = quotas.get(feature, {}).get(plan, 0)
        
        if current_count >= limit:
            logger.warning(f"Tenant {tenant_id} exceeded quota for {feature} (Limit: {limit})")
            return False
            
        return True

# Global singleton
metering_service = MeteringService()
