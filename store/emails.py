from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


def send_invoice_email(order):
    subject = f"Invoice for Order #{order.id}"

    try:
        html_message = render_to_string(
            "store/invoice_email.html",
            {"order": order}
        )

        email = EmailMessage(
            subject=subject,
            body=html_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[order.email],
        )

        email.content_subtype = "html"
        email.send(fail_silently=False)

        return True  # email sent successfully

    except Exception as e:
        logger.error(
            f"Failed to send invoice email for order {order.id}: {str(e)}",
            exc_info=True
        )
        return False  # email failed
