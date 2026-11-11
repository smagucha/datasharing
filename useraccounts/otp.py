import secrets
from datetime import timedelta

from django.contrib.auth.hashers import check_password, make_password
from django.db import transaction
from django.utils import timezone

from .models import OTP

OTP_TTL = timedelta(minutes=5)
RESEND_COOLDOWN = 60  # seconds
MAX_ATTEMPTS = 5


class OTPCooldown(Exception):
    pass


def issue_otp(user, purpose=OTP.Purpose.LOGIN):
    now = timezone.now()
    last = user.otps.filter(purpose=purpose).order_by("-created_at").first()
    if last and (now - last.created_at).total_seconds() < RESEND_COOLDOWN:
        raise OTPCooldown()

    user.otps.filter(purpose=purpose, is_used=False).update(is_used=True)
    code = f"{secrets.randbelow(10**6):06d}"
    OTP.objects.create(
        user=user,
        purpose=purpose,
        code_hash=make_password(code),
        expires_at=now + OTP_TTL,
    )
    return code


def verify_otp(user, code, purpose=OTP.Purpose.LOGIN):
    with transaction.atomic():
        otp = (
            user.otps.select_for_update()
            .filter(purpose=purpose, is_used=False, expires_at__gt=timezone.now())
            .order_by("-created_at")
            .first()
        )
        if not otp or otp.attempts >= MAX_ATTEMPTS:
            return False
        otp.attempts += 1
        ok = check_password(code, otp.code_hash)
        otp.is_used = ok
        otp.save(update_fields=["attempts", "is_used"])
        return ok
