import requests
import logging
import pyotp
from allauth.socialaccount.models import SocialAccount
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAdminUser, AllowAny
from rest_framework import status, viewsets
from django.conf import settings
from allauth.account.utils import send_email_confirmation

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_POST

from rest_framework import filters
from rest_framework.mixins import ListModelMixin, CreateModelMixin

from apps.api.models import UserAPIKey

from .models import CustomUser
from .model_utils import make_user_staff_on_auth0, remove_user_from_staff_on_auth0
from .serializers import ChangeEmailSerializer, VerifyOtpSerializer, UserSerializer, AdminUserTokenSerializer
from .utils import get_auth0_headers, get_auth0_management_token, update_auth0_user


class EmailManagementViewSet(viewsets.GenericViewSet):
    permission_classes = [AllowAny]


    def send_verification_email(self, user_id, auth0_token):
        """Helper function to send a verification email"""

        verification_url = (
            f"https://{settings.AUTH0_DOMAIN}/api/v2/jobs/verification-email"
        )
        headers = get_auth0_headers(auth0_token)
        provider, identity_user_id = user_id.split("|")
        response = requests.post(
            verification_url,
            json={
                "user_id": user_id,
                "client_id": settings.AUTH0_CLIENT_ID,
                "identity": {"user_id": identity_user_id, "provider": provider},
            },
            headers=headers,
        )
        response.raise_for_status()

    @action(detail=False, methods=["post"], url_path="resend-verification-email")
    def resend_verification_email(self, request):
        serializer = ChangeEmailSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        email = serializer.validated_data["email"]
        
        # Get Auth0 management token
        auth0_token = get_auth0_management_token()
        headers = get_auth0_headers(auth0_token)
        
        response = requests.get(
            f"https://{settings.AUTH0_DOMAIN}/api/v2/users-by-email",
            params={'email': email},
            headers=headers,
        )
        user_json  = response.json()
        if len(user_json) == 0:
            return Response({"detail": "Verification email sent successfully"})

        user_id = user_json[0]['user_id']

        try:
            self.send_verification_email(user_id, auth0_token)
        except requests.RequestException as e:
            logging.error(f"An error occurred: {e}")
            return Response({"detail":  "An error occurred while processing your request."}, status=status.HTTP_400_BAD_REQUEST)

        return Response(
            {"detail": "Verification email sent successfully"},
            status=status.HTTP_200_OK,
        )


class UserManagementViewSet(viewsets.GenericViewSet):
    """User management ViewSet for handling email, password, and OTP changes"""

    @action(detail=False, methods=["patch"], url_path="change-email")
    def change_email(self, request):
        serializer = ChangeEmailSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]
            auth0_account = SocialAccount.objects.get(user_id=request.user.id)
            user_id = auth0_account.uid

            # Get Auth0 management token
            auth0_token = get_auth0_management_token()

            # Update email in Auth0
            try:
                update_auth0_user(user_id, {"email": email}, auth0_token)
            except requests.RequestException as e:
                logging.error(f"An error occurred: {e}")
                return Response({"detail":  "An error occurred while processing your request."}, status=status.HTTP_400_BAD_REQUEST)

            # Update email locally
            request.user.email = email
            request.user.save()

            try:
                self.send_verification_email(user_id, auth0_token)
            except requests.RequestException as e:
                logging.error(f"An error occurred: {e}")
                return Response({"detail":  "An error occurred while processing your request."}, status=status.HTTP_400_BAD_REQUEST)

            return Response(
                {"detail": "Email updated successfully"}, status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=["post"], url_path="resend-verification-email")
    def resend_verification_email(self, request):
        serializer = ChangeEmailSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        email = serializer.validated_data["email"]
        auth0_account = SocialAccount.objects.get(email=email)
        if not auth0_account:
            return Response({"detail": "Verification email sent successfully"})
        user_id = auth0_account.uid

        # Get Auth0 management token
        auth0_token = get_auth0_management_token()
        try:
            self.send_verification_email(user_id, auth0_token)
        except requests.RequestException as e:
            logging.error(f"An error occurred: {e}")
            return Response({"detail":  "An error occurred while processing your request."}, status=status.HTTP_400_BAD_REQUEST)

        return Response(
            {"detail": "Verification email sent successfully"},
            status=status.HTTP_200_OK,
        )

    @action(detail=False, methods=["post"], url_path="resend-my-verification-email")
    def resend_verification_email_for_user(self, request):
        auth0_account = SocialAccount.objects.get(user_id=request.user.id)
        user_id = auth0_account.uid

        # Get Auth0 management token
        auth0_token = get_auth0_management_token()
        try:
            self.send_verification_email(user_id, auth0_token)
        except requests.RequestException as e:
            logging.error(f"An error occurred: {e}")
            return Response({"detail":  "An error occurred while processing your request."}, status=status.HTTP_400_BAD_REQUEST)

        return Response(
            {"detail": "Verification email sent successfully"},
            status=status.HTTP_200_OK,
        )

    def send_verification_email(self, user_id, auth0_token):
        """Helper function to send a verification email"""
        verification_url = (
            f"https://{settings.AUTH0_DOMAIN}/api/v2/jobs/verification-email"
        )
        headers = get_auth0_headers(auth0_token)
        provider, identity_user_id = user_id.split("|")
        print(provider, identity_user_id)
        response = requests.post(
            verification_url,
            json={
                "user_id": user_id,
                "client_id": settings.AUTH0_CLIENT_ID,
                "identity": {"user_id": identity_user_id, "provider": provider},
            },
            headers=headers,
        )
        response.raise_for_status()

    @action(detail=False, methods=["post"], url_path="change-password")
    def change_password(self, request):
        auth0_token = get_auth0_management_token()
        payload = {
            "client_id": settings.AUTH0_CLIENT_ID,
            "email": request.user.email,
            "connection": "Username-Password-Authentication",
        }
        response = requests.post(
            f"https://{settings.AUTH0_DOMAIN}/dbconnections/change_password",
            headers=get_auth0_headers(auth0_token),
            json=payload,
        )
        if response.status_code == 200:
            return Response(
                {"detail": "Password change initiated"}, status=status.HTTP_200_OK
            )
        else:
            return Response(response.json(), status=response.status_code)

    @action(detail=False, methods=["post"], url_path="init-otp")
    def init_otp(self, request):
        auth0_token = get_auth0_management_token()
        auth0_account = SocialAccount.objects.get(user_id=request.user.id)
        user_id = auth0_account.uid
        totp_secret = pyotp.random_base32()

        payload = {
            "type": "totp",
            "name": "totp",
            "totp_secret": totp_secret,
        }
        response = requests.post(
            f"https://{settings.AUTH0_DOMAIN}/api/v2/users/{user_id}/authentication-methods",
            headers=get_auth0_headers(auth0_token),
            json=payload,
        )
        if response.status_code == 201:
            return Response(
                {
                    "detail": "OTP initialized",
                    "data": {
                        "totp_secret": totp_secret,
                        "totp_uri": pyotp.TOTP(totp_secret).provisioning_uri(
                            name=request.user.email, issuer_name="vulmatch"
                        ),
                    },
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(response.json(), status=response.status_code)

    @action(detail=False, methods=["post"], url_path="verify-otp")
    def verify_otp(self, request):
        serializer = VerifyOtpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        otp_key = serializer.validated_data["otp_key"]
        otp = serializer.validated_data["otp"]
        totp = pyotp.TOTP(otp_key)

        if not totp.verify(otp):
            raise ValidationError("Invalid OTP")

        auth0_token = get_auth0_management_token()
        auth0_account = SocialAccount.objects.get(user_id=request.user.id)
        user_id = auth0_account.uid

        try:
            update_auth0_user(
                user_id, {"app_metadata": {"mfa_enabled": True}}, auth0_token
            )
        except requests.RequestException as e:
            logging.error(f"An error occurred: {e}")
            return Response({"detail":  "An error occurred while processing your request."}, status=status.HTTP_400_BAD_REQUEST)

        return Response(
            {"detail": "OTP verified successfully"}, status=status.HTTP_200_OK
        )

    @action(detail=False, methods=["post"], url_path="disable-otp")
    def disable_otp(self, request):
        auth0_token = get_auth0_management_token()
        auth0_account = SocialAccount.objects.get(user_id=request.user.id)
        user_id = auth0_account.uid

        try:
            update_auth0_user(
                user_id, {"app_metadata": {"mfa_enabled": False}}, auth0_token
            )
        except requests.RequestException as e:
            logging.error(f"An error occurred: {e}")
            return Response({"detail":  "An error occurred while processing your request."}, status=status.HTTP_400_BAD_REQUEST)

        return Response(
            {"detail": "OTP disabled successfully"}, status=status.HTTP_200_OK
        )


class UserAdminManagementViewSet(viewsets.GenericViewSet, ListModelMixin):
    serializer_class = UserSerializer
    filter_backends = [filters.OrderingFilter, filters.SearchFilter]
    search_fields = ['email']
    ordering_fields = ['is_staff', 'email', 'date_joined', 'last_login']
    ordering = ['email']
    permission_classes = (IsAdminUser,)

    def get_queryset(self):
        return CustomUser.objects.prefetch_related("membership_set__team")

    @action(detail=True, methods=["post"], url_path="make-staff")
    def make_staff(self, *args, **kwargs):
        user = self.get_object()
        if user.is_staff:
            return Response({"status": "success"})

        try:
            make_user_staff_on_auth0(user.id)
        except requests.RequestException as e:
            logging.error(f"An error occurred: {e}")
            return Response({"detail":  "An error occurred while processing your request."}, status=status.HTTP_400_BAD_REQUEST)

        CustomUser.objects.filter(id=user.id).update(is_staff=True, is_superuser=True)

        return Response(
            {
                "status": "success",
                "detail": "User made admin successfully",
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["post"], url_path="remove-staff")
    def remove_staff(self, *args, **kwargs):
        user = self.get_object()
        if not user.is_staff:
            return Response({"status": "success"})

        try:
            remove_user_from_staff_on_auth0(user.id)
        except requests.RequestException as e:
            logging.error(f"An error occurred: {e}")
            return Response({"detail":  "An error occurred while processing your request."}, status=status.HTTP_400_BAD_REQUEST)

        CustomUser.objects.filter(id=user.id).update(is_staff=False, is_superuser=False)
        return Response(
            {
                "status": "success",
                "detail": "User removed from admin successfully",
            },
            status=status.HTTP_200_OK,
        )


class AdminTokenApiView(viewsets.GenericViewSet, CreateModelMixin):
    permission_classes = [IsAdminUser]
    serializer_class = AdminUserTokenSerializer
