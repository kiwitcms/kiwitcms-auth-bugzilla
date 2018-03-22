import xmlrpc.client

from django.conf import settings
from django.core.validators import validate_email
from django.core.exceptions import ValidationError

class BugzillaBackend(ModelBackend):
    """
    Bugzilla authorization backend for Kiwi TCMS.

    It requires bugzilla xmlrpc.
    """
    # Web UI Needed
    can_login = True
    can_register = False
    can_logout = True

    def authenticate(self, request, username=None, password=None):
        server = xmlrpc.client.ServerProxy(settings.BUGZILLA3_RPC_SERVER)

        try:
            validate_email(username)
        except ValidationError:
            return None
        else:
            try:
                server.bugzilla.login(username, password)
            except xmlrpc.client.Fault:
                return None

            try:
                user = User.objects.get(email=username)
                user.set_password(password)
                user.save()
            except User.DoesNotExist:
                user = User.objects.create_user(
                    username=username.split('@')[0],
                    email=username
                )

                user.set_unusable_password(password)

        if user.check_password(password):
            return user
