from django.http import HttpRequest
from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.utils.translation import gettext as _

from apps.api.helpers import _get_api_key_object
from apps.users.models import CustomUser
from apps.subscriptions.helpers import subscribe_team_to_initial_subscription
from apps.utils.slug import get_next_unique_slug
from . import roles
from .models import Team, TeamApiKey, TeamApiKeyStatus


def get_default_team_name_for_user(user: CustomUser):
    return (user.get_display_name().split("@")[0] or _("My Team")).title()


def get_next_unique_team_slug(team_name: str) -> str:
    """
    Gets the next unique slug based on the name. Appends -1, -2, etc. until it finds
    a unique value.
    :param team_name:
    :return:
    """
    return get_next_unique_slug(Team, team_name[:40], "slug")


def get_team_for_request(request, view_kwargs):
    team_id = view_kwargs.get("team_id", None)
    if team_id:
        return get_object_or_404(Team, id=team_id)

    if not request.user.is_authenticated:
        return

    return get_default_team_from_request(request)


def get_default_team_from_request(request: HttpRequest) -> Team:
    if "team" in request.session:
        try:
            return request.user.teams.get(id=request.session["team"])
        except Team.DoesNotExist:
            # user wasn't member of team from session, or it didn't exist.
            # fall back to default behavior
            del request.session["team"]
            pass
    return get_default_team_for_user(request.user)


def get_default_team_for_user(user: CustomUser):
    if user.teams.exists():
        return user.teams.first()
    else:
        return None

def get_team_from_request(request: HttpRequest):
    if request is None:
        return None
    team_api_key = _get_api_key_object(request, TeamApiKey)
    if team_api_key.status != TeamApiKeyStatus.ACTIVE:
        raise PermissionDenied("Invalid key")
    team_api_key.last_used = timezone.now()
    team_api_key.save()
    return team_api_key.team


def create_default_team_for_user(user: CustomUser, team_name: str = None):
    team_name = team_name or get_default_team_name_for_user(user)
    slug = get_next_unique_team_slug(team_name)
    # unicode characters aren't allowed
    if not slug:
        slug = str(user.id)
    if not slug:
        slug = get_next_unique_team_slug("team")
    team = Team.objects.create(
        name=f"Default team for {user.email}", slug=slug, is_private=False, owner=user
    )
    team.members.add(user, through_defaults={"role": roles.ROLE_OWNER})
    team.save()
    subscribe_team_to_initial_subscription(team)
    return team

def get_team_from_request(request: HttpRequest):
    if request is None:
        return None
    team_api_key = _get_api_key_object(request, TeamApiKey)
    if team_api_key.status != TeamApiKeyStatus.ACTIVE:
        raise PermissionDenied("Invalid key")
    team_api_key.last_used = timezone.now()
    team_api_key.save()
    return team_api_key.team
