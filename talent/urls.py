from django.urls import path
from authentication import apis as view
from rest_framework.routers import DefaultRouter

router = DefaultRouter()

urlpatterns = router.urls

urlpatterns += [
  path(
      "admin/talent",
      view.CreateTalentView.as_view(),
      name="create-or-update-talent"
    ),
  path(
    "admin/talent/<uuid:pk>",
    view.UpdateTalentView.as_view(),
    name="update-talent"
  ),
  path(
    "talent-request",
    view.TalentRequestView.as_view(),
    name="talent-request"
  ),
  path(
    "admin/talents",
    view.TalentRequestList.as_view(),
    name="get-all-talent-requests"
  ),
  path(
    "talents",
    view.TalentList.as_view(),
    name="get-all-talents"
  ),
  path(
    "talent/<uuid:pk>",
    view.TalentDetail.as_view(),
    name="get-talent"
  ),
]
