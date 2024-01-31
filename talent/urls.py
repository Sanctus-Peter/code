from django.urls import path
from authentication import apis as view
from rest_framework.routers import DefaultRouter

router = DefaultRouter()

urlpatterns = router.urls

urlpatterns += [
  path(
      "admin/talent",
      view.CreateUpdateTalentView.as_view(),
      name="create-or-update-talent"
    ),
    path(
      "talent-request",
      view.TalentRequestView.as_view(),
      name="talent-request"
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