from django.urls import path
from .apis import StartRecordingView, UploadRecordingChunkView, StopRecordingView, GetAllRecordingsView

urlpatterns = [
    path('start-recording/', StartRecordingView.as_view(), name='start-recording'),
    path('upload-chunk/', UploadRecordingChunkView.as_view(), name='upload-chunk'),
    path('stop-recording/', StopRecordingView.as_view(), name='stop-recording'),
    path('recordings', GetAllRecordingsView.as_view(), name='get-all-recordings')
]
