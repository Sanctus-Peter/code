from django.db import models


class RecordingSession(models.Model):
    recording_id = models.CharField(max_length=255, unique=True)
    mime_type = models.CharField(max_length=255)
    status = models.CharField(max_length=20, default='recording')  # 'recording', 'processing', 'completed'
    transcription = models.TextField(blank=True)
    is_completed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)


class RecordingChunk(models.Model):
    session = models.ForeignKey(RecordingSession, on_delete=models.CASCADE)
    order = models.PositiveIntegerField()
    is_last_chunk = models.BooleanField(default=False)
    file_path = models.FileField(upload_to='recording_chunks/')  # Store the file path
    created_at = models.DateTimeField(auto_now_add=True)
