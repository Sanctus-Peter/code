from rest_framework import serializers
from .models import RecordingSession, RecordingChunk


class RecordingSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = RecordingSession
        fields = '__all__'


class RecordingChunkSerializer(serializers.ModelSerializer):
    class Meta:
        model = RecordingChunk
        fields = '__all__'


class RecordSerializer(serializers.Serializer):
    mime_type = serializers.CharField(max_length=255)


class UploadRecordingSerializer(serializers.Serializer):
    id = serializers.CharField(required=True)
    order = serializers.IntegerField()
    blob_data = serializers.ListField(child=serializers.FileField())
    # blob_data = serializers.FileField()


class StopRecordingSerializer(serializers.Serializer):
    id = serializers.CharField(required=True)
    blob_data = serializers.ListField(child=serializers.FileField())
    order = serializers.IntegerField()
    last_chunk = serializers.BooleanField(default=True)
