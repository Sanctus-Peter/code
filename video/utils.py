import os
import subprocess
import uuid

from django.conf import settings

from video.models import RecordingSession, RecordingChunk


def generate_unique_id():
    new_id = str(uuid.uuid4())
    try:
        # Check if the ID already exists
        RecordingSession.objects.get(recording_id=new_id)
        # If yes, try again
        return generate_unique_id()
    except RecordingSession.DoesNotExist:
        # If no, return the ID
        return new_id


def get_chunk_dir(recording_id):
    return os.path.join(settings.MEDIA_ROOT, 'recording_chunks', recording_id)


def combine_chunks(recording_id):
    chunks = RecordingChunk.objects.filter(session__recording_id=recording_id).order_by('order')
    if not chunks:
        return None

    output_path = os.path.join(get_chunk_dir(recording_id), 'combined_video.mp4')
    try:
        subprocess.run(
            ['ffmpeg', '-y', '-f', 'concat', '-safe', '0', '-i', 'concat.txt', '-c', 'copy', output_path],
            check=True)
        return output_path
    except subprocess.CalledProcessError:
        return None

