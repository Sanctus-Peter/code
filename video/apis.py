from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rq import Queue
from django_rq import get_connection
from .models import RecordingSession, RecordingChunk
from .serializers import UploadRecordingSerializer, StopRecordingSerializer, RecordSerializer, \
    RecordingSessionSerializer
from .tasks import transcribe_video
from .utils import generate_unique_id, get_chunk_dir, combine_chunks


class StartRecordingView(APIView):
    serializer_class = RecordSerializer

    def post(self, request):
        # Create a new recording session
        recording_id = generate_unique_id()
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            mime_type = serializer.validated_data['mime_type']
            RecordingSession.objects.create(
                recording_id=recording_id,
                mime_type=mime_type
            )
            return Response({'recording_id': recording_id}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UploadRecordingChunkView(APIView):
    serializer_class = UploadRecordingSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            recording_id = serializer.validated_data['id']
            file_objs = serializer.validated_data['blob_data']
            order = serializer.validated_data['order']
            try:
                recording_session = RecordingSession.objects.get(recording_id=recording_id)
            except RecordingSession.DoesNotExist:
                return Response({'detail': 'Recording session not found.'}, status=status.HTTP_404_NOT_FOUND)

            if file_objs:
                for file_obj in file_objs:
                    chunk_dir = get_chunk_dir(recording_id)
                    os.makedirs(chunk_dir, exist_ok=True)
                    chunk_filename = f'chunk_{order}.mp4'
                    chunk_path = os.path.join(chunk_dir, chunk_filename)

                    with open(chunk_path, 'wb') as destination:
                        for chunk in file_obj.chunks():
                            destination.write(chunk)

                    RecordingChunk.objects.create(
                        session=recording_session,
                        order=order,
                        file_path=chunk_path
                    )

                return Response(status=status.HTTP_200_OK)
            else:
                return Response({'detail': 'File data not provided.'}, status=status.HTTP_400_BAD_REQUEST)


class StopRecordingView(APIView):
    serializer_class = StopRecordingSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            recording_id = serializer.validated_data['id']
            file_objs = serializer.validated_data['blob_data']
            last_chunk = serializer.validated_data['last_chunk']
            order = serializer.validated_data['order']
            try:
                recording_session = RecordingSession.objects.get(recording_id=recording_id)
            except RecordingSession.DoesNotExist:
                return Response({'detail': 'Recording session not found.'}, status=status.HTTP_404_NOT_FOUND)

            if file_objs:
                for file_obj in file_objs:
                    chunk_dir = get_chunk_dir(recording_id)
                    os.makedirs(chunk_dir, exist_ok=True)
                    chunk_filename = f'chunk_{order}.mp4'
                    chunk_path = os.path.join(chunk_dir, chunk_filename)

                    with open(chunk_path, 'wb') as destination:
                        for chunk in file_obj.chunks():
                            destination.write(chunk)

                    RecordingChunk.objects.create(
                        session=recording_session,
                        order=order,
                        file_path=chunk_path,
                        is_last_chunk=last_chunk
                    )

            # Combine all the chunks
            output_path = combine_chunks(recording_id)
            if output_path:
                recording_session.is_completed = True
                recording_session.status = 'Processing'
                recording_session.save()
                # Enqueue the transcription task
                q = Queue(connection=get_connection('default'))
                q.enqueue(transcribe_video, recording_id)
                return Response(status=status.HTTP_200_OK)
            else:
                return Response({'detail': 'Error while combining chunks.'},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetAllRecordingsView(APIView):
    def get(self, request):
        recordings = RecordingSession.objects.all()
