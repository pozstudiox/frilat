import os

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploaded_files')
MAX_CONTENT_LENGTH = 5 * 1024 * 1024 * 1024  # 5 GB max file size
