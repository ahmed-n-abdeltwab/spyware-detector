import hashlib
import magic


def calculate_hash(file_stream):
    """
    Calculate the SHA-256 hash of a file.

    Args:
        file_stream: A file-like object containing the file data.

    Returns:
        str: SHA-256 hash of the file.
    """
    try:
        file_stream.seek(0)
        return hashlib.sha256(file_stream.read()).hexdigest()
    except Exception as e:
        return {"error": f"Hash calculation error: {str(e)}"}


def get_file_type(file_stream):
    """
    Detect the file type based on its content.

    Args:
        file_stream: A file-like object containing the file data.

    Returns:
        str: Detected file type.
    """
    try:
        file_stream.seek(0)
        mime = magic.Magic(mime=True)
        return mime.from_buffer(file_stream.read(2048))
    except Exception as e:
        return {"error": f"File type detection error: {str(e)}"}


def get_mime_type(file_stream):
    """
    Get the MIME type of a file.

    Args:
        file_stream: A file-like object containing the file data.

    Returns:
        str: MIME type of the file.
    """
    try:
        file_stream.seek(0)
        return magic.from_buffer(file_stream.read(2048), mime=True)
    except Exception as e:
        return {"error": f"MIME type detection error: {str(e)}"}
