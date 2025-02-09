# Use an official Python runtime as a parent image
FROM python:3.9

# Set the working directory in the container
WORKDIR /app

# Copy the project files into the container
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set up environment variables
ARG FLASK_PORT
ENV FLASK_PORT=${FLASK_PORT}

# Expose the port from .env (default to 5000)
EXPOSE ${FLASK_PORT}

# Run the application
CMD ["python", "server.py"]
