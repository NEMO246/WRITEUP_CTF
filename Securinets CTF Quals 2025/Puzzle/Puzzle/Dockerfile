# Use official Python base image
FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Copy project files
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set environment variables
#ENV FLASK_APP=app.py
#ENV FLASK_RUN_HOST=0.0.0.0

# Expose port
EXPOSE 5000

RUN useradd -m karrab && \
    chown -R karrab:karrab /app
USER karrab

# Run the app
CMD ["python", "app.py"]
