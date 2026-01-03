# Use official Python runtime as a parent image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies (for building some python packages if needed)
RUN apt-get update && apt-get install -y gcc default-libmysqlclient-dev pkg-config && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
# Copy application code
COPY app ./app
COPY storage ./storage
COPY start.sh .

# Permissions
RUN chmod +x start.sh

# Expose port
EXPOSE 8000

# Run entrypoint
CMD ["./start.sh"]
