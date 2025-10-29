# Use official Python 3 base image
FROM python:3.11-slim

# Set working directory
WORKDIR /opt/sap

# Create logs directory with appropriate permissions
RUN mkdir -p /opt/sap/logs && chmod 755 /opt/sap/logs

# Copy credentials.conf and script with desired paths
COPY credentials.conf /opt/sap/credentials.conf
COPY sap.py /opt/sap/sap.py

# Install dependencies
RUN pip install --no-cache-dir requests pytz

# Set environment variables if needed (optional)
# ENV PYTHONUNBUFFERED=1

# Run the Python script by default
CMD ["python3", "sap.py"]

#####################################################
# docker build -t sap-audit-beat:p.v1  .
#####################################################
