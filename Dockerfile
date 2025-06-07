FROM python:3.12-alpine
WORKDIR ./
COPY requirements.txt .
RUN pip install  --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
EXPOSE 8001
#COPY .env .
#CMD ["uvicorn", "server:mcp", "--host", "0.0.0.0", "--port", "8000"]
RUN apk update && apk add --no-cache socat
RUN echo '#!/bin/sh' > /start.sh && \
    echo 'echo "Starting application on port 8001..."' >> /start.sh && \
    # Start the application in the background
    echo 'adk api_server --host 127.0.0.1 --port 8001 &' >> /start.sh && \
    echo '' >> /start.sh && \
    # Wait for the application's port to be open
    echo 'echo "Waiting for application to be ready on port 8001..."' >> /start.sh && \
    echo 'while ! nc -z 127.0.0.1 8001; do' >> /start.sh && \
    echo '  sleep 0.1 # wait for 1/10 of a second before check again' >> /start.sh && \
    echo 'done' >> /start.sh && \
    echo '' >> /start.sh && \
    # Now start socat in the foreground
    echo 'echo "Application is ready. Starting socat proxy..."' >> /start.sh && \
    echo 'exec socat TCP-LISTEN:8000,fork,reuseaddr,bind=0.0.0.0 TCP:127.0.0.1:8001' >> /start.sh && \
    chmod +x /start.sh
CMD ["/start.sh"]
