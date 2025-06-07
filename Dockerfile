FROM python:3.12-alpine
WORKDIR ./
COPY requirements.txt .
RUN pip install  --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
EXPOSE 8001
COPY .env .
#CMD ["uvicorn", "server:mcp", "--host", "0.0.0.0", "--port", "8000"]
RUN apk update && apk add --no-cache socat
RUN echo '#!/bin/sh' > /start.sh && \
    echo 'echo "Starting socat proxy on port 8000 -> 8001"' >> /start.sh && \
    echo 'socat TCP-LISTEN:8000,fork,reuseaddr,bind=0.0.0.0 TCP:127.0.0.1:8001 &' >> /start.sh && \
    echo 'echo "Waiting for socat to start..."' >> /start.sh && \
    echo 'sleep 3' >> /start.sh && \
    echo 'echo "Starting application on port 8001"' >> /start.sh && \
    echo 'exec adk api_server --host 127.0.0.1 --port 8001' >> /start.sh && \
    chmod +x /start.sh
CMD ["/start.sh"]
