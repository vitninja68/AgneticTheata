FROM python:3.12-alpine
WORKDIR ./
COPY requirements.txt .
RUN pip install  --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["adk", "api_server"]
#CMD ["uvicorn", "server:mcp", "--host", "0.0.0.0", "--port", "8000"]
