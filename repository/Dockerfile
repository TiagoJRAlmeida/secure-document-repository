FROM python:3.12-slim
WORKDIR /repository

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["python3", "repository.py"]
