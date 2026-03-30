FROM python:3.12-slim
WORKDIR /client

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
COPY commands/ /usr/local/bin/
RUN chmod +x /usr/local/bin/rep_*
RUN rm -rf commands/

CMD ["./welcome.sh"]
