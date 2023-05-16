FROM alpine:latest

RUN apk update && apk add python3 && apk add curl
RUN python3 -m ensurepip

COPY ./requirements.txt /opt/flask/requirements.txt
COPY ./pop.sh /opt/flask/pop.sh

WORKDIR /opt/flask

RUN pip3 install -r requirements.txt

COPY . /opt/flask
RUN chmod a+x boot.sh

RUN chmod a+x pop.sh

EXPOSE 5000

VOLUME /opt/FlaskMock

ENV FLASK_APP app.py
ENTRYPOINT ["./boot.sh"]
