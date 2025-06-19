FROM python

RUN mkdir /code
COPY ./requirements.txt /code
WORKDIR /code

RUN pip install -r requirements.txt

RUN mkdir /start
COPY ./run.sh /start
RUN chmod +x /start/run.sh

RUN mkdir /key
COPY ./id_rsa /key
RUN chmod 444 /key/id_rsa

RUN mkdir /static

RUN useradd isaias -s /bin/bash
USER isaias


CMD /start/run.sh
