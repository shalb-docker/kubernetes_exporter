FROM python:3.7.1

RUN pip3 install prometheus_client
RUN pip3 install pyaml

COPY exporter/exporter.py /opt/exporter/exporter.py
COPY exporter/exporter.py.yml.default /opt/exporter/exporter.py.yml
RUN chmod 755 /opt/exporter/exporter.py

RUN useradd -m -s /bin/bash my_user
RUN chmod 664 /etc/ssl/certs/ca-certificates.crt
RUN chown root:my_user /etc/ssl/certs/ca-certificates.crt

USER my_user

ENTRYPOINT ["/usr/local/bin/python", "/opt/exporter/exporter.py"]
