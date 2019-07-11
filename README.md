# kubernetes_exporter
kubernetes exporter for prometheus monitoring

## build

~~~~
docker login
docker-compose -f docker-compose-build.yml build
docker-compose -f docker-compose-build.yml push
~~~~

## configuration

customize your configuration via config file kubernetes_exporter/exporter/exporter.py.yml

## run

Use docker-compose.yml to run container with mounted config kubernetes_exporter/exporter/exporter.py.yml
~~~~
docker-compose up
~~~~

## dependencies if want to run without container

pip3 install --user pyaml prometheus_client

