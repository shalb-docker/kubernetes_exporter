#!/usr/bin/env python

import urllib.request
import ssl
import json
import traceback
import argparse
import sys
import time
import logging
import yaml
import prometheus_client
import prometheus_client.core

# parse arguments
parser = argparse.ArgumentParser()
parser.add_argument('--config', default=sys.argv[0] + '.yml', help='config file location')
parser.add_argument('--log_level', help='logging level')
parser.add_argument('--url', help='kubernetes web UI url')
parser.add_argument('--tasks', help='tasks to execute')
parser.add_argument('--ssl_public_key', help='ssl public key file for http connection')
parser.add_argument('--ssl_private_key', help='ssl private key file for http connection')
args = parser.parse_args()

# add prometheus decorators
REQUEST_TIME = prometheus_client.Summary('request_processing_seconds', 'Time spent processing request')

def get_config(args):
    '''Parse configuration file and merge with cmd args'''
    for key in vars(args):
        conf[key] = vars(args)[key]
    with open(conf['config']) as conf_file:
        conf_yaml = yaml.load(conf_file, Loader=yaml.FullLoader)
    for key in conf_yaml:
        if not conf.get(key):
            conf[key] = conf_yaml[key]

def configure_logging():
    '''Configure logging module'''
    log = logging.getLogger(__name__)
    log.setLevel(conf['log_level'])
    FORMAT = '%(asctime)s %(levelname)s %(message)s'
    logging.basicConfig(format=FORMAT)

def add_ssl_trust():
    '''Add ssl trust for selfsigned ssl'''
    if conf['ssl_ca_key']:
        with open(conf['ssl_ca_key']) as ssl_ca_key_file:
            ssl_ca_key = ssl_ca_key_file.read().strip()
        with open('/etc/ssl/certs/ca-certificates.crt') as certs_file:
            certs = certs_file.read().strip()
        # check if 'ssl_ca_key' already presented in 'certs'
        if ssl_ca_key[-2] == certs[-2]:
            with open('/etc/ssl/certs/ca-certificates.crt', 'a') as certs_file:
                certs_file.write('\n' + ssl_ca_key)

# Decorate function with metric.
@REQUEST_TIME.time()
def get_data():
    '''Get data from target service'''
    for task_name in conf['tasks']:
        get_data_function = globals()['get_data_'+ task_name]
        task_data = get_data_function()
        return task_data
                
def get_data_nodes():
    '''Get data from "nodes" API'''
    url = conf['url'] + '/api/v1/nodes'
    if conf['ssl_public_key'] and conf['ssl_private_key']:
        context = ssl.SSLContext()
        context.load_cert_chain(conf['ssl_public_key'], keyfile=conf['ssl_private_key'])
        responce = urllib.request.urlopen(url, context=context)
    else:
        responce = urllib.request.urlopen(url)
    raw_data = responce.read().decode()
    json_data = json.loads(raw_data)
    result = parse_data_nodes(json_data)
    return result

def parse_data_nodes(data):
    '''Parse data from "nodes" API'''
    result = list()
    for node in data['items']:
        name = node['metadata']['name']
        # get conditions
        conditions = ['NetworkUnavailable', 'MemoryPressure', 'DiskPressure', 'PIDPressure', 'Ready']
        for s in node['status']['conditions']:
            type_tmp = s['type']
            status = s['status']
            metric_name = '{0}_node_{1}'.format(conf['name'], type_tmp.lower())
            labels = {'node_name': name}
            description = 'Value of kubelet condition: "{0}" - True is 1, False is 0'.format(type_tmp)
            if type_tmp in conditions:
                if status == 'True':
                    value = 1
                elif status == 'False':
                    value = 0
                metric = {'metric_name': metric_name, 'labels': labels, 'description': description, 'value': value}
                if metric not in result:
                    result.append(metric)
                else:
                    log.error('Metric: "{0}" already exist in "result"'.format(metric))
                conditions.remove(type_tmp)
            else:
                log.error('Condition: "{0}" not in "conditions"'.format(type_tmp))
        # get info
       #metric_name = '{0}_node_info'.format(conf['name'])
       #labels = {'node_name': name}
       #labels['machine_id'] = node['status']['nodeInfo']['machineID']
       #for l in node['metadata']['labels']:
       #    label = l.split('/')[-1]
       #    labels[label] = node['metadata']['labels'][l]
       #for addr in node['status']['addresses']:
       #    if addr['type'] == 'InternalIP':
       #        labels['internal_ip'] = addr['address']
       #description = "Useful information about node"
       #metric = {'metric_name': metric_name, 'labels': labels, 'description': description, 'value': 1}
       #result.append(metric)
    return result

# run
conf = dict()
get_config(args)
add_ssl_trust()
configure_logging()

kubernetes_exporter_up = prometheus_client.Gauge('kubernetes_exporter_up', 'kubernetes exporter scrape status')
kubernetes_exporter_errors_total = prometheus_client.Counter('kubernetes_exporter_errors_total', 'exporter scrape errors total counter')

class Collector(object):
    def collect(self):
        # add static metrics
        gauge = prometheus_client.core.GaugeMetricFamily
        counter = prometheus_client.core.CounterMetricFamily
        # get dinamic data
        data = dict()
        try:
            data = get_data()
            kubernetes_exporter_up.set(1)
        except:
            trace = traceback.format_exception(sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2])
            for line in trace:
                print(line[:-1])
            kubernetes_exporter_up.set(0)
            kubernetes_exporter_errors_total.inc()
        # add dinamic metrics
        to_yield = set()
        for metric in data:
            labels = list(metric['labels'].keys())
            labels_values = [ metric['labels'][k] for k in labels ]
            if metric['metric_name'] not in to_yield:
                setattr(self, metric['metric_name'], gauge(metric['metric_name'], metric['description'], labels=labels))
            if labels:
                getattr(self, metric['metric_name']).add_metric(labels_values, metric['value'])
                to_yield.add(metric['metric_name'])
        for metric in to_yield:
            yield getattr(self, metric)

       #kubernetes_node = gauge('kubernetes_node', 'kubernetes_node Description', labels=['name'])
       #    kubernetes_node.add_metric([name], status)
       #yield kubernetes_node

registry = prometheus_client.core.REGISTRY
registry.register(Collector())

prometheus_client.start_http_server(conf['listen_port'])

# endless loop
while True:
    try:
        while True:
            time.sleep(conf['check_interval'])
    except KeyboardInterrupt:
        break
    except:
        trace = traceback.format_exception(sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2])
        for line in trace:
            print(line[:-1])

