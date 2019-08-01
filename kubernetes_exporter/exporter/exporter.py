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
    return log

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
        get_data_function()
                
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
    parse_data_nodes(json_data)

def parse_data_nodes(json_data):
    '''Parse data from "nodes" API'''
    for node in json_data['items']:
        name = node['metadata']['name']
        # get conditions
        conditions = ['OutOfDisk', 'NetworkUnavailable', 'MemoryPressure', 'DiskPressure', 'PIDPressure', 'Ready']
        for condition in node['status']['conditions']:
            metric_name = '{0}_node_condition'.format(conf['name'])
            labels = {'node_name': name}
            description = 'Value of kubelet condition - True is 1, False is 0'
            if condition['type'] in conditions:
                if condition['status'] == 'True':
                    value = 1
                elif condition['status'] == 'False':
                    value = 0
                conditions_labels = labels.copy()
                conditions_labels['condition'] = condition['type']
                metric = {'metric_name': metric_name, 'labels': conditions_labels, 'description': description, 'value': value}
                data.append(metric)
                conditions.remove(condition['type'])
            else:
                log.error('Condition: "{0}" not in "conditions"'.format(condition['type']))
        # get info
        metric_name = '{0}_node_info'.format(conf['name'])
        labels = {'node_name': name}
        labels['machine_id'] = node['status']['nodeInfo']['machineID']
        for l in node['metadata']['labels']:
            label = label_clean(l.split('/')[-1])
            value = label_clean(node['metadata']['labels'][l])
            if not value:
                value = 'false'
            labels[label] = value
        for addr in node['status']['addresses']:
            if addr['type'] == 'InternalIP':
                labels['internal_ip'] = addr['address']
                break
        description = "Useful information about node"
        metric = {'metric_name': metric_name, 'labels': labels, 'description': description, 'value': 1}
        data.append(metric)

def get_data_pods():
    '''Get data from "pods" API'''
    url = conf['url'] + '/api/v1/pods/'
    if conf['ssl_public_key'] and conf['ssl_private_key']:
        context = ssl.SSLContext()
        context.load_cert_chain(conf['ssl_public_key'], keyfile=conf['ssl_private_key'])
        responce = urllib.request.urlopen(url, context=context)
    else:
        responce = urllib.request.urlopen(url)
    raw_data = responce.read().decode()
    json_data = json.loads(raw_data)
    parse_data_pods(json_data)

def parse_data_pods(json_data):
    '''Parse data from "pods" API'''
    for pod in json_data['items']:
        name = pod['metadata']['name']
        labels = {'pod_name': name}
        namespace = pod['metadata']['namespace']
        labels['namespace'] = namespace
        status = pod['status']['phase']
        if status == 'Pending':
            node_name = 'none'
        else:
            node_name = pod['spec']['nodeName']
        labels['node_name'] = node_name
        # get conditions
        conditions = ['Initialized', 'Ready', 'ContainersReady', 'PodScheduled', 'Unschedulable']
        for condition in pod['status']['conditions']:
            metric_name = '{0}_pod_condition'.format(conf['name'])
            description = 'Value of pod condition - True is 1, False is 0'
            if condition['type'] in conditions:
                if condition['status'] == 'True':
                    value = 1
                elif condition['status'] == 'False':
                    value = 0
                conditions_labels = labels.copy()
                conditions_labels['condition'] = condition['type']
                metric = {'metric_name': metric_name, 'labels': conditions_labels, 'description': description, 'value': value}
                data.append(metric)
                conditions.remove(condition['type'])
            else:
                log.error('Condition: "{0}" not in "conditions"'.format(condition['type']))
        # get running
        status_map = {
            'Running': 1,
            'Pending': 0,
            'Succeeded': -1,
            'Unknown': -2,
            'Failed': -3
        }
        description = 'Pod phase, see vaules mapping: {0}'.format(status_map)
        metric_name = '{0}_pod_phase'.format(conf['name'])
        metric = {'metric_name': metric_name, 'labels': labels, 'description': description, 'value': status_map[status]}
        data.append(metric)
        # get containers
        if status == 'Pending':
            continue
        for container in pod['status']['containerStatuses']:
            container_labels = labels.copy()
            container_labels['container_name'] = container['name']
            ready_value = bool(container['ready'])
            metric_name = '{0}_container_ready'.format(conf['name'])
            metric = {'metric_name': metric_name, 'labels': container_labels, 'description': 'Specifies whether the container has passed its readiness probe - True is 1, False is 0', 'value': ready_value}
            data.append(metric)
            state = list(container['state'].keys())[0]
            state_map = {
                'running': 1,
                'waiting': 0,
                'terminated': -1
            }
            description = 'Container state, see vaules mapping: {0}'.format(state_map)
            metric_name = '{0}_container_state'.format(conf['name'])
            metric = {'metric_name': metric_name, 'labels': container_labels, 'description': description, 'value': state_map[state]}
            data.append(metric)

def label_clean(label):
    replace_map = {
        '\\': '',
        '"': '',
        '\n': '',
        '\t': '',
        '\r': '',
        '-': '_',
        ' ': '_'
    }
    for r in replace_map:
        label = label.replace(r, replace_map[r])
    return label

# run
conf = dict()
get_config(args)
add_ssl_trust()
log = configure_logging()
data = list()

kubernetes_exporter_up = prometheus_client.Gauge('kubernetes_exporter_up', 'kubernetes exporter scrape status')
kubernetes_exporter_errors_total = prometheus_client.Counter('kubernetes_exporter_errors_total', 'exporter scrape errors total counter')

class Collector(object):
    def collect(self):
        # add static metrics
        gauge = prometheus_client.core.GaugeMetricFamily
        counter = prometheus_client.core.CounterMetricFamily
        # get dinamic data
       #data = list()
        try:
            get_data()
            kubernetes_exporter_up.set(1)
        except:
            trace = traceback.format_exception(sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2])
            for line in trace:
                print(line[:-1])
            kubernetes_exporter_up.set(0)
            kubernetes_exporter_errors_total.inc()
        # add dinamic metrics
        to_yield = set()
        for _ in range(len(data)):
            metric = data.pop()
            labels = list(metric['labels'].keys())
            labels_values = [ metric['labels'][k] for k in labels ]
            if metric['metric_name'] not in to_yield:
                setattr(self, metric['metric_name'], gauge(metric['metric_name'], metric['description'], labels=labels))
            if labels:
                getattr(self, metric['metric_name']).add_metric(labels_values, metric['value'])
                to_yield.add(metric['metric_name'])
        for metric in to_yield:
            yield getattr(self, metric)

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

