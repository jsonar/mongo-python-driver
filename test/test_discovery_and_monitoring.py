# Copyright 2014-present MongoDB, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test the topology module."""

import os
import sys
import threading

sys.path[0:0] = [""]

from bson import json_util, Timestamp
from pymongo import common
from pymongo.errors import (AutoReconnect,
                            ConfigurationError,
                            NetworkTimeout,
                            NotMasterError,
                            OperationFailure)
from pymongo.helpers import _check_command_response
from pymongo.ismaster import IsMaster
from pymongo.server_description import ServerDescription, SERVER_TYPE
from pymongo.settings import TopologySettings
from pymongo.topology import Topology, _ErrorContext
from pymongo.topology_description import TOPOLOGY_TYPE
from pymongo.uri_parser import parse_uri
from test import unittest, IntegrationTest
from test.utils import (assertion_context,
                        Barrier,
                        get_pool,
                        server_name_to_type,
                        rs_or_single_client,
                        wait_until)


# Location of JSON test specifications.
_TEST_PATH = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), 'discovery_and_monitoring')


class MockMonitor(object):
    def __init__(self, server_description, topology, pool, topology_settings):
        self._server_description = server_description
        self._topology = topology

    def open(self):
        pass

    def close(self):
        pass

    def join(self):
        pass

    def request_check(self):
        pass


def create_mock_topology(uri, monitor_class=MockMonitor):
    parsed_uri = parse_uri(uri)
    replica_set_name = None
    direct_connection = None
    if 'replicaset' in parsed_uri['options']:
        replica_set_name = parsed_uri['options']['replicaset']
    if 'directConnection' in parsed_uri['options']:
        direct_connection = parsed_uri['options']['directConnection']

    topology_settings = TopologySettings(
        parsed_uri['nodelist'],
        replica_set_name=replica_set_name,
        monitor_class=monitor_class,
        direct_connection=direct_connection)

    c = Topology(topology_settings)
    c.open()
    return c


def got_ismaster(topology, server_address, ismaster_response):
    server_description = ServerDescription(
        server_address, IsMaster(ismaster_response), 0)
    topology.on_change(server_description)


def got_app_error(topology, app_error):
    server_address = common.partition_node(app_error['address'])
    server = topology.get_server_by_address(server_address)
    error_type = app_error['type']
    generation = app_error.get('generation', server.pool.generation)
    when = app_error['when']
    max_wire_version = app_error['maxWireVersion']
    # XXX: We could get better test coverage by mocking the errors on the
    # Pool/SocketInfo.
    try:
        if error_type == 'command':
            _check_command_response(app_error['response'])
        elif error_type == 'network':
            raise AutoReconnect('mock non-timeout network error')
        elif error_type == 'timeout':
            raise NetworkTimeout('mock network timeout error')
        else:
            raise AssertionError('unknown error type: %s' % (error_type,))
        assert False
    except (AutoReconnect, NotMasterError, OperationFailure) as e:
        if when == 'beforeHandshakeCompletes' and error_type == 'timeout':
            raise unittest.SkipTest('PYTHON-2211')

        topology.handle_error(
            server_address, _ErrorContext(e, max_wire_version, generation))


def get_type(topology, hostname):
    description = topology.get_server_by_address((hostname, 27017)).description
    return description.server_type


class TestAllScenarios(unittest.TestCase):
    pass


def topology_type_name(topology_type):
    return TOPOLOGY_TYPE._fields[topology_type]


def server_type_name(server_type):
    return SERVER_TYPE._fields[server_type]


def check_outcome(self, topology, outcome):
    expected_servers = outcome['servers']

    # Check weak equality before proceeding.
    self.assertEqual(
        len(topology.description.server_descriptions()),
        len(expected_servers))

    if outcome.get('compatible') is False:
        with self.assertRaises(ConfigurationError):
            topology.description.check_compatible()
    else:
        # No error.
        topology.description.check_compatible()

    # Since lengths are equal, every actual server must have a corresponding
    # expected server.
    for expected_server_address, expected_server in expected_servers.items():
        node = common.partition_node(expected_server_address)
        self.assertTrue(topology.has_server(node))
        actual_server = topology.get_server_by_address(node)
        actual_server_description = actual_server.description
        expected_server_type = server_name_to_type(expected_server['type'])

        self.assertEqual(
            server_type_name(expected_server_type),
            server_type_name(actual_server_description.server_type))

        self.assertEqual(
            expected_server.get('setName'),
            actual_server_description.replica_set_name)

        self.assertEqual(
            expected_server.get('setVersion'),
            actual_server_description.set_version)

        self.assertEqual(
            expected_server.get('electionId'),
            actual_server_description.election_id)

        self.assertEqual(
            expected_server.get('topologyVersion'),
            actual_server_description.topology_version)

        expected_pool = expected_server.get('pool')
        if expected_pool:
            self.assertEqual(
                expected_pool.get('generation'),
                actual_server.pool.generation)

    self.assertEqual(outcome['setName'], topology.description.replica_set_name)
    self.assertEqual(outcome.get('logicalSessionTimeoutMinutes'),
                     topology.description.logical_session_timeout_minutes)

    expected_topology_type = getattr(TOPOLOGY_TYPE, outcome['topologyType'])
    self.assertEqual(topology_type_name(expected_topology_type),
                     topology_type_name(topology.description.topology_type))


def create_test(scenario_def):
    def run_scenario(self):
        c = create_mock_topology(scenario_def['uri'])

        for i, phase in enumerate(scenario_def['phases']):
            # Including the phase description makes failures easier to debug.
            description = phase.get('description', str(i))
            with assertion_context('phase: %s' % (description,)):
                for response in phase.get('responses', []):
                    got_ismaster(
                        c, common.partition_node(response[0]), response[1])

                for app_error in phase.get('applicationErrors', []):
                    got_app_error(c, app_error)

                check_outcome(self, c, phase['outcome'])

    return run_scenario


def create_tests():
    for dirpath, _, filenames in os.walk(_TEST_PATH):
        dirname = os.path.split(dirpath)[-1]

        for filename in filenames:
            with open(os.path.join(dirpath, filename)) as scenario_stream:
                scenario_def = json_util.loads(scenario_stream.read())

            # Construct test from scenario.
            new_test = create_test(scenario_def)
            test_name = 'test_%s_%s' % (
                dirname, os.path.splitext(filename)[0])

            new_test.__name__ = test_name
            setattr(TestAllScenarios, new_test.__name__, new_test)


create_tests()


class TestClusterTimeComparison(unittest.TestCase):
    def test_cluster_time_comparison(self):
        t = create_mock_topology('mongodb://host')

        def send_cluster_time(time, inc, should_update):
            old = t.max_cluster_time()
            new = {'clusterTime': Timestamp(time, inc)}
            got_ismaster(t,
                         ('host', 27017),
                         {'ok': 1,
                          'minWireVersion': 0,
                          'maxWireVersion': 6,
                          '$clusterTime': new})

            actual = t.max_cluster_time()
            if should_update:
                self.assertEqual(actual, new)
            else:
                self.assertEqual(actual, old)

        send_cluster_time(0, 1, True)
        send_cluster_time(2, 2, True)
        send_cluster_time(2, 1, False)
        send_cluster_time(1, 3, False)
        send_cluster_time(2, 3, True)


class TestIgnoreStaleErrors(IntegrationTest):

    def test_ignore_stale_connection_errors(self):
        N_THREADS = 5
        barrier = Barrier(N_THREADS, timeout=30)
        client = rs_or_single_client(minPoolSize=N_THREADS)
        self.addCleanup(client.close)

        # Wait for initial discovery.
        client.admin.command('ping')
        pool = get_pool(client)
        starting_generation = pool.generation
        wait_until(lambda: len(pool.sockets) == N_THREADS, 'created sockets')

        def mock_command(*args, **kwargs):
            # Synchronize all threads to ensure they use the same generation.
            barrier.wait()
            raise AutoReconnect('mock SocketInfo.command error')

        for sock in pool.sockets:
            sock.command = mock_command

        def insert_command(i):
            try:
                client.test.command('insert', 'test', documents=[{'i': i}])
            except AutoReconnect as exc:
                pass

        threads = []
        for i in range(N_THREADS):
            threads.append(threading.Thread(target=insert_command, args=(i,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Expect a single pool reset for the network error
        self.assertEqual(starting_generation+1, pool.generation)

        # Server should be selectable.
        client.admin.command('ping')


if __name__ == "__main__":
    unittest.main()
