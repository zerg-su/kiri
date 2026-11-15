#!/usr/bin/env python3
"""Opt-in Docker API regression tests against one explicit local socket.

Only disposable containers and networks are created. No host project or key is
mounted. The optional syscall probe is a test binary, mounted read-only.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid

IMAGE = 'alpine@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f'
OPTIONS = None


class Isolation(unittest.TestCase):
    def setUp(self):
        self.prefix = 'lair-isolation-' + uuid.uuid4().hex[:10]
        self.containers, self.networks = [], []
        self.tmp = tempfile.TemporaryDirectory(prefix='lair-seccomp-')
        self.addCleanup(self.tmp.cleanup)
        self.env = dict(os.environ)
        self.env.pop('DOCKER_HOST', None)
        self.env.pop('DOCKER_CONTEXT', None)

    def docker(self, *args):
        return subprocess.run([OPTIONS.docker, '--host', 'unix://' + OPTIONS.socket, *args],
                              env=self.env, text=True, capture_output=True, timeout=120)

    def ok(self, *args):
        result = self.docker(*args)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout.strip()

    def profile(self, value):
        path = Path(self.tmp.name) / ('profile-' + uuid.uuid4().hex + '.json')
        path.write_text(json.dumps(value))
        return 'seccomp=' + str(path)

    def network(self, suffix, internal=True):
        name = self.prefix + '-' + suffix
        self.ok('network', 'create', *(['--internal'] if internal else []), name)
        self.networks.append(name)
        return name

    def container(self, suffix, *args, detach=False, command=('/bin/true',)):
        name = self.prefix + '-' + suffix
        self.containers.append(name)
        return self.docker('run', '--name', name, *(['-d'] if detach else ['--rm']), *args, IMAGE, *command)

    def test_custom_deny_all_is_enforced(self):
        control = self.container('control', '--network', 'none')
        self.assertEqual(control.returncode, 0, control.stderr)
        blocked = self.container('blocked', '--network', 'none', '--security-opt',
                           self.profile({'defaultAction': 'SCMP_ACT_KILL_PROCESS', 'syscalls': []}))
        self.assertNotEqual(blocked.returncode, 0, 'Custom seccomp was ignored: /bin/true ran.')

    def test_a_malformed_custom_policy_is_rejected(self):
        blocked = self.container('bad-policy', '--network', 'none', '--security-opt',
                           self.profile({'defaultAction': 'SCMP_ACT_NOT_REAL', 'syscalls': []}))
        self.assertNotEqual(blocked.returncode, 0, 'Unknown seccomp action was silently ignored.')

    def probe_args(self):
        if not OPTIONS.probe:
            self.skipTest('--probe was not supplied')
        return ('--mount', 'type=bind,source=' + str(Path(OPTIONS.probe).resolve()) + ',target=/probe,readonly')

    def test_custom_errno_and_argument_filter_and_exec_inheritance(self):
        mount = self.probe_args()
        policy = self.profile({'defaultAction': 'SCMP_ACT_ALLOW', 'syscalls': [
            {'names': ['getppid'], 'action': 'SCMP_ACT_ERRNO', 'errnoRet': 13},
            {'names': ['getpgid'], 'action': 'SCMP_ACT_ERRNO', 'errnoRet': 13,
             'args': [{'index': 0, 'op': 'SCMP_CMP_MASKED_EQ', 'value': 1, 'valueTwo': 0}]}]})
        for suffix, command in [('errno', ('/probe', 'getppid', '13')),
                                ('matched', ('/probe', 'getpgid', '0', '13')),
                                ('allowed', ('/probe', 'getpgid', '1', '0')),
                                ('sudo-compatible', ('/probe', 'nnp'))]:
            with self.subTest(command=suffix):
                result = self.container(suffix, '--network', 'none', *mount, '--security-opt', policy, command=command)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        running = self.container('exec-policy', '--network', 'none', *mount, '--security-opt', policy,
                                 detach=True, command=('sleep', '300'))
        self.assertEqual(running.returncode, 0, running.stderr)
        self.ok('exec', self.containers[-1], '/probe', 'getppid', '13')

    def test_custom_allow_all_cannot_remove_the_host_boundary(self):
        mount = self.probe_args()
        for suffix in ['vsock', 'uring']:
            result = self.container(suffix, '--network', 'none', *mount, '--security-opt',
                                    self.profile({'defaultAction': 'SCMP_ACT_ALLOW'}), command=('/probe', suffix))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_lair_profile_allows_its_user_namespace_without_host_capabilities(self):
        mount = self.probe_args()
        if not OPTIONS.lair_profile:
            self.skipTest('--lair-profile was not supplied')
        result = self.container('lair-profile', '--network', 'none', *mount, '--security-opt',
                                'seccomp=' + str(Path(OPTIONS.lair_profile).resolve()), command=('/probe', 'userns'))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_lair_profile_preserves_normal_path_lookup(self):
        if not OPTIONS.lair_profile:
            self.skipTest('--lair-profile was not supplied')
        result = self.container('lair-path', '--network', 'none', '--security-opt',
                                'seccomp=' + str(Path(OPTIONS.lair_profile).resolve()),
                                command=('sh', '-c', 'command -v nslookup && ls -l /usr/bin/nslookup'))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_compose_preserves_the_profile_and_internal_service_dns(self):
        mount = self.probe_args()
        if not OPTIONS.lair_profile:
            self.skipTest('--lair-profile was not supplied')
        path = Path(self.tmp.name) / 'compose.json'
        path.write_text(json.dumps({'services': {
            'peer': {'image': IMAGE, 'command': ['sleep', '300'], 'networks': ['private'], 'stop_grace_period': '1s'},
            'probe': {'image': IMAGE, 'depends_on': ['peer'], 'networks': ['private'],
                      'security_opt': ['seccomp=' + str(Path(OPTIONS.lair_profile).resolve())],
                      'volumes': [str(Path(OPTIONS.probe).resolve()) + ':/probe:ro'],
                      'command': ['sh', '-c', 'nslookup peer && ! timeout 4 nslookup example.com && /probe userns']}},
            'networks': {'private': {'internal': True}}}))
        compose = ('compose', '--project-name', self.prefix, '-f', str(path))
        try:
            self.ok(*compose, 'up', '--abort-on-container-exit', '--exit-code-from', 'probe')
        finally:
            self.ok(*compose, 'down', '--timeout', '2')

    def test_internal_dns_keeps_peer_names_but_never_resolves_external_names(self):
        network = self.network('internal')
        peer = self.container('peer', '--network', network, '--network-alias', 'lair-peer',
                        detach=True, command=('sleep', '300'))
        self.assertEqual(peer.returncode, 0, peer.stderr)
        result = self.container('peer-query', '--network', network,
                          command=('timeout', '6', 'nslookup', 'lair-peer'))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for suffix, extra, command in (
            ('external-a', (), ('timeout', '6', 'nslookup', 'example.com')),
            ('external-aaaa', (), ('timeout', '6', 'nslookup', '-type=AAAA', 'example.com')),
            ('custom-dns', ('--dns', '1.1.1.1'), ('timeout', '6', 'nslookup', 'example.com')),
            ('host-name', (), ('timeout', '6', 'nslookup', 'host.docker.internal')),
        ):
            with self.subTest(query=suffix):
                result = self.container(suffix, '--network', network, *extra, command=command)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_the_internal_bridge_gateway_cannot_forward_dns(self):
        network = self.network('gateway')
        gateway = self.ok('network', 'inspect', '--format', '{{(index .IPAM.Config 0).Gateway}}', network)
        result = self.container('query', '--network', network,
                          command=('timeout', '6', 'nslookup', 'example.com', gateway))
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_another_external_bridge_is_not_a_dns_escape(self):
        internal, external = self.network('inside'), self.network('outside', internal=False)
        peer = self.container('outside-peer', '--network', external, detach=True, command=('sleep', '300'))
        self.assertEqual(peer.returncode, 0, peer.stderr)
        gateway = self.ok('network', 'inspect', '--format', '{{(index .IPAM.Config 0).Gateway}}', external)
        result = self.container('cross-bridge-query', '--network', internal,
                                command=('timeout', '6', 'nslookup', 'example.com', gateway))
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_dns_access_tracks_network_connect_and_disconnect(self):
        internal, external = self.network('inside'), self.network('outside', internal=False)
        client = self.container('client', '--network', internal, detach=True, command=('sleep', '300'))
        self.assertEqual(client.returncode, 0, client.stderr)
        name = self.containers[-1]
        self.ok('network', 'connect', external, name)
        self.ok('exec', name, 'timeout', '6', 'nslookup', 'example.com')
        self.ok('network', 'disconnect', external, name)
        result = self.docker('exec', name, 'timeout', '6', 'nslookup', 'example.com')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def tearDown(self):
        for name in reversed(self.containers):
            self.docker('stop', '-t', '2', name)
            self.docker('rm', name)
        for name in reversed(self.networks):
            self.ok('network', 'rm', name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True)
    parser.add_argument('--docker', default='docker')
    parser.add_argument('--probe', help='static Linux executable built from tests/isolation-probe.rs')
    parser.add_argument('--lair-profile', help='optional Docker seccomp JSON used by Lair')
    parser.add_argument('--report', type=Path, help='write structured test results')
    OPTIONS, rest = parser.parse_known_args()
    program = unittest.main(argv=[__file__, *rest], exit=False)
    result = program.result
    if OPTIONS.report:
        OPTIONS.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'tests_run': result.testsRun,
            'failures': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped)}))
    raise SystemExit(not result.wasSuccessful())
