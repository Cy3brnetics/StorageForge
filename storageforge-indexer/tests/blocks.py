"""The three blocks of the unit suite, so a change can be checked in a minute and the whole suite still runs before a merge. tests/run.py runs them.

    light    pure Python against a temporary database: parsers, compilers, scripts as text, the API through Flask's test client. Seconds per module.
    medium   local tools and longer API walks: bash running the generated scripts, telnet and console sessions, the scheduler's runner, nft and iptables in check mode.
    heavy    real servers and real time: Chromium through Playwright, sshd, Docker, the sentinel and its decoys, key rotation, scans end to end.

A class not named below is light. A class is named by 'module.Class', and test_blocks.py fails when a name here no longer exists, so a renamed class
can't drop out of its block without anyone seeing. The random tests (test_props_*.py) are light: they run a small fixed set of examples every time,
and `run.py deep` runs them again with many more examples and a fresh seed.

Timings that put a class here, on one core of the owner's machine on 2026-11-16, are in tests/README.md.
"""

HEAVY = {
    # Chromium through Playwright
    'test_browser_copies.BrowserCopies',
    'test_browser_drafts.BrowserDrafts',
    'test_browser_enclave.BrowserEnclave',
    'test_browser_logs.BrowserLogs',
    'test_browser_notifications.BrowserNotifications',
    'test_browser_map_whatif.MapWhatIfBrowser',
    'test_browser_planner_versions.PlannerVersions',
    'test_browser_polish.BrowserPolish',
    'test_browser_sfnet.BrowserSfnet',
    'test_browser_smoke.BrowserSmoke',
    'test_sshcerts.BrowserSshCa',
    'test_browser_smoke.MapAtScale',
    'test_browser_vms.BrowserVms',
    # a real sshd, Docker, or the kernel's firewall
    'test_feature_routes.RealSshServer',
    'test_infra.RealDocker',
    'test_infra.RealIptables',
    'test_infra.RealNft',
    'test_nettransport.RealSshTerminal',
    'test_platform_more.WriterOnRealNftables',
    'test_security.RealNftables',
    'test_security.RealSentinel',
    'test_sfnet_rotation.RealWireGuard',
    'test_sfcontroller.RealLink',
    'test_sends.RealSshd',
    # real time: waits, stalls and timers that have to run out
    'test_recovery.StalledWalk',
    'test_rotation.Rotation',
    'test_security.Brake',
    'test_security.Decoys',
    'test_sync_engine.Engine',
    # long walks through the whole product: a scan end to end, every route, every page of a feature
    'test_audit_2026_11_03.SentinelPermission',
    'test_cli_commands.Commands',
    'test_feature_routes.Administration',
    'test_feature_routes.DiscoveryViews',
    'test_feature_routes.MapViews',
    'test_feature_routes.RemovedJobs',
    'test_feature_routes.Reports',
    'test_feature_routes.SecurityPolicies',
    'test_hostlogs.Entrances',
    'test_indexer.EndToEnd',
    'test_platform.VaultTests',
    'test_platform_more.EveryRouteAnswers',
    'test_route_rules.RouteRules',
    'test_scansign.SignedScan',
    'test_security.Events',
    'test_security.Firewall',
    'test_security.NothingIsInvented',
    'test_security.Wiring',
    'test_whatif_sentences.SentencesInTheAnswer',
}

MEDIUM = {
    'test_sshca.Certificates',       # a real sshd, started for one test
    'test_sshcerts.TrustStep',       # the trust and revocation steps against a real sshd, reloaded
    'test_sshcerts.CaInTheEnclave',  # the real enclave program signing a certificate
    'test_tunnel_exposure.Steps',    # bash running the two tunnel steps against stand-ins
    'test_overlay_steps.NetBird',    # bash running the join and leave steps against stand-ins, on a PATH of their own
    'test_overlay_steps.ZeroTier',
    'test_overlay_steps.OpenZiti',
    'test_overlay_steps.NebulaReal',     # the real nebula-cert and nebula, where they are found
    'test_overlay_steps.NebulaJoin',     # the vault's CA, the real nebula-cert, and the step
    'test_overlay_steps.NebulaNetwork',  # two real Nebula nodes in network namespaces of this account
    'test_scan_progress.Watched',    # a real local scan, watched
    'test_scan_progress.JobsList',
    'test_enclave.Enclave',          # the real enclave program, built with cargo, and the real ssh-add and ssh-keygen
    'test_enclave.VaultThroughEnclave',   # the vault, the agent helper, deploy's signer and the audit log with the enclave configured
    'test_enclave.Supervised',       # the VM started and watched, killed once, and started again
    'test_enclave.SupervisedByFirecracker',
    'test_enclave.EnclaveImage',     # the same again in the micro VM, where the image has been built and KVM is here
    'test_enclave_unlock.Unlock',    # the starter, a server that forgets the secret, and a person typing it: the real enclave program
    'test_enclave_stepup.StepUp',    # step-up checked inside: passwords, FIDO2 assertions made in software, tokens, lock-downs
    'test_enclave_stepup.ShortTokens',
    'test_enclave_release.Release',  # releases bound to a step, host or platform, written into the audit log from inside, and the chain's head
    'test_enclave_counts.Counts',     # limits per kind of task, and notifications from the enclave's own counts
    'test_enclave_lock2.SecondLock',  # the second lock on the KEK, with the enclave and without
    'test_enclave_channel.Channel',   # the Noise channel and the pinned key, with a relay that reads and changes what crosses
    'test_rotate_keys.Rewrap',        # the vault key rewrapped on schedule inside the enclave
    # bash, telnet and console sessions run for real
    'test_console.Api',
    'test_desktop_steps.Dux',
    'test_desktop_steps.WrittenProfile',
    'test_osinstall.TheScript',
    'test_selfupdate.Installer',
    'test_sfnetwork.InterfaceStep',
    'test_sfnet_paths.RealSsh',     # a real sshd on a loopback address, and real ssh to it
    'test_selfupdate.Repository',
    'test_console.Session',
    'test_console_open.Open',
    'test_errlog.ExitWhileWriting',
    'test_nettransport.Telnet',
    'test_pkglist.Collect',
    'test_platform.OpsTests',
    'test_platform_more.WriterOnRealIptables',
    'test_scheduler.HostSideSafetyTests',
    'test_scheduler.RawCommandTests',
    'test_scheduler.RunnerTests',
    'test_sends.Generated',
    'test_props_scripts.HostileValuesAnywhere',
    'test_folderwork.Worker',
    'test_storage_ops.Types',
    'test_updates.Script',
    # longer API walks
    'test_audit_2026_11_03.EveryWayToAHold',
    'test_consistency.EgressFirewall',
    'test_design_versions.Api',
    'test_infra.Network',
    'test_infra.ThroughTheRoutes',
    'test_kvm.Api',
    'test_platform.ServerTests',
    'test_remote_nodes.Lockdown',
    'test_roles.ResetLinks',
    'test_roles.SearchOnly',
    'test_scan_signs.Signs',
    'test_scheduler.SchedulerSafetyTests',
    'test_scheduler.Step5Tests',
    # reads every file in the repository
    'test_source_hygiene.SourceHygiene',
}

BLOCKS = ('light', 'medium', 'heavy')


def block_of(test_id: str) -> str:
    """'test_x.Class.test_y' → its block."""
    name = '.'.join(test_id.split('.')[:2])
    return 'heavy' if name in HEAVY else 'medium' if name in MEDIUM else 'light'


def is_random(test_id: str) -> bool:
    return test_id.startswith('test_props_')
