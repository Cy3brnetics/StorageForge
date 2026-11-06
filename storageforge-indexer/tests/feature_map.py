"""Every feature, the unit tests that cover it, and where the KVM lab verifies it. test_feature_map.py checks this file against the code
and docs/features/README.md, so a new feature with no test, or a test renamed away from one, fails the suite.

unit: 'module.Class' or 'module.Class.test_name' under tests/.
lab:  (tier, 'check'), a check by that name in that tier. Tier 2 is gauntlet.py, whose names are stages.
why:  only with no lab entry: what stops the lab from verifying it. These are the known gaps, and they are listed in docs/kvm-lab.md.
"""

# The rows of the catalogue in docs/features/README.md, by their link text.
CATALOGUE = {
    'Scan a host': {'unit': ['test_indexer.EndToEnd', 'test_cli_commands.Commands.test_scan_says_when_a_host_cannot_be_reached'], 'lab': [(1, 'scan-status'), (2, 'scan')]},
    'Scan schedule and quiet hours': {'unit': ['test_feature_routes.DiscoveryViews.test_a_host_schedule_keeps_what_it_is_given_and_refuses_the_rest'], 'lab': [(13, 'scan-schedule')]},
    'Read-only scan access': {'unit': ['test_platform.HostAccessTests', 'test_cli_commands.Commands.test_access_status_and_script'], 'lab': [(1, 'scan-with-access'), (2, 'scan-access')]},
    'File search': {'unit': ['test_indexer.Patterns', 'test_feature_routes.DiscoveryViews.test_search_hosts_and_jobs_answer_for_the_scanned_host'], 'lab': [(1, 'search'), (13, 'cli-tour')]},
    'File changes between scans': {'unit': ['test_feature_routes.DiscoveryViews.test_changes_between_two_scans_are_counted_and_grouped_by_folder', 'test_cli_commands.Commands.test_changes_shows_each_change_in_both_formats'], 'lab': [(13, 'file-changes')]},
    'Capacity trend': {'unit': ['test_feature_routes.DiscoveryViews.test_capacity_has_a_real_reading_of_the_mount', 'test_indexer.Capacity'], 'lab': [(13, 'capacity-trend')]},
    'Duplicates and cold data': {'unit': ['test_feature_routes.DiscoveryViews.test_duplicates_are_the_files_with_the_same_bytes', 'test_feature_routes.DiscoveryViews.test_twin_folders_and_cold_folders'], 'lab': [(13, 'duplicates'), (13, 'cold-data')]},
    'Docker and Podman inventory': {'unit': ['test_platform.DockerTests', 'test_infra.RealDocker'], 'lab': [(1, 'containers'), (13, 'containers-docker'), (13, 'containers-podman')]},
    'Git inventory and inspector': {'unit': ['test_audit_fixes.OddRepoPaths', 'test_cli_commands.Commands.test_git_docker_and_clamav_answer_with_no_data'], 'lab': [(13, 'git')]},
    'Host configurations and reinstall script': {'unit': ['test_hostconfig.Capture', 'test_hostconfig.Api', 'test_feature_routes.DiscoveryViews.test_host_config_versions_scripts_and_the_bundle'], 'lab': [(13, 'host-configs'), (13, 'reinstall-apply')]},
    'Topology editor': {'unit': ['test_browser_smoke.BrowserSmoke', 'test_platform.GraphTests'], 'lab': [(1, 'topology'), (13, 'ui-pages')]},
    'Shares manager': {'unit': ['test_tasks.ShareChecks', 'test_cli_commands.Commands.test_shares_check_and_script_on_a_host_with_no_design'], 'lab': [(2, 'share-apply'), (3, 'nfs'), (13, 'ui-pages')]},
    'File map': {'unit': ['test_filemap.FileMap', 'test_feature_routes.Reports.test_the_file_map_and_ignored_paths'], 'lab': [(13, 'file-map')]},
    'Structure graph': {'unit': ['test_platform.GraphTests', 'test_cli_commands.Commands.test_the_graph_builds_counts_and_exports_a_canvas'], 'lab': [(13, 'structure-graph')]},
    'Canvas export': {'unit': ['test_feature_routes.Reports.test_the_canvas_is_a_canvas_with_no_dangling_edge', 'test_cli_commands.Commands.test_the_graph_builds_counts_and_exports_a_canvas'], 'lab': [(13, 'canvas')]},
    'Markdown report': {'unit': ['test_cli_commands.Commands.test_export_markdown_names_the_host_and_its_mount', 'test_cli_commands.Commands.test_a_report_from_saved_payloads_needs_no_index'], 'lab': [(13, 'markdown')]},
    'Planner': {'unit': ['test_feature_routes.Reports.test_the_planner_reads_a_scan_saves_and_compares', 'test_recovery.Designs'], 'lab': [(13, 'planner')]},
    'Management planner': {'unit': ['test_routers.Api.test_the_management_planner_starts_from_every_machine', 'test_browser_smoke.BrowserSmoke.test_the_management_planner_opens_every_view_and_compiles_under_the_csp'], 'lab': [(12, 'management-planner')]},
    'Network devices': {'unit': ['test_routers.Devices', 'test_routers.RouterOsReading', 'test_routers.OpenWrtReading'], 'lab': [(12, 'facts-routeros'), (12, 'facts-openwrt'), (12, 'transport-telnet'), (12, 'transport-password'), (12, 'map-shows-router')]},
    'pfSense and Cisco devices': {'unit': ['test_routers.PfSenseReading', 'test_routers.CiscoReading'], 'why': 'no free image of either for the lab: both have only met published formats and a simulated shell'},
    'Network language': {'unit': ['test_routers.Language'], 'lab': [(12, 'compile-nftables'), (12, 'compile-iptables'), (12, 'normalize-to-dsl')]},
    'Device changes with a rollback': {'unit': ['test_routers.Devices.test_the_way_back_goes_on_before_the_change', 'test_routers.Devices.test_each_platforms_way_back'], 'lab': [(12, 'apply-and-keep'), (12, 'rollback-routeros'), (12, 'rollback-openwrt')]},
    'Paths through routers': {'unit': ['test_routers.ThroughTheRouter', 'test_routers.WanExposure'], 'lab': [(12, 'reach-allowed-matches-curl'), (12, 'reach-blocked-matches-curl'), (12, 'reach-flips-with-the-rule'), (12, 'reach-through-port-forward'), (12, 'exposure-through-router')]},
    'Network scanner': {'unit': ['test_routers.Scanner', 'test_browser_smoke.BrowserSmoke.test_the_scan_tab_says_it_is_off_and_turns_on_under_the_csp', 'test_browser_smoke.BrowserSmoke.test_a_scan_result_links_back_to_that_machines_pages'], 'lab': [(12, 'scanner-off-sends-nothing'), (12, 'scanner-finds-and-links')]},
    'Traffic monitoring': {'unit': ['test_routers.Traffic'], 'lab': [(12, 'traffic-rates')]},
    'Change plans': {'unit': ['test_platform.ChangePlanTests', 'test_cli_commands.Commands.test_plan_types_import_list_check_script_and_ansible'], 'lab': [(2, 'change-apply'), (5, 'btrfs-plan-tasks')]},
    'Move plans': {'unit': ['test_tasks.MoveExtras', 'test_cli_commands.Commands.test_moves_import_list_check_and_script'], 'lab': [(2, 'job-apply'), (3, 'move-across-hosts'), (3, 'move-cutover')]},
    'NFS and SMB shares': {'unit': ['test_indexer.Shares', 'test_lab_findings.ShareScript'], 'lab': [(2, 'share-mount'), (3, 'nfs'), (3, 'smb')]},
    'Storage tasks': {'unit': ['test_tasks.Tasks', 'test_cli_commands.Commands.test_tasks_import_list_check_and_script'], 'lab': [(2, 'task-systemd'), (2, 'task-result')]},
    'Scheduler': {'unit': ['test_scheduler.SchedulerApiTests', 'test_cli_commands.Commands.test_the_scheduler_from_end_to_end'], 'lab': [(3, 'schedule-timer'), (3, 'schedule-cron')]},
    'Deploy access': {'unit': ['test_platform.ServerTests', 'test_cli_commands.Commands.test_deploy_status_setup_script_and_alerts'], 'lab': [(2, 'deploy-access'), (2, 'remove-access')]},
    'Signed deploys': {'unit': ['test_engine.EngineTests', 'test_feature_routes.EngineCancel'], 'lab': [(2, 'engine'), (4, 'signed-requests'), (13, 'deploy-actions')]},
    'Deployed jobs': {'unit': ['test_tasks.Fleet'], 'lab': [(2, 'job-run-mirror'), (2, 'job-result-mirror'), (2, 'job-verify-mirror')]},
    'Sync engine': {'unit': ['test_sync_engine.Engine'], 'lab': [(6, 'sync-dedup'), (6, 'sync-failover'), (6, 'sync-btrfs-stream')]},
    'Existing snapshot jobs': {'unit': ['test_snapjobs.Imported', 'test_snapjobs.Parse'], 'lab': [(13, 'snapjobs-rsnapshot'), (13, 'snapjobs-snapper')]},
    'Alerts': {'unit': ['test_storage_ops.Alerts', 'test_lab_findings.DiskAlerts'], 'lab': [(4, 'disk-full'), (4, 'pool-degraded'), (13, 'deploy-actions')]},
    'Drift': {'unit': ['test_tasks.DeployedProtection'], 'lab': [(2, 'drift-real'), (2, 'drift-clean'), (4, 'drift')]},
    'Remote nodes': {'unit': ['test_remote_nodes.Nodes', 'test_cli_commands.Commands.test_remote_nodes_list_and_adding_one_needs_the_tunnel'], 'lab': [(7, 'remote-adopt'), (7, 'remote-deploy'), (7, 'remote-revoke')]},
    'Key vault and bindings': {'unit': ['test_platform.VaultTests', 'test_cli_commands.Commands.test_the_vault_from_a_key_to_its_removal', 'test_feature_routes.Administration.test_a_key_with_a_binding_stays_until_the_binding_goes'], 'lab': [(13, 'vault-cli')]},
    'Host identity': {'unit': ['test_platform.HostIdentityTests', 'test_feature_routes.RealSshServer'], 'lab': [(4, 'changed-host-key'), (4, 'rescan-after-rekey-api')]},
    'Keys added by hand': {'unit': ['test_cli_commands.Commands.test_host_keys_exit_1_for_an_unknown_key_and_rekey_needs_a_host'], 'lab': [(13, 'host-identity')]},
    'Accounts and sign-in': {'unit': ['test_cli_commands.Commands.test_accounts_from_adding_to_removing', 'test_roles.PrivilegeChain'], 'lab': [(13, 'accounts')]},
    'Roles': {'unit': ['test_roles.CustomRoles', 'test_roles.RouteRules'], 'lab': [(13, 'accounts')]},
    'Invite and reset links': {'unit': ['test_roles.Invites', 'test_roles.ResetLinks'], 'lab': [(13, 'accounts'), (13, 'site-and-reset')]},
    'Audit log': {'unit': ['test_feature_routes.Administration.test_the_audit_chain_verifies_until_a_row_changes', 'test_cli_commands.Commands.test_the_audit_log_tails_and_verifies'], 'lab': [(13, 'audit-chain')]},
    'Activity log': {'unit': ['test_logbook.Log', 'test_feature_routes.Reports.test_the_activity_log_filters_exports_and_keeps_its_own_trail'], 'lab': [(13, 'activity-log')]},
    'Backups and restore': {'unit': ['test_recovery.Restore', 'test_cli_commands.BackupCommands', 'test_feature_routes.Administration.test_backups_are_made_listed_and_keep_a_copy_target'], 'lab': [(13, 'backups'), (13, 'restore-backup')]},
    'Sites and reset': {'unit': ['test_sites.Sites', 'test_cli_commands.Commands.test_the_site_has_a_name_status_and_fingerprints'], 'lab': [(13, 'site-and-reset')]},
    'Retire a host': {'unit': ['test_tasks.Retire', 'test_feature_routes.Administration.test_retiring_a_host_is_refused_while_a_job_needs_it_and_takes_it_out_of_every_view'], 'lab': [(13, 'retire-host')]},
    'PostgreSQL': {'unit': ['test_platform.DBCase'], 'lab': [], 'why': 'The lab runs StorageForge on SQLite. tests/ci.sh runs the unit tests on PostgreSQL through STORAGEFORGE_TEST_PG instead (78 of 1043 skip there: SQLite files, and the command line tests that drive one).'},
}

# What the roadmaps added since the catalogue was written (docs/ransomware-defense.md, docs/infrastructure-map.md).
PLATFORM = {
    'Signed scan payloads': {'unit': ['test_scansign.Signed', 'test_scansign.SignedScan', 'test_scansign.Setup', 'test_scansign.Records'], 'lab': [(2, 'scan-signed')]},
    'Signed sends between hosts': {'unit': ['test_sends.Verbs', 'test_sends.Generated', 'test_sends.Checks', 'test_sends.RealSshd', 'test_sends.SignedReceive', 'test_sends.Route'],
                                   'lab': [(16, 'send-btrfs-full'), (16, 'send-btrfs-incremental'), (16, 'send-btrfs-retention'), (16, 'send-receiver-record'), (16, 'send-refused-not-enrolled'), (16, 'send-zfs-full')]},
    'Host logs': {'unit': ['test_hostlogs.Parsing', 'test_hostlogs.Secrets', 'test_hostlogs.Storing', 'test_hostlogs.Searching', 'test_hostlogs.Counting', 'test_hostlogs.Entrances'],
                  'lab': [(14, 'hostlogs-read'), (14, 'hostlogs-limited'), (14, 'hostlogs-no-journald'), (14, 'hostlogs-secrets-removed'), (14, 'hostlogs-caps')]},
    'Holds, cool-off and two admins': {'unit': ['test_security.Holds', 'test_security.OfflineKey'], 'lab': [(9, 'hold-zfs'), (9, 'hold-btrfs'), (9, 'release-cool-off'), (9, 'dual-admin'), (9, 'offline-key')]},
    'Clock guard': {'unit': ['test_security.ClockGuard'], 'lab': [(9, 'clock-guard'), (9, 'clock-30-days')]},
    'Decoys and the brake': {'unit': ['test_security.Decoys', 'test_security.RealSentinel', 'test_security.Brake'], 'lab': [(9, 'decoy-trip'), (9, 'brake-armed')]},
    'Attribution': {'unit': ['test_security.Behaviour'], 'lab': [(9, 'samba-attribution'), (9, 'nfs-attribution')]},
    'Airgap and quarantine': {'unit': ['test_security.RealNftables', 'test_security.Firewall'], 'lab': [(9, 'airgap-confirmed'), (9, 'airgap-timer'), (9, 'quarantine')]},
    'Blast radius and clean room': {'unit': ['test_feature_routes.SecurityActions.test_the_clean_room_sweep_tells_a_hit_from_nothing_from_a_mount_it_refuses'], 'lab': [(9, 'blast-and-clean-room')]},
    'SELinux, AppArmor and the baseline': {'unit': ['test_security.Measuring'], 'lab': [(9, 'selinux'), (9, 'apparmor'), (9, 'baseline')]},
    'Firewall writer, fences and rollback timer': {'unit': ['test_platform_more.WriterOnRealNftables', 'test_platform_more.WriterOnRealIptables'], 'lab': [(11, 'fw-rule-ufw'), (11, 'fw-rule-nftables'), (11, 'fw-rule-firewalld'), (11, 'fence'), (11, 'ssh-cut-rollback')]},
    'Retention policies and rollback preview': {'unit': ['test_feature_routes.SecurityPolicies.test_a_retention_policy', 'test_feature_routes.SecurityActions.test_a_rollback_preview_counts_what_a_restore_would_really_do'], 'lab': [(11, 'retention')]},
    'YARA, Falco, packages and bundles': {'unit': ['test_platform_more.Yara', 'test_platform_more.Falco', 'test_feature_routes.SecurityActions.test_the_package_check_reports_the_tools_as_the_host_does'], 'lab': [(11, 'yara'), (11, 'falco'), (11, 'packages'), (11, 'bundle')]},
    'Playbooks': {'unit': ['test_platform_more.Playbooks'], 'lab': [(11, 'playbook')]},
    'Identity, evidence, re-converge and waivers': {'unit': ['test_platform_more.Identity', 'test_platform_more.Evidence', 'test_feature_routes.SecurityPolicies.test_a_waiver'], 'lab': [(11, 'identity'), (11, 'evidence'), (11, 'reconverge')]},
    'ClamAV': {'unit': ['test_clamav.Scripts', 'test_feature_routes.ClamavRoutes'], 'lab': [(13, 'clamav')]},
    'Dashboards, ban tiers and alert routes': {'unit': ['test_feature_routes.SecurityPolicies.test_every_dashboard_tile_answers_and_the_read_only_views_name_their_host', 'test_feature_routes.SecurityPolicies.test_ban_tiers_thresholds_filters_watch_and_context_read_back'], 'lab': [(13, 'api-sweep'), (13, 'ui-pages')]},
    'Infrastructure map: network, services and firewall': {'unit': ['test_infra.Network', 'test_infra.Exposure', 'test_infra.RealNft'], 'lab': [(10, 'network-read'), (10, 'fw-model-ufw'), (10, 'nothing-invented'), (10, 'passive'), (13, 'map-views')]},
    'Containers and VMs': {'unit': ['test_infra.Parsers'], 'lab': [(10, 'workload-docker'), (10, 'workload-podman'), (10, 'workload-libvirt'), (13, 'lxc-guests'), (13, 'incus-guests')]},
    'Change tracking and placeholders': {'unit': ['test_infra.TheMap'], 'lab': [(10, 'change-tracking'), (11, 'placeholder')]},
    'Path query and what-if': {'unit': ['test_platform_more.Reach', 'test_platform_more.WhatIf'], 'lab': [(11, 'reach-table'), (11, 'whatif-agrees')]},
    'Designs and exports': {'unit': ['test_platform_more.Designs', 'test_platform_more.Exports'], 'lab': [(10, 'exports-redacted'), (11, 'design')]},
    'WireGuard': {'unit': ['test_platform_more.AccessLayer'], 'lab': [(11, 'wireguard')]},
    'Appliances': {'unit': ['test_appliances.Detection', 'test_appliances.Verdicts'], 'lab': [(8, 'appliances')]},
    'System updates': {'unit': ['test_updates.Fleet', 'test_updates.Script'], 'lab': [], 'why': 'A real update on a VM depends on what the mirrors hold that day, so no tier can state its result. Scripts run against stand-ins.'},
    'Tailscale, proxies and identity providers': {'unit': ['test_platform_more.AccessLayer'], 'lab': [], 'why': 'Needs an account on an outside service, and the lab has no traffic to carry.'},
    'Proxmox guests': {'unit': ['test_infra.Parsers'], 'lab': [(8, 'appliances')]},
    'PagerDuty': {'unit': ['test_platform_more.EveryRouteAnswers'], 'lab': [], 'why': 'Needs the real service. ntfy is what the lab delivers to.'},
    'FIDO2 step-up': {'unit': ['test_platform_more.Webauthn', 'test_platform_more.StepUp'], 'lab': [], 'why': 'Needs a physical token. Chromium\'s virtual authenticator is the closest a browser test gets.'},
    'Device transports: SSH terminal, Telnet, legacy SSH and sealed device passwords': {'unit': ['test_nettransport.Telnet', 'test_nettransport.RealSshTerminal', 'test_nettransport.Legacy', 'test_nettransport.Credentials'], 'lab': [], 'why': 'Tier 12 needs the router VMs, which are phase 8 of the networking roadmap. Until then a real sshd with a simulated switch shell, and a real socket server speaking RFC 854. No real router has been connected to, and SSH password logins have not run, since they need root sshd.'},
    'Terraform and Puppet exports': {'unit': ['test_platform_more.Exports'], 'lab': [(10, 'exports-redacted')]},
}

# On the roadmap and not built: nothing to test yet. docs/kvm-lab.md lists tier 12 for it, and tiers_network.py does not exist.
NOT_BUILT = ('Router and firewall appliances, tier 12', 'MikroTik DSL and its transpiler')

# Routes no test calls by name, and why that is right. Anything else with no test fails test_feature_map.
UNCALLED_ROUTES = {
    '/': 'the browser tests load it',
    '/index.html': 'the same page as /',
    '/planner': 'the browser tests and tier 13 load it',
    '/manage': 'the browser tests and tier 12 load it',
    '/search': 'the browser tests and tier 13 load it',
    '/enroll': 'the browser tests load it',
    '/login': 'the browser tests load it',
    '/healthz': 'the healthcheck command and tier 0',
}
