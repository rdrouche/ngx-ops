# Scheduled tasks (Scheduler)

The **Scheduler** page runs actions at fixed times. Tasks are stored in the dashboard database and managed from the interface.

## Create a task

**New task**: choose the action, the schedule, the action-specific options, activation and whether to send an email at the end.

Scheduling is visual (every X minutes or hours, every day, certain days of the week, day of the month) or in **cron** for advanced mode. A preview shows the next five runs, in the server time zone (`TZ` variable).

## Actions

| Action | Effect |
| ------ | ------ |
| Reload Nginx | `nginx -t` then `nginx -s reload`, without interruption. Cancelled if the configuration is invalid |
| Restart the Nginx container | Restarts the container, after the same prior test. Useful for what a reload does not fix |
| Restart the analyzer | Restarts the analyzer container and waits for its API to respond. History and baseline are kept |
| Periodic summary | Generates the summary (traffic, robots, CrowdSec, WAF, certificates), visible in the Summary page and sendable by email |
| Backup | Local ZIP, Git, S3 or a combination |
| Backup to the Hub | Sends the Nginx configuration, the NGX Ops configuration files and the environment variables (secrets masked) to the [Hub](../hub/backups.md) |
| Restart GoAccess | Restarts the chosen GoAccess containers (all active ones if none is selected) |
| Restart managed containers | Restarts the chosen containers (analyzer, WAF, shipper, challenge, certbot…) one after the other. A missing or disabled container is skipped, never created |
| Update managed containers | Pulls the latest image and recreates the container if it changed (brief interruption) |
| Check container updates | Reports, in the notification center, containers for which a newer version exists, without changing anything |
| Synchronize certificates | Synchronizes certificates with other NGX Ops: one node obtains the Let's Encrypt certificate, the others install it. An `nginx -t` precedes each reload, with rollback on failure |

!!! tip "Summary consistency"
    For the periodic summary, the schedule decides **when** it triggers and the covered period **which window** it summarizes. Weekly: Monday at 7 am with 168 hours. Daily: every day at 7 am with 24 hours. Otherwise part of the period is missing or repeated.

## Manage tasks

The list shows each task's next run and last result. You can enable or disable it, **run it now**, edit it, delete it and view its history (last 50 runs).

The **Export** and **Import** buttons exchange a `scheduled-tasks.json` file, with merge or replacement.

## Permissions

Reading requires the right to view configurations. Creating, editing, running and importing require the Nginx control right. See [Users and roles](../dashboard/users.md).

!!! info "Old scheduler.yml file"
    Tasks are no longer in a YAML file. If a `scheduler.yml` from an old installation exists, it is imported once at first start, then ignored.
