# Live logs

**Live logs** is one of the only log-related features that does not require **Nginx Analyzer**.

This feature is deliberately simple: it displays in real time the content of the log files in `/var/log/nginx`. It is equivalent to running the `tail -f` command directly on a log file.

To access this feature, go to **CONFIGURATION → Live logs**.

In the navigation panel, select the log file to view, to display its content in real time.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-019-logviewer.png" width="800" />

New lines added to the file are displayed automatically, which is notably useful to follow the requests received by Nginx during a test or while troubleshooting.
