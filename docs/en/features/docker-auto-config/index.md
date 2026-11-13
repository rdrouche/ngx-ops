# Docker auto-configuration (experimental)

To **make deploying Docker containers easier**, **NGX Ops** includes two auto-configuration modes, suited to different environments:

* **Auto-publishing from the same host as Nginx**
* **Auto-publishing from remote hosts**

If you already use **Traefik**, the principle will be familiar.

In both modes, **NGX Ops relies on Docker labels** to get the information needed to publish a container.

From these [labels](labels.md), NGX Ops dynamically generates the **Nginx VHost** configuration that lets Nginx receive requests and forward them to the container concerned.

The goal is to publish a Docker application without having to create the whole VHost configuration manually.

How it works then differs depending on where the container is:

* when the container runs **on the same host as Nginx**, NGX Ops can talk directly to the local Docker socket;
* when the container runs on a **remote host**, NGX Ops uses an **agent** to get the Docker information and allow the application to be published.

> **Note:** this feature is currently **experimental**. It is meant to simplify publishing Docker applications while keeping Nginx's native operation and configuration.
